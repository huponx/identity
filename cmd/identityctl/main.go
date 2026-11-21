// identityctl administers identity straight on its database and Redis: the first admin, the
// OAuth clients, the token exchange policies and the MFA state of a user. It exists for the
// bootstrap (nothing can call the gRPC API before a client and an admin exist) and for
// emergencies; day to day administration goes through the gRPC API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/huponx/gocommon/config"
	"github.com/huponx/gocommon/logging"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/appconfig"
	"github.com/huponx/identity/internal/keys"
	"github.com/huponx/identity/internal/mfa"
	"github.com/huponx/identity/internal/notify"
	"github.com/huponx/identity/internal/oauth"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"github.com/huponx/identity/internal/token"
	"go.uber.org/zap"
)

const usage = `usage: identityctl <command> [flags]

commands:
  bootstrap       --email E [--name N]       create the first admin (password from IDENTITY_BOOTSTRAP_PASSWORD); refused when an admin exists
  client create   --id ID --type public|confidential --resource AUD [--name N] [--redirect-uri U]... [--post-logout-uri U]...
                  [--backchannel-logout-uri U] [--grant G]... [--scope S]... [--role R]...   prints the secret once
  client add-uri  --id ID [--redirect-uri U]... [--post-logout-uri U]...   add URIs to an existing client
  client rotate   --id ID                    new secret, printed once
  client role     --id ID --role R           give a role to a client
  exchange set    --client ID --audience AUD [--max-scope "a b"] [--depth N]
  exchange delete --client ID --audience AUD
  user mfa        --user ID|EMAIL (--disable | --enforce | --unenforce | --reset)
  user password-reset --user ID|EMAIL        send the reset mail

Reads the same environment as identity (POSTGRES_*, REDIS_*, IDENTITY_*).`

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "identityctl:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cfg, err := config.Load[appconfig.Identity]()
	if err != nil {
		return err
	}
	log, err := logging.New(logging.Config{Level: cfg.Level, Encoding: "console", Service: "identityctl", Env: cfg.Env})
	if err != nil {
		return err
	}
	st, err := store.New(ctx, cfg.Postgres.URL())
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "bootstrap":
		return bootstrap(ctx, st, args[1:])
	case "client":
		if len(args) < 2 {
			return errors.New(usage)
		}
		return client(ctx, st, args[1], args[2:])
	case "exchange":
		if len(args) < 2 {
			return errors.New(usage)
		}
		return exchange(ctx, st, args[1], args[2:])
	case "user":
		if len(args) < 2 {
			return errors.New(usage)
		}
		acct, err := accountService(ctx, cfg, st, log)
		if err != nil {
			return err
		}
		defer acct.Drain()
		return user(ctx, st, acct, args[1], args[2:])
	default:
		return errors.New(usage)
	}
}

func bootstrap(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	email := fs.String("email", "", "e-mail of the admin")
	name := fs.String("name", "Administrator", "display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pw := os.Getenv("IDENTITY_BOOTSTRAP_PASSWORD")
	if *email == "" || pw == "" {
		return errors.New("--email and IDENTITY_BOOTSTRAP_PASSWORD are required")
	}
	n, err := st.CountAdmins(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return errors.New("an admin already exists; bootstrap only runs on an empty installation")
	}
	if err := password.Check(pw, *email, ""); err != nil {
		return err
	}
	h, err := password.Hash(pw)
	if err != nil {
		return err
	}
	u, err := st.CreateUser(ctx, store.User{Email: *email, Name: *name, PasswordHash: h}, []string{"admin"})
	if err != nil {
		return err
	}
	fmt.Printf("admin created: %s (%s)\n", u.Email, u.ID)
	return nil
}

func client(ctx context.Context, st *store.Store, sub string, args []string) error {
	fs := flag.NewFlagSet("client "+sub, flag.ContinueOnError)
	id := fs.String("id", "", "client id")
	switch sub {
	case "create":
		name := fs.String("name", "", "display name")
		typ := fs.String("type", "", "public or confidential")
		resource := fs.String("resource", "", "audience of the tokens issued to the client")
		backchannel := fs.String("backchannel-logout-uri", "", "back-channel logout endpoint")
		var redirects, logouts, grants, scopes, roles list
		fs.Var(&redirects, "redirect-uri", "allowed redirect URI (repeatable)")
		fs.Var(&logouts, "post-logout-uri", "allowed post logout redirect URI (repeatable)")
		fs.Var(&grants, "grant", "allowed grant (repeatable; default authorization_code, refresh_token)")
		fs.Var(&scopes, "scope", "allowed scope (repeatable; default openid profile email offline_access)")
		fs.Var(&roles, "role", "role of the client (repeatable)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *id == "" || *resource == "" || (*typ != "public" && *typ != "confidential") {
			return errors.New("--id, --resource and --type public|confidential are required")
		}
		c := store.Client{
			ClientID: *id, Name: firstNonEmpty(*name, *id), Type: *typ, RedirectURIs: redirects, PostLogoutRedirectURIs: logouts,
			BackchannelLogoutURI: *backchannel, AllowedGrants: grants, AllowedScopes: scopes, Resource: *resource, Roles: roles,
		}
		if len(c.AllowedGrants) == 0 {
			c.AllowedGrants = []string{"authorization_code", "refresh_token"}
		}
		if len(c.AllowedScopes) == 0 {
			c.AllowedScopes = []string{"openid", "profile", "email", "offline_access"}
		}
		secret := ""
		if c.Type == "confidential" {
			secret = password.Random(32)
			c.SecretHash = oauth.HashSecret(secret)
		}
		if _, err := st.CreateClient(ctx, c); err != nil {
			return err
		}
		fmt.Printf("client created: %s\n", c.ClientID)
		if secret != "" {
			fmt.Printf("client secret (shown once): %s\n", secret)
		}
		return nil
	case "rotate":
		if err := fs.Parse(args); err != nil {
			return err
		}
		secret := password.Random(32)
		if err := st.SetClientSecret(ctx, *id, oauth.HashSecret(secret)); err != nil {
			return err
		}
		fmt.Printf("new client secret for %s (shown once): %s\n", *id, secret)
		return nil
	case "add-uri":
		var redirects, logouts list
		fs.Var(&redirects, "redirect-uri", "redirect URI to add (repeatable)")
		fs.Var(&logouts, "post-logout-uri", "post logout redirect URI to add (repeatable)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *id == "" || len(redirects)+len(logouts) == 0 {
			return errors.New("--id and at least one --redirect-uri or --post-logout-uri are required")
		}
		for _, u := range append(append([]string{}, redirects...), logouts...) {
			if !store.ValidURI(u) {
				return fmt.Errorf("invalid uri %s", u)
			}
		}
		return st.AddClientURIs(ctx, *id, redirects, logouts)
	case "role":
		role := fs.String("role", "", "role")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *id == "" || *role == "" {
			return errors.New("--id and --role are required")
		}
		return st.AssignRole(ctx, "", *id, *role)
	}
	return errors.New(usage)
}

func exchange(ctx context.Context, st *store.Store, sub string, args []string) error {
	fs := flag.NewFlagSet("exchange "+sub, flag.ContinueOnError)
	clientID := fs.String("client", "", "client id")
	audience := fs.String("audience", "", "audience")
	maxScope := fs.String("max-scope", "", "space separated scopes the token may carry at most")
	depth := fs.Int("depth", 1, "maximum delegation chain depth")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" || *audience == "" {
		return errors.New("--client and --audience are required")
	}
	switch sub {
	case "set":
		return st.SetExchangePolicy(ctx, store.ExchangePolicy{ClientID: *clientID, Audience: *audience, MaxScope: *maxScope, MaxChainDepth: *depth})
	case "delete":
		return st.DeleteExchangePolicy(ctx, *clientID, *audience)
	}
	return errors.New(usage)
}

func accountService(ctx context.Context, cfg appconfig.Identity, st *store.Store, log *zap.Logger) (*account.Service, error) {
	sta, err := state.New(ctx, cfg.Redis.URL())
	if err != nil {
		return nil, err
	}
	keySet, err := keys.Load(cfg.SigningKeyFile, cfg.SigningKeyID, cfg.PreviousKeysDir)
	if err != nil {
		return nil, err
	}
	var sealer *mfa.Sealer
	if cfg.MFAMode != appconfig.MFAOff {
		if sealer, err = mfa.NewSealer(cfg.MFAKeys); err != nil {
			return nil, err
		}
	}
	tk := token.New(token.Config{Issuer: cfg.Issuer, AccessTTL: cfg.AccessTokenTTL, IDTTL: cfg.IDTokenTTL, RefreshTTL: cfg.RefreshTokenTTL, ExchangeTTL: cfg.ExchangeTokenTTL}, keySet, st, sta)
	return account.New(account.Config{Issuer: cfg.Issuer, MFAMode: cfg.MFAMode, MFAIssuerName: cfg.MFAIssuerName, RevokeTTL: cfg.AccessTokenTTL + time.Minute},
		st, sta, tk, sealer, notify.Build(ctx, cfg, log), log), nil
}

func user(ctx context.Context, st *store.Store, acct *account.Service, sub string, args []string) error {
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	who := fs.String("user", "", "user id or e-mail")
	disable := fs.Bool("disable", false, "turn MFA off")
	enforce := fs.Bool("enforce", false, "require MFA for the user")
	unenforce := fs.Bool("unenforce", false, "stop requiring MFA for the user")
	reset := fs.Bool("reset", false, "delete the authenticator and the recovery codes, end the sessions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *who == "" {
		return errors.New("--user is required")
	}
	u, err := st.UserByEmail(ctx, *who)
	if errors.Is(err, store.ErrNotFound) {
		u, err = st.UserByID(ctx, *who)
	}
	if err != nil {
		return fmt.Errorf("user %q: %w", *who, err)
	}
	switch sub {
	case "password-reset":
		return acct.SendReset(ctx, u)
	case "mfa":
		switch {
		case *disable:
			return acct.AdminDisableMFA(ctx, u)
		case *enforce:
			return acct.AdminEnforceMFA(ctx, u, true)
		case *unenforce:
			return acct.AdminEnforceMFA(ctx, u, false)
		case *reset:
			return acct.AdminResetMFA(ctx, u)
		}
		return errors.New("one of --disable, --enforce, --unenforce, --reset is required")
	}
	return errors.New(usage)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
