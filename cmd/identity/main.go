package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gocommon/config"
	"github.com/huponx/gocommon/grpcserver"
	"github.com/huponx/gocommon/healthz"
	"github.com/huponx/gocommon/httpx"
	"github.com/huponx/gocommon/jwtx"
	"github.com/huponx/gocommon/logging"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/appconfig"
	"github.com/huponx/identity/internal/keys"
	"github.com/huponx/identity/internal/mfa"
	"github.com/huponx/identity/internal/notify"
	"github.com/huponx/identity/internal/oauth"
	"github.com/huponx/identity/internal/passkey"
	"github.com/huponx/identity/internal/service"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"github.com/huponx/identity/internal/token"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.MustLoad[appconfig.Identity]()
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	log, err := logging.New(logging.Config{Level: cfg.Level, Encoding: cfg.Encoding, Service: serviceName(cfg.Service), Env: cfg.Env})
	if err != nil {
		panic(err)
	}
	defer logging.Sync(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.New(ctx, cfg.Postgres.URL())
	if err != nil {
		log.Fatal("postgres", zap.Error(err))
	}
	defer st.Close()
	// the catalog of permissions must match the code before identity serves anybody: a changed permission set
	// changes what many users may do, so a failure stops the start (the old pods keep serving the old set)
	if err := service.SyncOwnPermissions(ctx, st, log); err != nil {
		log.Fatal("permission sync", zap.Error(err))
	}
	sta, err := state.New(ctx, cfg.Redis.URL())
	if err != nil {
		log.Fatal("redis", zap.Error(err))
	}
	sta.LimitFactor = cfg.RateLimitFactor
	defer sta.Close()

	keySet, err := keys.Load(cfg.SigningKeyFile, cfg.SigningKeyID, cfg.PreviousKeysDir)
	if err != nil {
		log.Fatal("signing keys", zap.Error(err))
	}
	var sealer *mfa.Sealer
	if cfg.MFAMode != appconfig.MFAOff {
		if sealer, err = mfa.NewSealer(cfg.MFAKeys); err != nil {
			log.Fatal("mfa keys", zap.Error(err))
		}
	}

	tokens := token.New(token.Config{
		Issuer: cfg.Issuer, AccessTTL: cfg.AccessTokenTTL, IDTTL: cfg.IDTokenTTL,
		RefreshTTL: cfg.RefreshTokenTTL, ExchangeTTL: cfg.ExchangeTokenTTL,
	}, keySet, st, sta)

	notifier := notify.Build(ctx, cfg, log)
	var passkeys *passkey.Service
	if cfg.WebAuthnEnabled {
		if passkeys, err = passkey.New(passkey.Config{RPID: cfg.WebAuthnRP(), RPName: cfg.WebAuthnName(), Origins: cfg.WebAuthnOriginList()}); err != nil {
			log.Fatal("webauthn", zap.Error(err))
		}
		log.Info("passkeys are on", zap.String("rp_id", cfg.WebAuthnRP()), zap.Strings("origins", cfg.WebAuthnOriginList()))
	}
	acct := account.New(account.Config{
		Issuer: cfg.Issuer, MFAMode: cfg.MFAMode, MFAIssuerName: cfg.MFAIssuerName, AdminURL: cfg.AdminURL,
		RevokeTTL: cfg.AccessTokenTTL + time.Minute,
	}, st, sta, tokens, sealer, notifier, log)
	acct.Passkeys = passkeys

	// gRPC API: our own JWTs (aud identity) and, for local runs only, a static token
	verifier, err := jwtx.NewVerifier(jwtx.VerifierConfig{Issuer: cfg.Issuer, Audience: cfg.AuthAudience, Keys: jwtx.StaticKeySet(keySet.Public)})
	if err != nil {
		log.Fatal("jwt verifier", zap.Error(err))
	}
	authFns := []grpcserver.AuthFunc{grpcserver.JWTAuth(verifier)}
	srv := grpcserver.New(
		grpcserver.WithLogger(log),
		grpcserver.WithReflection(cfg.IsLocal()),
		grpcserver.WithAuth(grpcserver.AnyAuth(authFns...)),
		grpcserver.WithMethodPermissions(service.Permissions),
	)
	idSvc := service.New(acct, st, sta, tokens, cfg.MFAMode)
	idSvc.RegistrationEnabled = cfg.RegistrationEnabled
	idSvc.Log = log
	identityv1.RegisterIdentityServiceServer(srv.GRPC, idSvc)

	// HTTP: OAuth 2.0 / OpenID Connect
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery(), httpx.Logger(log), httpx.RequestContext(), httpx.AccessLog())
	router.GET("/healthz", healthz.Live())
	router.GET("/readyz", healthz.Ready(
		healthz.Check{Name: "postgres", Fn: st.Ping},
		healthz.Check{Name: "redis", Fn: sta.Ping},
	))
	web := oauth.New(oauth.Config{
		Issuer: cfg.Issuer, SecureCookies: !cfg.IsLocal() || startsHTTPS(cfg.Issuer),
		SessionIdle: cfg.SessionIdleTTL, SessionAbsolute: cfg.SessionAbsoluteTTL, MFAMode: cfg.MFAMode,
		TrustedProxies: cfg.TrustedProxies, AccessTokenDefault: cfg.AccessTokenTTL, RefreshTokenTTL: cfg.RefreshTokenTTL,
		UIDir: cfg.UIDir, RequireUI: !cfg.IsLocal(), PortalURL: cfg.PortalURL,
		RegistrationEnabled: cfg.RegistrationEnabled, RegistrationRole: cfg.RegistrationRole,
	}, acct, st, sta, tokens, keySet, log)
	if err := web.Routes(router); err != nil {
		log.Fatal("http routes", zap.Error(err))
	}
	httpSrv := &http.Server{
		Addr: cfg.HTTPAddr(), Handler: router,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}

	lis, err := net.Listen("tcp", cfg.GRPCAddr())
	if err != nil {
		log.Fatal("listen", zap.Error(err), zap.String("addr", cfg.GRPCAddr()))
	}
	errCh := make(chan error, 2)
	go func() {
		log.Info("identity grpc listening", zap.String("addr", cfg.GRPCAddr()))
		errCh <- srv.GRPC.Serve(lis)
	}()
	go func() {
		log.Info("identity http listening", zap.String("addr", cfg.HTTPAddr()), zap.String("issuer", cfg.Issuer), zap.String("mfa_mode", cfg.MFAMode))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go cleanup(ctx, st, log)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Error("serve", zap.Error(err))
		}
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	srv.Stop(shutCtx)
	acct.Drain()
}

func startsHTTPS(u string) bool { return len(u) > 8 && u[:8] == "https://" }

// cleanup removes old refresh tokens once an hour.
func cleanup(ctx context.Context, st *store.Store, log *zap.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := st.DeleteExpiredRefreshTokens(ctx); err != nil {
				log.Warn("cleanup refresh tokens", zap.Error(err))
			} else if n > 0 {
				log.Info("expired refresh tokens deleted", zap.Int64("count", n))
			}
		}
	}
}

func serviceName(name string) string {
	if name == "" || name == "app" {
		return "identity"
	}
	return name
}
