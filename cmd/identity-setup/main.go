// identity-setup is the initial setup of identity, run once as a Job after the database schema exists: the
// first admin (only when no admin exists, with a password that must be changed at the first sign in), the
// OAuth clients and the token exchange policies. See internal/setup. It needs only PostgreSQL.
//
//	SETUP_CONFIG          JSON, see internal/setup.Config
//	SETUP_ADMIN_PASSWORD  password of the first admin (from a Secret), read only when the config has an admin
//	<secret_env>          one variable per confidential client, named in the config
//	POSTGRES_*            as the server
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/huponx/gocommon/config"
	"github.com/huponx/identity/internal/appconfig"
	"github.com/huponx/identity/internal/setup"
	"github.com/huponx/identity/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "identity-setup:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := setup.Parse(os.Getenv("SETUP_CONFIG"))
	if err != nil {
		return err
	}
	// only the Postgres part of the server configuration is needed
	app, err := config.Load[appconfig.Setup]()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	st, err := store.New(ctx, app.Postgres.URL())
	if err != nil {
		return err
	}
	defer st.Close()
	logf := func(format string, args ...any) { fmt.Printf("identity-setup: "+format+"\n", args...) }
	err = setup.Run(ctx, st, cfg, setup.Env{AdminPassword: os.Getenv("SETUP_ADMIN_PASSWORD"), Getenv: os.Getenv}, logf)
	if err != nil {
		return err
	}
	logf("done")
	return nil
}
