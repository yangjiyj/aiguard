// Command jjd-secrets-rewrap reports or rewraps stored credentials into the
// format selected by JJD_SECRETS_CIPHER / JJD_SM4_KEYRING / JJD_SM4_ACTIVE_KEY_ID.
//
//	jjd-secrets-rewrap -database-url "$DATABASE_URL"          # dry run (default)
//	jjd-secrets-rewrap -database-url "$DATABASE_URL" -apply   # rewrap
//
// Exit codes: 0 ok, 1 usage/config/database error, 2 some rows failed.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets/rewrap"
)

func main() {
	url := flag.String("database-url", os.Getenv("DATABASE_URL"), "PostgreSQL URL (default $DATABASE_URL)")
	apply := flag.Bool("apply", false, "rewrap values; without it only a format report is printed")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall timeout")
	flag.Parse()
	if *url == "" {
		fmt.Fprintln(os.Stderr, "database url is required (-database-url or DATABASE_URL)")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	conn, err := pgx.Connect(ctx, *url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())

	reports, err := rewrap.Run(ctx, conn, rewrap.Columns, *apply)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"apply": *apply, "columns": reports})
	if err != nil {
		fmt.Fprintln(os.Stderr, "rewrap:", err)
		os.Exit(1)
	}
	if rewrap.Summarize(reports) != nil {
		os.Exit(2)
	}
}
