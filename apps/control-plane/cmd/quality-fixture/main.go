package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/bootstrap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/url"
	"os"
)

// This utility may bootstrap only the explicitly named local acceptance database.
func main() {
	u, e := url.Parse(os.Getenv("QUALITY_DATABASE_URL"))
	if e != nil || u.Hostname() != "127.0.0.1" || u.Path != "/jjd267" || os.Getenv("QUALITY_FIXTURE_ONLY") != "1" {
		panic("requires explicit isolated loopback jjd267 fixture")
	}
	ctx := context.Background()
	db, e := pgxpool.New(ctx, os.Getenv("QUALITY_DATABASE_URL"))
	if e != nil {
		panic(e)
	}
	defer db.Close()
	if e = bootstrap.EnsurePlatformDefaults(ctx, repository.NewRuleSetRepository(db), repository.NewRuleRepository(db)); e != nil {
		panic(e)
	}
	rs, e := repository.NewRuleRepository(db).ListCompilableRulesByTenant(ctx, "tenant_default", "")
	if e != nil {
		panic(e)
	}
	p := rules.Compile("tenant_default", rs, nil)
	b, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(os.Getenv("QUALITY_POLICY_OUTPUT"), b, 0600); e != nil {
		panic(e)
	}
	fmt.Printf("compiled rules=%d policies=%d\n", len(p.Rules), len(p.Policies))
}
