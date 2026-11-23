// security-counter-repair previews derived counter changes; writes require an
// explicit tenant, apply mode, and a new private backup file. Never changes facts
// or human dispositions. Restore uses compare-and-swap to protect newer counts.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/alertcounter"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"time"
)

type change struct {
	Tenant         string     `json:"tenant"`
	Group          string     `json:"group"`
	OldOccurrences int        `json:"old_occurrences"`
	OldUsers       int        `json:"old_users"`
	OldAt          *time.Time `json:"old_calculated_at"`
	NewOccurrences int        `json:"new_occurrences"`
	NewUsers       int        `json:"new_users"`
	AppliedAt      *time.Time `json:"applied_at,omitempty"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	mode := flag.String("mode", "dry-run", "dry-run, apply, or restore")
	tenant := flag.String("tenant", "", "tenant scope (required for writes)")
	backup := flag.String("backup", "", "new backup file for apply; existing file for restore")
	limit := flag.Int("limit", 100, "maximum groups per batch")
	after := flag.String("after-group", "", "resume after this group ID (requires tenant)")
	flag.Parse()
	if *after != "" && *tenant == "" {
		return fmt.Errorf("cursor requires tenant")
	}
	if *mode != "dry-run" && *mode != "apply" && *mode != "restore" {
		return fmt.Errorf("invalid mode")
	}
	if *limit < 1 || *limit > 1000 {
		return fmt.Errorf("limit must be 1..1000")
	}
	if *mode != "dry-run" && (*tenant == "" || *backup == "") {
		return fmt.Errorf("writes require explicit tenant and backup")
	}
	ctx := context.Background()
	dsn := os.Getenv("QUALITY_DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("QUALITY_DATABASE_URL is required")
	}
	db, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return fmt.Errorf("database configuration invalid")
	}
	defer db.Close()
	options := pgx.TxOptions{IsoLevel: pgx.RepeatableRead}
	if *mode == "dry-run" {
		options.AccessMode = pgx.ReadOnly
	}
	tx, e := db.BeginTx(ctx, options)
	if e != nil {
		return fmt.Errorf("database unavailable")
	}
	defer tx.Rollback(ctx)
	if *mode == "restore" {
		raw, e := os.ReadFile(*backup)
		if e != nil {
			return e
		}
		var rows []change
		if e = json.Unmarshal(raw, &rows); e != nil {
			return e
		}
		restored, skipped := 0, 0
		for _, r := range rows {
			if r.Tenant != *tenant || r.AppliedAt == nil {
				return fmt.Errorf("backup tenant or applied identity mismatch")
			}
			tag, e := tx.Exec(ctx, `UPDATE alert_groups SET distinct_occurrences=$1,affected_users=$2,last_calc_at=$3 WHERE tenant_id=$4 AND id=$5 AND distinct_occurrences=$6 AND affected_users=$7 AND last_calc_at IS NOT DISTINCT FROM $8`, r.OldOccurrences, r.OldUsers, r.OldAt, r.Tenant, r.Group, r.NewOccurrences, r.NewUsers, r.AppliedAt)
			if e != nil {
				return e
			}
			if tag.RowsAffected() == 1 {
				restored++
			} else {
				skipped++
			}
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]int{"restored": restored, "skipped_newer_or_missing": skipped})
	}
	query := `SELECT tenant_id,id,COALESCE(distinct_occurrences,0),COALESCE(affected_users,0),last_calc_at FROM alert_groups WHERE ($1='' OR tenant_id=$1) AND ($3='' OR id>$3) ORDER BY tenant_id,id LIMIT $2`
	if *mode == "apply" {
		query += ` FOR UPDATE`
	}
	rows, e := tx.Query(ctx, query, *tenant, *limit, *after)
	if e != nil {
		return e
	}
	all := []change{}
	for rows.Next() {
		var c change
		if e = rows.Scan(&c.Tenant, &c.Group, &c.OldOccurrences, &c.OldUsers, &c.OldAt); e != nil {
			rows.Close()
			return e
		}
		all = append(all, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	changes := []change{}
	for _, c := range all {
		if e = tx.QueryRow(ctx, alertcounter.PreviewByGroup, c.Tenant, c.Group).Scan(&c.NewOccurrences, &c.NewUsers); e != nil {
			return e
		}
		if c.NewOccurrences == c.OldOccurrences && c.NewUsers == c.OldUsers {
			continue
		}
		if *mode == "apply" {
			if e = tx.QueryRow(ctx, alertcounter.ByGroup, c.Tenant, c.Group).Scan(&c.NewOccurrences, &c.NewUsers); e != nil {
				return e
			}
			if e = tx.QueryRow(ctx, `SELECT last_calc_at FROM alert_groups WHERE tenant_id=$1 AND id=$2`, c.Tenant, c.Group).Scan(&c.AppliedAt); e != nil {
				return e
			}
		}
		changes = append(changes, c)
	}
	if *mode == "apply" {
		f, e := os.OpenFile(*backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		e = json.NewEncoder(f).Encode(changes)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		// Persist the new directory entry before committing the database change.
		dir, err := os.Open(filepath.Dir(*backup))
		if err != nil {
			return err
		}
		syncErr := dir.Sync()
		dirCloseErr := dir.Close()
		if syncErr != nil {
			return syncErr
		}
		if dirCloseErr != nil {
			return dirCloseErr
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
	} else {
		if e = tx.Rollback(ctx); e != nil {
			return e
		}
	}
	next := ""
	if len(all) > 0 {
		next = all[len(all)-1].Group
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"scanned": len(all), "next_after_group": next, "changes": changes})
}
