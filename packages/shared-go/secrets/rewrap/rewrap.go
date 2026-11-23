// Package rewrap re-encrypts stored credentials into the currently
// configured secrets format (W10). It is the only way to finish an
// AES-GCM -> SM4-GCM migration, retire an SM4 key id, or roll back to
// AES-GCM before downgrading binaries. Reads never need it: secrets always
// decrypts both formats.
//
// Every row update is a compare-and-swap on the old ciphertext, so a
// concurrent admin edit wins and the row is simply skipped.
package rewrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// Family selects which secrets API a column uses.
type Family int

const (
	ProviderSecret Family = iota
	CAPrivateKey
)

// Column describes one persistent ciphertext column. Where, when set, is
// an extra static filter (never user input).
type Column struct {
	Table, KeyColumn, ValueColumn, Where string
	Family                               Family
}

// Columns lists the long-lived credential columns. Deliberately excluded:
//   - mcp_servers.auth_ciphertext: migration 117 binds the route hash to
//     the ciphertext, so rewrapping would quarantine approved servers.
//     These values keep their current format until an admin re-saves them.
//   - short-lived queues (mcp_confirmation_*, *_inspection_*): they expire
//     on their own and are always readable in either format.
var Columns = []Column{
	{Table: "provider_credentials", KeyColumn: "id", ValueColumn: "secret_ciphertext", Family: ProviderSecret},
	{Table: "internal_keys", KeyColumn: "id", ValueColumn: "key_ciphertext", Family: ProviderSecret},
	{Table: "identity_sources", KeyColumn: "id", ValueColumn: "client_secret_enc", Family: ProviderSecret},
	{Table: "directory_sources", KeyColumn: "id", ValueColumn: "bind_password_enc", Family: ProviderSecret},
	{Table: "retention_storage_config", KeyColumn: "id", ValueColumn: "s3_secret_enc", Family: ProviderSecret},
	{Table: "system_settings", KeyColumn: "key", ValueColumn: "value", Where: "key IN ('judge_api_key','outbound_proxy_url')", Family: ProviderSecret},
	{Table: "ca_certificates", KeyColumn: "id", ValueColumn: "private_key_encrypted", Family: CAPrivateKey},
}

// DB is the subset of pgx used here (pgxpool.Pool and pgx.Conn satisfy it).
type DB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Report counts values per column and per format.
type Report struct {
	Column    string         `json:"column"`
	Formats   map[string]int `json:"formats"`
	Rewrapped int            `json:"rewrapped"`
	Skipped   int            `json:"skipped_concurrent"`
	Failed    int            `json:"failed"`
	Errors    []string       `json:"errors,omitempty"`
}

func (c Column) name() string { return c.Table + "." + c.ValueColumn }

func (c Column) selectSQL() string {
	q := fmt.Sprintf(`SELECT %s::text, %s FROM %s WHERE %s LIKE 'enc:%%'`,
		pgx.Identifier{c.KeyColumn}.Sanitize(), pgx.Identifier{c.ValueColumn}.Sanitize(), pgx.Identifier{c.Table}.Sanitize(), pgx.Identifier{c.ValueColumn}.Sanitize())
	if c.Where != "" {
		q += " AND " + c.Where
	}
	return q
}

func (c Column) updateSQL() string {
	return fmt.Sprintf(`UPDATE %s SET %s=$1 WHERE %s::text=$2 AND %s=$3`,
		pgx.Identifier{c.Table}.Sanitize(), pgx.Identifier{c.ValueColumn}.Sanitize(), pgx.Identifier{c.KeyColumn}.Sanitize(), pgx.Identifier{c.ValueColumn}.Sanitize())
}

func (c Column) rewrap(v string) (string, bool, error) {
	if c.Family == CAPrivateKey {
		return secrets.RewrapCAPrivateKey(v)
	}
	return secrets.RewrapProviderSecret(v)
}

type row struct{ key, value string }

func tableExists(ctx context.Context, db DB, table string) (bool, error) {
	rows, err := db.Query(ctx, `SELECT to_regclass($1) IS NOT NULL`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var ok bool
	if rows.Next() {
		if err := rows.Scan(&ok); err != nil {
			return false, err
		}
	}
	return ok, rows.Err()
}

// Run scans every column. With apply=false it only reports formats
// (a dry run / pre-downgrade check); with apply=true it rewraps values not
// already in the configured target format.
func Run(ctx context.Context, db DB, cols []Column, apply bool) ([]Report, error) {
	// Validate the write configuration up front so a typo cannot half-apply.
	if _, err := secrets.ConfiguredCipher(); err != nil {
		return nil, err
	}
	if _, err := secrets.ActiveSM4KeyID(); err != nil {
		return nil, err
	}
	var reports []Report
	for _, c := range cols {
		ok, err := tableExists(ctx, db, c.Table)
		if err != nil {
			return reports, err
		}
		if !ok {
			continue
		}
		rep := Report{Column: c.name(), Formats: map[string]int{}}
		rows, err := db.Query(ctx, c.selectSQL())
		if err != nil {
			return reports, fmt.Errorf("%s: %w", c.name(), err)
		}
		var pending []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.key, &r.value); err != nil {
				rows.Close()
				return reports, fmt.Errorf("%s: %w", c.name(), err)
			}
			rep.Formats[secrets.DescribeCiphertext(r.value)]++
			pending = append(pending, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return reports, fmt.Errorf("%s: %w", c.name(), err)
		}
		if apply {
			for _, r := range pending {
				out, changed, err := c.rewrap(r.value)
				if err != nil {
					rep.Failed++
					rep.Errors = append(rep.Errors, fmt.Sprintf("%s=%s: %v", c.KeyColumn, r.key, err))
					continue
				}
				if !changed {
					continue
				}
				tag, err := db.Exec(ctx, c.updateSQL(), out, r.key, r.value)
				if err != nil {
					rep.Failed++
					rep.Errors = append(rep.Errors, fmt.Sprintf("%s=%s: %v", c.KeyColumn, r.key, err))
					continue
				}
				if tag.RowsAffected() == 0 {
					rep.Skipped++
					continue
				}
				rep.Rewrapped++
			}
		}
		reports = append(reports, rep)
	}
	return reports, nil
}

// ErrFailures is returned by Summarize when any row failed.
var ErrFailures = errors.New("rewrap finished with failures")

// Summarize returns ErrFailures when any column reported a failure.
func Summarize(reports []Report) error {
	for _, r := range reports {
		if r.Failed > 0 {
			return ErrFailures
		}
	}
	return nil
}
