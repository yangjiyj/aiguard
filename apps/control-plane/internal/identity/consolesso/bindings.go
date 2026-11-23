package consolesso

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// W9 9.3：CAS / 企业微信账号绑定。登录只认这里显式建立的绑定。

var (
	ErrBindingConflict = errors.New("console sso: external identity already bound to another account")
	ErrBindingNotFound = errors.New("console sso: binding not found")
	ErrBindingInvalid  = errors.New("console sso: invalid binding")
)

type Binding struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Provider  string    `json:"provider"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"external_subject"`
	CreatedAt time.Time `json:"created_at"`
}

type BindingStore struct{ db *pgxpool.Pool }

func NewBindingStore(db *pgxpool.Pool) *BindingStore {
	if db == nil {
		return nil
	}
	return &BindingStore{db: db}
}

// ValidBindingSubject：CAS user 允许常见账号字符；企业微信 userid 与接口返回规则一致。
func ValidBindingSubject(provider, subject string) bool {
	if subject == "" || subject != strings.TrimSpace(subject) || !utf8.ValidString(subject) || len(subject) > 512 {
		return false
	}
	switch provider {
	case ProviderWeCom:
		return weComUserIDPattern.MatchString(subject)
	case ProviderCAS:
		for _, r := range subject {
			if r < 0x20 || r == 0x7f {
				return false
			}
		}
		return true
	}
	return false
}

func (b *BindingStore) List(ctx context.Context, tenantID, userID string) ([]Binding, error) {
	rows, err := b.db.Query(ctx, `
		SELECT id, tenant_id, user_id, source_type, issuer, external_subject, created_at
		FROM user_identity_links
		WHERE tenant_id=$1 AND user_id=$2 AND source_type IN ('cas','wecom')
		ORDER BY created_at, id
	`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("console sso: list bindings: %w", err)
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		var v Binding
		if err := rows.Scan(&v.ID, &v.TenantID, &v.UserID, &v.Provider, &v.Issuer, &v.Subject, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Create 建立绑定；同一外部主体已绑定到本账号时幂等返回，已绑定到别的账号时 ErrBindingConflict。
func (b *BindingStore) Create(ctx context.Context, v Binding) (Binding, bool, error) {
	if (v.Provider != ProviderCAS && v.Provider != ProviderWeCom) || v.TenantID == "" || v.UserID == "" ||
		strings.TrimSpace(v.Issuer) == "" || !ValidBindingSubject(v.Provider, v.Subject) {
		return Binding{}, false, ErrBindingInvalid
	}
	v.Issuer = strings.TrimSuffix(strings.TrimSpace(v.Issuer), "/")
	var out Binding
	err := b.db.QueryRow(ctx, `
		INSERT INTO user_identity_links (id, tenant_id, user_id, issuer, source_type, source_id, external_subject)
		VALUES ($1,$2,$3,$4,$5,'',$6)
		ON CONFLICT (tenant_id, issuer, source_type, external_subject) DO NOTHING
		RETURNING id, tenant_id, user_id, source_type, issuer, external_subject, created_at
	`, "uil_"+uuid.NewString(), v.TenantID, v.UserID, v.Issuer, v.Provider, v.Subject).Scan(
		&out.ID, &out.TenantID, &out.UserID, &out.Provider, &out.Issuer, &out.Subject, &out.CreatedAt)
	if err == nil {
		return out, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, false, fmt.Errorf("console sso: create binding: %w", err)
	}
	err = b.db.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, source_type, issuer, external_subject, created_at
		FROM user_identity_links
		WHERE tenant_id=$1 AND issuer=$2 AND source_type=$3 AND external_subject=$4
	`, v.TenantID, v.Issuer, v.Provider, v.Subject).Scan(
		&out.ID, &out.TenantID, &out.UserID, &out.Provider, &out.Issuer, &out.Subject, &out.CreatedAt)
	if err != nil {
		return Binding{}, false, fmt.Errorf("console sso: read existing binding: %w", err)
	}
	if out.UserID != v.UserID {
		return Binding{}, false, ErrBindingConflict
	}
	return out, false, nil
}

// Delete 只删本租户的 cas/wecom 绑定，不会误删 OIDC/LDAP 等其他来源的绑定。
func (b *BindingStore) Delete(ctx context.Context, tenantID, id string) (Binding, error) {
	var out Binding
	err := b.db.QueryRow(ctx, `
		DELETE FROM user_identity_links
		WHERE tenant_id=$1 AND id=$2 AND source_type IN ('cas','wecom')
		RETURNING id, tenant_id, user_id, source_type, issuer, external_subject, created_at
	`, tenantID, id).Scan(&out.ID, &out.TenantID, &out.UserID, &out.Provider, &out.Issuer, &out.Subject, &out.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, ErrBindingNotFound
	}
	if err != nil {
		return Binding{}, fmt.Errorf("console sso: delete binding: %w", err)
	}
	return out, nil
}

// Get 读取本租户的一条 cas/wecom 绑定；不存在返回 nil。
func (b *BindingStore) Get(ctx context.Context, tenantID, id string) (*Binding, error) {
	var out Binding
	err := b.db.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, source_type, issuer, external_subject, created_at
		FROM user_identity_links
		WHERE tenant_id=$1 AND id=$2 AND source_type IN ('cas','wecom')
	`, tenantID, id).Scan(&out.ID, &out.TenantID, &out.UserID, &out.Provider, &out.Issuer, &out.Subject, &out.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("console sso: get binding: %w", err)
	}
	return &out, nil
}
