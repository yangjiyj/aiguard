package consolesso

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	stateTTL  = 10 * time.Minute
	ticketTTL = 60 * time.Second

	stateKeyPrefix  = "console_sso:state:"
	ticketKeyPrefix = "console_sso:ticket:"
)

var errNotFound = errors.New("console sso: not found or expired")

// flowState 在 /login 与 /callback 之间保存一次性授权上下文。
// BindingHash 绑定发起登录的浏览器（cookie 原值只在浏览器里），防登录 CSRF。
type flowState struct {
	Provider     string `json:"provider,omitempty"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	BindingHash  string `json:"binding_hash"`
}

// ticket 是回调成功后发给登录页的一次性凭据：60 秒内换取控制台会话。
// 会话在兑换时才创建，未兑换的票据过期即失效，不留孤儿会话。
type ticket struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
	Subject  string `json:"subject"`
	Provider string `json:"provider,omitempty"`
}

// store 的读取都是 GETDEL：state 与 ticket 都只能用一次。
type store interface {
	putState(ctx context.Context, state string, v flowState) error
	takeState(ctx context.Context, state string) (flowState, error)
	putTicket(ctx context.Context, id string, v ticket) error
	takeTicket(ctx context.Context, id string) (ticket, error)
}

type redisStore struct{ client *redis.Client }

func newRedisStore(client *redis.Client) *redisStore { return &redisStore{client: client} }

func (s *redisStore) put(ctx context.Context, key string, v any, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, key, data, ttl).Err()
}

func (s *redisStore) take(ctx context.Context, key string, v any) error {
	data, err := s.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (s *redisStore) putState(ctx context.Context, state string, v flowState) error {
	return s.put(ctx, stateKeyPrefix+hashHex(state), v, stateTTL)
}

func (s *redisStore) takeState(ctx context.Context, state string) (flowState, error) {
	var v flowState
	err := s.take(ctx, stateKeyPrefix+hashHex(state), &v)
	return v, err
}

func (s *redisStore) putTicket(ctx context.Context, id string, v ticket) error {
	return s.put(ctx, ticketKeyPrefix+hashHex(id), v, ticketTTL)
}

func (s *redisStore) takeTicket(ctx context.Context, id string) (ticket, error) {
	var v ticket
	err := s.take(ctx, ticketKeyPrefix+hashHex(id), &v)
	return v, err
}
