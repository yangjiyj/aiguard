package retentionstore

import "fmt"

// 留存存储后端标识。
const (
	BackendLocal = "local"
	BackendS3    = "s3"
)

// Config 选择并配置留存存储后端。LocalRoot 既是 local 后端的根,也作为 s3 后端
// 切换前旧对象的回退根(GetObject 在 S3 取不到时回退本机读)。
type Config struct {
	Backend     string // "local"(默认) | "s3"
	LocalRoot   string
	S3Endpoint  string
	S3Bucket    string
	S3AccessKey string
	S3SecretKey string
	S3Region    string
	S3UseSSL    bool
	S3Prefix    string
}

// NewStore 按配置实例化留存后端。默认 local;backend=s3 时建 S3 后端(失败返回错误,
// 不静默降级——避免以为在用对象存储、实际悄悄写本机)。
func NewStore(cfg Config) (Store, error) {
	switch cfg.Backend {
	case BackendS3:
		return NewS3Store(cfg)
	case BackendLocal, "":
		return NewLocalStore(cfg.LocalRoot)
	default:
		return nil, fmt.Errorf("unknown retention backend %q", cfg.Backend)
	}
}
