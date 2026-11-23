package modelrouter

import "fmt"

// 模型名「查不到」的原因。只描述名字解析，与线路健康、熔断、缺凭证无关。
const (
	ModelMissNotFound  = "not_found" // 目录里没有这个名字（也没有唯一的后缀匹配）
	ModelMissInactive  = "inactive"  // 名字存在，但模型或供应商已停用，不在可用目录里
	ModelMissAmbiguous = "ambiguous" // 不带前缀的名字匹配到多个不同的模型全名，不猜
)

// ModelNotFoundError 表示请求的模型名在租户「可用模型目录」里解析不到。
// errors.Is(err, ErrModelNotFound) 为真；数据库故障等基础设施错误不会是这个类型。
type ModelNotFoundError struct {
	TenantID  string
	Requested string
	Reason    string
	// Candidates 仅在 Reason=ambiguous 时有值：可用目录里最后一段与请求名相等的模型全名，只用于审计。
	Candidates []string
}

func (e *ModelNotFoundError) Error() string {
	return fmt.Sprintf("model %s is not configured for tenant %s (%s)", e.Requested, e.TenantID, e.Reason)
}

func (e *ModelNotFoundError) Is(target error) bool { return target == ErrModelNotFound }
