package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

// cnError 是面向客户的中文错误：Error() 只给中文说明，Unwrap 保留原始原因供 errors.Is/As。
type cnError struct {
	msg   string
	cause error
}

func (e *cnError) Error() string { return e.msg }
func (e *cnError) Unwrap() error { return e.cause }

func cnErrorf(cause error, format string, args ...any) error {
	return &cnError{msg: fmt.Sprintf(format, args...), cause: cause}
}

var statusCodePattern = regexp.MustCompile(`status (\d{3})`)

// FriendlyError 把发送错误转成客户可读的中文原因，不暴露英文技术细节。
func FriendlyError(err error) string {
	if err == nil {
		return ""
	}
	var ce *cnError
	if errors.As(err, &ce) {
		return ce.msg
	}
	var se *chatbotStatusError
	if errors.As(err, &se) {
		return se.Error()
	}
	switch {
	case errors.Is(err, safetarget.ErrPrivateAddress), errors.Is(err, safetarget.ErrForbiddenAddress):
		return "目标地址不被允许：禁止发往内网、回环或云元数据地址"
	case errors.Is(err, safetarget.ErrInvalidURL):
		return "目标地址格式不正确，请填写完整的 http(s) 地址"
	case errors.Is(err, safetarget.ErrResolution):
		return "目标域名无法解析，请检查地址或网络"
	case errors.Is(err, safetarget.ErrRedirectNotAllowed):
		return "目标地址发生了跳转，出于安全考虑已拒绝"
	case errors.Is(err, context.DeadlineExceeded):
		return "连接目标地址超时"
	case errors.Is(err, context.Canceled):
		return "发送已取消"
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return "连接目标地址超时"
		}
		return "无法连接到目标地址，请检查网络连通性"
	}
	if m := statusCodePattern.FindStringSubmatch(err.Error()); m != nil {
		return "目标地址返回 HTTP " + m[1] + "，请检查地址与凭证"
	}
	return "发送失败，请检查渠道配置与网络连通性"
}
