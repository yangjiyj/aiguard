package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// 密码复杂度错误码：前端据此给出中文提示，后端 message 同时给出可读说明。
var (
	errPasswordTooShort      = errors.New("password_too_short")
	errPasswordTooFewClasses = errors.New("password_too_few_classes")
	errPasswordHasUsername   = errors.New("password_contains_username")
	errPasswordReused        = errors.New("password_reused")
)

type passwordPolicyError struct {
	code    error
	message string
	details map[string]int
}

func (e *passwordPolicyError) Error() string { return e.message }
func (e *passwordPolicyError) Unwrap() error { return e.code }
func (e *passwordPolicyError) Code() string  { return e.code.Error() }

// policyErrorDetails 让前端按管理员实际配置提示（而非写死默认值）。
func policyErrorDetails(policy ConsoleLoginPolicy) map[string]int {
	return map[string]int{
		"min_length":    policy.PasswordMinLength,
		"min_classes":   policy.PasswordMinClasses,
		"history_count": policy.PasswordHistoryCount,
	}
}

// passwordCharClasses 统计大写、小写、数字、其他符号四类中出现了几类。
func passwordCharClasses(password string) int {
	var upper, lower, digit, other bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{upper, lower, digit, other} {
		if b {
			n++
		}
	}
	return n
}

// ValidatePasswordComplexity 只做与历史无关的规则：长度、字符类别、不含用户名。
func ValidatePasswordComplexity(policy ConsoleLoginPolicy, username, password string) error {
	if len([]rune(password)) < policy.PasswordMinLength {
		return &passwordPolicyError{errPasswordTooShort, fmt.Sprintf("password must be at least %d characters", policy.PasswordMinLength), policyErrorDetails(policy)}
	}
	if passwordCharClasses(password) < policy.PasswordMinClasses {
		return &passwordPolicyError{errPasswordTooFewClasses, fmt.Sprintf("password must contain at least %d of: uppercase, lowercase, digits, symbols", policy.PasswordMinClasses), policyErrorDetails(policy)}
	}
	if u := strings.TrimSpace(username); len(u) >= 3 && strings.Contains(strings.ToLower(password), strings.ToLower(u)) {
		return &passwordPolicyError{errPasswordHasUsername, "password must not contain the username", policyErrorDetails(policy)}
	}
	return nil
}

// PasswordHistoryStore 由 repository.UserPasswordHistoryRepository 实现。
type PasswordHistoryStore interface {
	RecentHashes(ctx context.Context, userID string, limit int) ([]string, error)
	Record(ctx context.Context, userID, passwordHash string, keep int) error
}

// writePasswordPolicyError 输出 400 + 具体规则码（password_too_short 等）；非规则错误按内部错误处理。
func writePasswordPolicyError(w http.ResponseWriter, err error) {
	var pe *passwordPolicyError
	if errors.As(err, &pe) {
		writeErrorWithStatusAndDetails(w, http.StatusBadRequest, pe.Code(), pe.Error(), pe.details)
		return
	}
	writeError(w, "internal_error", "failed to validate password")
}

func logConsoleSecurityError(action string, err error) {
	log.Printf("console security: %s failed: %v", action, err)
}

// checkPasswordNotReused 与当前哈希及最近 N-1 条历史比对（当前密码算作 N 次之一）。
func checkPasswordNotReused(ctx context.Context, store PasswordHistoryStore, policy ConsoleLoginPolicy, userID, currentHash, password string) error {
	if policy.PasswordHistoryCount <= 0 {
		return nil
	}
	hashes := []string{}
	if currentHash != "" {
		hashes = append(hashes, currentHash)
	}
	if store != nil && policy.PasswordHistoryCount > 1 {
		recent, err := store.RecentHashes(ctx, userID, policy.PasswordHistoryCount-1)
		if err != nil {
			return err
		}
		hashes = append(hashes, recent...)
	}
	for _, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil {
			return &passwordPolicyError{errPasswordReused, fmt.Sprintf("password must differ from the last %d passwords", policy.PasswordHistoryCount), policyErrorDetails(policy)}
		}
	}
	return nil
}
