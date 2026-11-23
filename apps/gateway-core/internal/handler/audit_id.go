package handler

import (
	"strings"

	"github.com/google/uuid"
)

const auditIDEntropyHexChars = 24

func newAuditID(prefix string) string {
	randomHex := strings.ReplaceAll(uuid.NewString(), "-", "")
	return prefix + randomHex[:auditIDEntropyHexChars]
}
