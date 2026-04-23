package util

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// SHA256Hex returns the SHA-256 digest of the trimmed input as a lowercase hex string.
func SHA256Hex(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}
