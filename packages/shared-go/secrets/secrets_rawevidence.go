package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// 脱敏原文留证（enc:v3:）：与供应商凭据、MCP 结果相互独立的加密域。
// 密钥由平台数据加密密钥（JJD_PROVIDER_SECRET_KEY / JJD_MASTER_KEY）经 HMAC 域分离派生，
// 用 AES-256-GCM（JJD_SECRETS_CIPHER=sm4-gcm 时用 SM4-GCM），并强制绑定 AAD
// （租户、请求、用户、会话、方向、消息序号、处置），密文被搬到别的行、或被改挂到别的
// 用户/会话下就无法解开。
//
// 去重与完整性摘要用 RawEvidenceContentMAC（HMAC-SHA256，密钥同样由数据加密密钥域分离派生），
// 不存无盐 SHA-256：否则拿到库的人可以离线逐个核对"某个身份证号/手机号是否出现过"。
const (
	rawEvidencePrefix                 = "enc:v3:"
	rawEvidenceKeyDomain              = "jjdguard:raw-evidence:key:v1"
	rawEvidenceMACDomain              = "jjdguard:raw-evidence:content-mac:v1"
	familyRawEvidence    secretFamily = "raw-evidence"
)

// RawEvidenceAAD 是留证密文绑定的附加数据：写入方（网关）与读取方（控制面）必须用同一个函数。
// userID 为空表示匿名请求；sessionID 是库里 session_id 列的值（网关没有会话时用请求编号）。
func RawEvidenceAAD(tenantID, requestID, userID, sessionID, direction string, index int, disposition string) []byte {
	return []byte(strings.Join([]string{"raw-evidence:v2", tenantID, requestID, userID, sessionID, direction, fmt.Sprint(index), disposition}, "\x00"))
}

func rawEvidenceMACKey() ([]byte, error) {
	var base []byte
	mode, err := ConfiguredCipher()
	if err != nil {
		return nil, err
	}
	if mode == CipherSM4GCM {
		keyID, err := ActiveSM4KeyID()
		if err != nil {
			return nil, err
		}
		if base, err = sm4Key(familyRawEvidence, keyID); err != nil {
			return nil, err
		}
	} else if base, err = loadSecretKey(); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, base)
	_, _ = mac.Write([]byte(rawEvidenceMACDomain))
	return mac.Sum(nil), nil
}

// RawEvidenceContentMAC 返回租户内原文的 HMAC-SHA256（32 字节），用于去重；没有数据加密密钥时报错。
func RawEvidenceContentMAC(tenantID string, plaintext []byte) ([]byte, error) {
	key, err := rawEvidenceMACKey()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(tenantID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(plaintext)
	return mac.Sum(nil), nil
}

func rawEvidenceKey() ([]byte, error) {
	base, err := loadSecretKey()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, base)
	_, _ = mac.Write([]byte(rawEvidenceKeyDomain))
	return mac.Sum(nil), nil
}

// EncryptRawEvidence 加密一段脱敏前的原文。plaintext 与 aad 都不能为空。
func EncryptRawEvidence(plaintext, aad []byte) (string, error) {
	if len(plaintext) == 0 || len(aad) == 0 {
		return "", errors.New("raw evidence plaintext and AAD are required")
	}
	key, err := rawEvidenceKey()
	if err != nil {
		return "", err
	}
	mode, err := ConfiguredCipher()
	if err != nil {
		return "", err
	}
	if mode == CipherSM4GCM {
		out, _, err := sm4Seal(familyRawEvidence, rawEvidencePrefix, plaintext, aad)
		return out, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create raw evidence cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create raw evidence GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate raw evidence nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	return rawEvidencePrefix + base64.RawStdEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// DecryptRawEvidence 只接受 enc:v3: 密文，且 AAD 必须与加密时逐字节一致。
func DecryptRawEvidence(ciphertext string, aad []byte) ([]byte, error) {
	if !strings.HasPrefix(ciphertext, rawEvidencePrefix) || len(aad) == 0 {
		return nil, errors.New("invalid raw evidence ciphertext or AAD")
	}
	if env, isSM4, err := parseSM4Envelope(ciphertext, rawEvidencePrefix); err != nil {
		return nil, err
	} else if isSM4 {
		return sm4Open(familyRawEvidence, env, aad)
	}
	key, err := rawEvidenceKey()
	if err != nil {
		return nil, err
	}
	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(ciphertext, rawEvidencePrefix))
	if err != nil {
		return nil, fmt.Errorf("decode raw evidence ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create raw evidence cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create raw evidence GCM: %w", err)
	}
	if len(payload) < gcm.NonceSize() {
		return nil, errors.New("raw evidence ciphertext too short")
	}
	plain, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt raw evidence ciphertext: %w", err)
	}
	return plain, nil
}
