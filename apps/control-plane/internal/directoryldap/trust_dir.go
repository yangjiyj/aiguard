package directoryldap

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
)

// 共享目录 CA 信任：解决「预览通过、激活时 FullSync 报 PKIX path building failed」。
//
// 现场根因是两条互不相通的信任源：
//   - 预览走 Go 侧，用库里存的 ca_cert_pem；
//   - Keycloak FullSync 走 JVM 侧，只认 KC_TRUSTSTORE_PATHS 指向的目录。
//
// 运维把 CA 填进控制台，Keycloak 看不到；放进信任目录，预览看不到。两边都
// 得配才行，而现场只会配一处 —— 于是预览过、激活炸。
//
// 这里让 Go 侧也读同一个目录（容器内挂的就是 Keycloak 的 truststores），
// 做到「CA 放一个位置，两个消费者同时生效」。仍是完整校验：只补可信根，
// 不放宽任何验证。
//
// 有意不做缓存：目录很小，而运维中途补一张 CA 后应当立即生效，不必重启。
const directoryTrustDirEnv = "DIRECTORY_TRUST_DIR"

// loadSharedTrustAnchors 读取信任目录里的所有 CA 证书。
//
// 刻意的取舍：
//   - 只收 IsCA 的证书。用户明确要求绝不盲信任意叶子证书，所以叶子一律丢弃
//     （放错位置的服务器证书不该变成信任根）。
//   - 非证书文件（.gitkeep 等）与解析失败的内容一律跳过，不让单个坏文件拖垮
//     整个加载 —— 失败的代价是「少一个可信根」，绝不是「信任一切」。
//   - 目录不存在（base 包无此挂载）返回空，属正常路径。
func loadSharedTrustAnchors(dir string) []*x509.Certificate {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	anchors := make([]*x509.Certificate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			continue
		}
		for _, certificate := range decodeCACertificates(raw) {
			anchors = append(anchors, certificate)
		}
	}
	return anchors
}

func decodeCACertificates(raw []byte) []*x509.Certificate {
	certificates := make([]*x509.Certificate, 0, 1)
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return certificates
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			continue
		}
		certificates = append(certificates, certificate)
	}
}
