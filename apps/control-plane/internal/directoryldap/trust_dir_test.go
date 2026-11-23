package directoryldap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// 现场根因：预览走 Go 侧、用库里存的 ca_cert_pem 建信任；Keycloak FullSync
// 走 JVM 侧、只认 KC_TRUSTSTORE_PATHS 目录里的 CA。两条信任源互不相通，
// 于是「预览通过、激活时 FullSync 报 PKIX path building failed」。
//
// 这里锁死共享信任目录的语义：Go 侧必须把同一个目录里的 CA 也加载进来，
// 这样运维只需把 CA 放进一个位置，两个消费者同时生效。

func writeTestCA(t *testing.T, dir, name string) *x509.Certificate {
	t.Helper()
	certificate, pemBytes := newSelfSignedCA(t)
	if err := os.WriteFile(filepath.Join(dir, name), pemBytes, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return certificate
}

func TestDirectoryTrustDirectoryLoadsSharedCAs(t *testing.T) {
	dir := t.TempDir()
	certificate := writeTestCA(t, dir, "customer-root.pem")
	// 非证书文件必须被忽略而不是让整个加载失败：真实部署目录里就有 .gitkeep。
	if err := os.WriteFile(filepath.Join(dir, ".gitkeep"), []byte("# placeholder\n"), 0o644); err != nil {
		t.Fatalf("write placeholder: %v", err)
	}

	t.Setenv(directoryTrustDirEnv, dir)
	config, err := directoryTLSConfig(TestRequest{}, "dc.example.test")
	if err != nil {
		t.Fatalf("directoryTLSConfig() error = %v", err)
	}
	if config.RootCAs == nil {
		t.Fatal("shared trust directory CA was not loaded")
	}
	if !poolContains(config.RootCAs, certificate) {
		t.Fatal("shared trust directory CA is not in the resulting pool")
	}
	if config.InsecureSkipVerify {
		t.Fatal("loading a shared CA must not disable verification")
	}
}

func TestDirectoryTrustDirectoryCombinesWithPerSourceCA(t *testing.T) {
	dir := t.TempDir()
	shared := writeTestCA(t, dir, "shared-root.pem")
	perSource, perSourcePEM := newSelfSignedCA(t)

	t.Setenv(directoryTrustDirEnv, dir)
	config, err := directoryTLSConfig(TestRequest{CACertPEM: string(perSourcePEM)}, "dc.example.test")
	if err != nil {
		t.Fatalf("directoryTLSConfig() error = %v", err)
	}
	// 两个来源必须并存：删掉任何一个都会让一部分客户的目录连不上。
	if !poolContains(config.RootCAs, shared) {
		t.Fatal("shared trust directory CA was dropped when a per-source CA exists")
	}
	if !poolContains(config.RootCAs, perSource) {
		t.Fatal("per-source CA was dropped when a shared trust directory exists")
	}
}

func TestDirectoryTrustDirectoryMissingOrEmptyKeepsDefaultVerification(t *testing.T) {
	// 目录不存在（base 包）和目录里只有占位文件（首装未配 CA）都不能报错，
	// 也不能悄悄放宽校验 —— 默认必须继续做完整校验。
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, ".gitkeep"), []byte("# placeholder\n"), 0o644); err != nil {
		t.Fatalf("write placeholder: %v", err)
	}
	for name, dir := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "does-not-exist"),
		"empty":   empty,
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(directoryTrustDirEnv, dir)
			config, err := directoryTLSConfig(TestRequest{}, "dc.example.test")
			if err != nil {
				t.Fatalf("directoryTLSConfig() error = %v", err)
			}
			if config.InsecureSkipVerify {
				t.Fatal("verification must stay enabled when no shared CA is provisioned")
			}
			if config.MinVersion != tls.VersionTLS12 {
				t.Fatalf("MinVersion = %d, want TLS 1.2", config.MinVersion)
			}
		})
	}
}

func TestDirectoryTrustDirectoryRejectsGarbageWithoutWeakeningTrust(t *testing.T) {
	// 目录里放了非法内容时，绝不能退化成「信任一切」。宁可不加载。
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.pem"), []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatalf("write broken CA: %v", err)
	}
	t.Setenv(directoryTrustDirEnv, dir)
	config, err := directoryTLSConfig(TestRequest{}, "dc.example.test")
	if err != nil {
		t.Fatalf("directoryTLSConfig() error = %v", err)
	}
	if config.InsecureSkipVerify {
		t.Fatal("a malformed shared CA must not disable verification")
	}
}

func TestDirectoryTrustDirectoryIgnoresLeafCertificates(t *testing.T) {
	// 用户明确要求：绝不盲信任意叶子证书。信任目录只接受 CA。
	dir := t.TempDir()
	_, leafPEM := newSelfSignedLeaf(t)
	if err := os.WriteFile(filepath.Join(dir, "leaf.pem"), leafPEM, 0o644); err != nil {
		t.Fatalf("write leaf: %v", err)
	}
	ca := writeTestCA(t, dir, "root.pem")

	t.Setenv(directoryTrustDirEnv, dir)
	config, err := directoryTLSConfig(TestRequest{}, "dc.example.test")
	if err != nil {
		t.Fatalf("directoryTLSConfig() error = %v", err)
	}
	if !poolContains(config.RootCAs, ca) {
		t.Fatal("CA next to a leaf certificate must still load")
	}
	leafBlock, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if poolContains(config.RootCAs, leaf) {
		t.Fatal("a non-CA leaf certificate must never enter the trust pool")
	}
}
