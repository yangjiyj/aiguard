package skillscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"io"
	"mime"
	"path"
	"strings"
)

type archiveScanState struct {
	scanner       *Scanner
	report        *Report
	seen          map[string]bool
	files         int
	expanded      int64
	skillManifest bool
}

func (s *archiveScanState) fail(code, file string) *ScanError {
	return &ScanError{Code: code, File: file}
}

func (s *archiveScanState) entryName(name, prefix string) (string, *ScanError) {
	clean, err := validateArchivePath(name, s.scanner.limits.MaxPathDepth)
	if err != nil {
		return "", s.fail(err.Error(), prefix+name)
	}
	full := prefix + clean
	if _, err := validateArchivePath(full, s.scanner.limits.MaxPathDepth); err != nil {
		return "", s.fail(err.Error(), full)
	}
	folded := strings.ToLower(full)
	if s.seen[folded] {
		return "", s.fail("duplicate_path", full)
	}
	s.seen[folded] = true
	s.files++
	if s.files > s.scanner.limits.MaxFiles {
		return "", s.fail("too_many_files", full)
	}
	return full, nil
}

func (s *archiveScanState) readPayload(stream io.Reader, name string) ([]byte, *ScanError) {
	bound := s.scanner.limits.MaxSingleFileBytes
	remaining := s.scanner.limits.MaxExpandedBytes - s.expanded
	if remaining < bound {
		bound = remaining
	}
	if bound < 0 {
		return nil, s.fail("expanded_size_exceeded", name)
	}
	payload, err := io.ReadAll(io.LimitReader(stream, bound+1))
	if int64(len(payload)) > bound {
		if remaining < s.scanner.limits.MaxSingleFileBytes {
			return nil, s.fail("expanded_size_exceeded", name)
		}
		return nil, s.fail("single_file_too_large", name)
	}
	if err != nil {
		return nil, s.fail("entry_read_failed", name)
	}
	return payload, nil
}

func (s *archiveScanState) scanZip(payload []byte, prefix string, depth int) *ScanError {
	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		code := "invalid_zip"
		if prefix != "" {
			code = "invalid_embedded_archive"
		}
		return s.fail(code, strings.TrimSuffix(prefix, "!/"))
	}
	if len(reader.File) > s.scanner.limits.MaxFiles-s.files {
		return s.fail("too_many_files", strings.TrimSuffix(prefix, "!/"))
	}
	for _, file := range reader.File {
		name, err := s.entryName(file.Name, prefix)
		if err != nil {
			return err
		}
		if file.Mode().IsDir() {
			continue
		}
		if !file.Mode().IsRegular() {
			return s.fail("non_regular_file", name)
		}
		if file.UncompressedSize64 > uint64(s.scanner.limits.MaxSingleFileBytes) {
			return s.fail("single_file_too_large", name)
		}
		if file.UncompressedSize64 > 0 && (file.CompressedSize64 == 0 || file.UncompressedSize64/file.CompressedSize64 > uint64(s.scanner.limits.MaxCompressionRatio)) {
			return s.fail("compression_ratio_exceeded", name)
		}
		stream, openErr := file.Open()
		if openErr != nil {
			return s.fail("entry_open_failed", name)
		}
		body, readErr := s.readPayload(stream, name)
		closeErr := stream.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return s.fail("entry_read_failed", name)
		}
		if err := s.scanFile(name, body, depth); err != nil {
			return err
		}
	}
	return nil
}

func (s *archiveScanState) scanTar(payload []byte, prefix string, depth int) *ScanError {
	reader := tar.NewReader(bytes.NewReader(payload))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return s.fail("invalid_embedded_archive", strings.TrimSuffix(prefix, "!/"))
		}
		name, pathErr := s.entryName(header.Name, prefix)
		if pathErr != nil {
			return pathErr
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return s.fail("non_regular_file", name)
		}
		if header.Size < 0 || header.Size > s.scanner.limits.MaxSingleFileBytes {
			return s.fail("single_file_too_large", name)
		}
		body, readErr := s.readPayload(reader, name)
		if readErr != nil {
			return readErr
		}
		if err := s.scanFile(name, body, depth); err != nil {
			return err
		}
	}
}

func embeddedArchiveKind(name string, payload []byte) string {
	lower := strings.ToLower(name)
	if bytes.HasPrefix(payload, []byte("PK\x03\x04")) || bytes.HasPrefix(payload, []byte("PK\x05\x06")) || bytes.HasPrefix(payload, []byte("PK\x07\x08")) {
		return "zip"
	}
	if bytes.HasPrefix(payload, []byte{0x1f, 0x8b}) {
		return "gzip"
	}
	if bytes.HasPrefix(payload, []byte("BZh")) {
		return "bzip2"
	}
	if len(payload) >= 262 && string(payload[257:262]) == "ustar" {
		return "tar"
	}
	for _, suffix := range []string{".zip", ".jar", ".war", ".whl"} {
		if strings.HasSuffix(lower, suffix) {
			return "zip"
		}
	}
	if strings.HasSuffix(lower, ".tar") {
		return "tar"
	}
	if strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tgz") {
		return "gzip"
	}
	if strings.HasSuffix(lower, ".bz2") || strings.HasSuffix(lower, ".tbz2") {
		return "bzip2"
	}
	if isEmbeddedArchive(name) || bytes.HasPrefix(payload, []byte{0xfd, '7', 'z', 'X', 'Z', 0}) || bytes.HasPrefix(payload, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}) || bytes.HasPrefix(payload, []byte("Rar!")) {
		return "unsupported"
	}
	return ""
}

func (s *archiveScanState) scanFile(name string, payload []byte, depth int) *ScanError {
	s.expanded += int64(len(payload))
	if s.expanded > s.scanner.limits.MaxExpandedBytes {
		return s.fail("expanded_size_exceeded", name)
	}
	hash := digestHex(payload)
	mediaType := mime.TypeByExtension(strings.ToLower(path.Ext(name)))
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	s.report.Manifest = append(s.report.Manifest, ManifestEntry{Path: name, Size: int64(len(payload)), SHA256: hash, MediaType: mediaType})
	if depth == 0 && path.Base(name) == "SKILL.md" {
		s.skillManifest = true
	}
	kind := embeddedArchiveKind(name, payload)
	if kind != "" {
		s.report.Findings = append(s.report.Findings, Finding{Type: "embedded_archive", Severity: RiskHigh, File: name, EvidencePreview: "nested archive recursively inspected", ContentHash: hash})
		if kind == "unsupported" {
			return s.fail("unsupported_embedded_archive", name)
		}
		if depth >= s.scanner.limits.MaxArchiveDepth {
			return s.fail("archive_depth_exceeded", name)
		}
		switch kind {
		case "zip":
			return s.scanZip(payload, name+"!/", depth+1)
		case "tar":
			return s.scanTar(payload, name+"!/", depth+1)
		case "gzip", "bzip2":
			return s.scanCompressed(name, payload, depth+1, kind)
		}
	}
	s.report.Findings = append(s.report.Findings, scanPayloadText(name, hash, payload)...)
	return nil
}

func (s *archiveScanState) scanCompressed(name string, payload []byte, depth int, kind string) *ScanError {
	var reader io.Reader
	var closer io.Closer
	if kind == "gzip" {
		decoded, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return s.fail("invalid_embedded_archive", name)
		}
		reader, closer = decoded, decoded
	} else {
		reader = bzip2.NewReader(bytes.NewReader(payload))
	}
	child := path.Base(name)
	lower := strings.ToLower(child)
	switch {
	case strings.HasSuffix(lower, ".tgz"):
		child = child[:len(child)-4] + ".tar"
	case strings.HasSuffix(lower, ".tbz2"):
		child = child[:len(child)-5] + ".tar"
	case kind == "gzip" && strings.HasSuffix(lower, ".gz"):
		child = child[:len(child)-3]
	case kind == "bzip2" && strings.HasSuffix(lower, ".bz2"):
		child = child[:len(child)-4]
	default:
		child += ".decoded"
	}
	full, entryErr := s.entryName(child, name+"!/")
	if entryErr != nil {
		if closer != nil {
			_ = closer.Close()
		}
		return entryErr
	}
	body, readErr := s.readPayload(reader, full)
	if closer != nil {
		if err := closer.Close(); err != nil && readErr == nil {
			readErr = s.fail("invalid_embedded_archive", name)
		}
	}
	if readErr != nil {
		if readErr.Code == "entry_read_failed" {
			return s.fail("invalid_embedded_archive", name)
		}
		return readErr
	}
	if len(payload) > 0 && int64(len(body))/int64(len(payload)) > int64(s.scanner.limits.MaxCompressionRatio) {
		return s.fail("compression_ratio_exceeded", name)
	}
	return s.scanFile(full, body, depth)
}
