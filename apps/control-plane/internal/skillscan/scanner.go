package skillscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type RiskLevel string
type Decision string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"

	DecisionAllow   Decision = "allow"
	DecisionConfirm Decision = "confirm"
	DecisionBlock   Decision = "block"
)

const (
	defaultMaxArchiveBytes     int64 = 20 << 20
	defaultMaxFiles                  = 1000
	defaultMaxSingleFileBytes  int64 = 2 << 20
	defaultMaxExpandedBytes    int64 = 50 << 20
	defaultMaxPathDepth              = 20
	defaultMaxArchiveDepth           = 3
	defaultMaxCompressionRatio       = 100
	maxArchivePathBytes              = 512
	maxEvidencePreviewRunes          = 240
)

type Limits struct {
	MaxArchiveBytes     int64
	MaxFiles            int
	MaxSingleFileBytes  int64
	MaxExpandedBytes    int64
	MaxPathDepth        int
	MaxArchiveDepth     int
	MaxCompressionRatio int
}

type Finding struct {
	Type            string    `json:"type"`
	Severity        RiskLevel `json:"severity"`
	File            string    `json:"file,omitempty"`
	Line            int       `json:"line,omitempty"`
	EvidencePreview string    `json:"evidence_preview,omitempty"`
	ContentHash     string    `json:"content_hash,omitempty"`
}

type ManifestEntry struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
}

type Report struct {
	BundleHash string          `json:"bundle_hash"`
	TreeHash   string          `json:"tree_hash"`
	RiskLevel  RiskLevel       `json:"risk_level"`
	Decision   Decision        `json:"decision"`
	Findings   []Finding       `json:"findings"`
	Manifest   []ManifestEntry `json:"manifest"`
}

type ScanError struct {
	Code string
	File string
}

func (e *ScanError) Error() string {
	return "skill archive rejected: " + e.Code
}

type Scanner struct {
	limits Limits
}

func NewScanner(limits Limits) *Scanner {
	if limits.MaxArchiveBytes <= 0 {
		limits.MaxArchiveBytes = defaultMaxArchiveBytes
	}
	if limits.MaxFiles <= 0 {
		limits.MaxFiles = defaultMaxFiles
	}
	if limits.MaxSingleFileBytes <= 0 {
		limits.MaxSingleFileBytes = defaultMaxSingleFileBytes
	}
	if limits.MaxExpandedBytes <= 0 {
		limits.MaxExpandedBytes = defaultMaxExpandedBytes
	}
	if limits.MaxPathDepth <= 0 {
		limits.MaxPathDepth = defaultMaxPathDepth
	}
	if limits.MaxArchiveDepth <= 0 {
		limits.MaxArchiveDepth = defaultMaxArchiveDepth
	}
	if limits.MaxCompressionRatio <= 0 {
		limits.MaxCompressionRatio = defaultMaxCompressionRatio
	}
	return &Scanner{limits: limits}
}

func Scan(archive []byte) (Report, error) {
	return NewScanner(Limits{}).Scan(archive)
}

func (s *Scanner) Scan(archive []byte) (Report, error) {
	report := Report{
		BundleHash: digestHex(archive),
		RiskLevel:  RiskLow,
		Decision:   DecisionAllow,
		Findings:   []Finding{},
		Manifest:   []ManifestEntry{},
	}
	state := archiveScanState{scanner: s, report: &report, seen: map[string]bool{}}
	var scanErr *ScanError
	if int64(len(archive)) > s.limits.MaxArchiveBytes {
		scanErr = &ScanError{Code: "archive_too_large"}
	} else {
		scanErr = state.scanZip(archive, "", 0)
	}

	sort.Slice(report.Manifest, func(i, j int) bool {
		return report.Manifest[i].Path < report.Manifest[j].Path
	})
	report.TreeHash = manifestTreeHash(report.Manifest)
	if scanErr != nil {
		report.RiskLevel, report.Decision = RiskCritical, DecisionBlock
		report.Findings = append(report.Findings, Finding{
			Type: "archive_violation", Severity: RiskCritical, File: scanErr.File,
			EvidencePreview: scanErr.Code,
		})
		return report, scanErr
	}
	if !state.skillManifest {
		report.Findings = append(report.Findings, Finding{
			Type: "manifest_missing", Severity: RiskMedium,
			EvidencePreview: "SKILL.md not present",
		})
	}
	report.RiskLevel, report.Decision = classifyFindings(report.Findings)
	return report, nil
}

func manifestTreeHash(manifest []ManifestEntry) string {
	entries := append([]ManifestEntry(nil), manifest...)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	tree := sha256.New()
	for _, entry := range entries {
		_, _ = io.WriteString(tree, entry.Path)
		_, _ = tree.Write([]byte{0})
		_, _ = io.WriteString(tree, entry.SHA256)
		_, _ = tree.Write([]byte{0})
		_, _ = io.WriteString(tree, strconv.FormatInt(entry.Size, 10))
		_, _ = tree.Write([]byte{0})
	}
	return hex.EncodeToString(tree.Sum(nil))
}

func validateArchivePath(name string, maxDepth int) (string, error) {
	if name == "" || len(name) > maxArchivePathBytes || !utf8.ValidString(name) {
		return "", errors.New("invalid_path")
	}
	if strings.Contains(name, "\\") || strings.ContainsRune(name, '\x00') || path.IsAbs(name) {
		return "", errors.New("path_escape")
	}
	for _, char := range name {
		if unicode.IsControl(char) {
			return "", errors.New("invalid_path")
		}
	}
	clean := path.Clean(name)
	trimmed := strings.TrimSuffix(name, "/")
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != trimmed {
		return "", errors.New("path_escape")
	}
	parts := strings.Split(clean, "/")
	if len(parts) > maxDepth || (len(parts[0]) >= 2 && parts[0][1] == ':') {
		return "", errors.New("path_depth_or_volume")
	}
	return clean, nil
}

func isEmbeddedArchive(name string) bool {
	base := strings.ToLower(path.Base(name))
	for _, suffix := range []string{
		".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".bz2", ".xz",
		".7z", ".rar", ".jar", ".war", ".whl", ".iso",
	} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func isScannableText(name string) bool {
	base := strings.ToLower(path.Base(name))
	if base == "skill.md" || base == "package.json" || base == "requirements.txt" ||
		base == "pyproject.toml" || base == "cargo.toml" || base == "go.mod" ||
		base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") ||
		base == "makefile" || base == "procfile" || strings.HasSuffix(base, ".lock") {
		return true
	}
	switch strings.ToLower(path.Ext(base)) {
	case ".md", ".txt", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".vbs", ".ipynb",
		".py", ".rb", ".pl", ".php", ".lua", ".js", ".mjs", ".cjs", ".ts", ".tsx",
		".go", ".rs", ".java", ".kt", ".kts", ".cs", ".swift",
		".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf":
		return true
	default:
		return false
	}
}

type textRule struct {
	kind     string
	severity RiskLevel
	pattern  *regexp.Regexp
}

var textRules = []textRule{
	{kind: "dangerous_command", severity: RiskCritical, pattern: regexp.MustCompile(`(?i)(rm\s+-[a-z]*r[a-z]*f|mkfs(?:\.|\s)|dd\s+if=|chmod\s+[0-7]*[4-7][0-7]{2}|(?:curl|wget)[^\n|;]*(?:\||;)\s*(?:sh|bash)|(?:iwr|invoke-webrequest)[^\n|;]*\|\s*(?:iex|invoke-expression)|remove-item[^\n]{0,120}-(?:recurse|r)[^\n]{0,80}-(?:force|fo)|format(?:-volume|\s+[a-z]:)|powershell(?:\.exe)?[^\n]{0,120}-(?:enc|encodedcommand)|(?:del|rmdir)\s+/(?:s|q)|nc[^\n]{0,120}\s-e\s|/dev/tcp/|docker\.sock|/etc/shadow)`)},
	{kind: "credential_path", severity: RiskHigh, pattern: regexp.MustCompile(`(?i)(?:^|[\s"'=])(?:~?/)?\.(?:ssh|aws|kube)(?:/|\b)|(?:^|[/\s])\.env(?:\b|/)|id_rsa|credentials(?:\.json)?`)},
	{kind: "metadata_access", severity: RiskCritical, pattern: regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)`)},
	{kind: "network_egress", severity: RiskMedium, pattern: regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)},
	{kind: "install_hook", severity: RiskHigh, pattern: regexp.MustCompile(`(?i)(postinstall|preinstall|prepare\s*["':=]|hooks?/|install\.(?:sh|py|js))`)},
	{kind: "unbounded_dependency", severity: RiskMedium, pattern: regexp.MustCompile(`(?i)(?:pip|pip3|npm|pnpm|yarn)\s+install\s+(?:--[^\s]+\s+)*[a-z0-9_.@/-]+(?:\s|$)|["'][^"']+["']\s*:\s*["'](?:\*|latest|[~^]?[0-9]+(?:\.[x*])+)["']`)},
	{kind: "hidden_instruction", severity: RiskHigh, pattern: regexp.MustCompile(`(?i)(ignore\s+(?:all\s+)?previous\s+instructions?|reveal|print|exfiltrat)[^\n]{0,80}(system\s+prompt|developer\s+message|hidden\s+instruction)`)},
	{kind: "dynamic_code_execution", severity: RiskHigh, pattern: regexp.MustCompile(`(?i)(?:\b(?:eval|exec|invoke-expression|iex)\s*\(|\|\s*(?:iex|invoke-expression)\b)`)},
	{kind: "obfuscated_payload", severity: RiskHigh, pattern: regexp.MustCompile(`(?i)(base64\.(?:b64decode|decodebytes)|frombase64string|\batob\s*\(|-(?:enc|encodedcommand)\b)`)},
}

var secretAssignment = regexp.MustCompile(`(?i)(["']?[a-z0-9_-]*(?:api[_-]?key|access[_-]?token|token|secret|password|authorization|cookie)[a-z0-9_-]*["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|[^\s,;]+)`)
var privateKeyStart = regexp.MustCompile(`(?i)-----BEGIN [^-\n]{0,64}PRIVATE KEY-----`)
var privateKeyEnd = regexp.MustCompile(`(?i)-----END [^-\n]{0,64}PRIVATE KEY-----`)
var bearerSecret = regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._~+/=-]+`)
var urlUserInfo = regexp.MustCompile(`(?i)(https?://)[^/@\s'"]+:[^/@\s'"]+@`)
var urlQuerySecret = regexp.MustCompile(`(?i)([?&](?:api[_-]?key|access[_-]?token|token|secret|password|signature)=)[^&\s'"<>]+`)
var quotedJSONText = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
var exactNodePackage = regexp.MustCompile(`^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+@[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$`)

func exactPinnedNodeInstall(line string) bool {
	args := strings.Fields(line)
	if len(args) < 3 || (args[0] != "npm" && args[0] != "pnpm" && args[0] != "yarn") || args[1] != "install" {
		return false
	}
	packages := 0
	for _, arg := range args[2:] {
		switch arg {
		case "--save", "--save-dev", "--save-exact", "--global", "-g", "--no-audit", "--no-fund":
			continue
		}
		if !exactNodePackage.MatchString(arg) {
			return false
		}
		packages++
	}
	return packages > 0
}

func scanText(file, contentHash, content string) []Finding {
	findings := make([]Finding, 0)
	lines := strings.Split(content, "\n")
	safeLines := strings.Split(redactPrivateKeys(content, true), "\n")
	seen := map[string]struct{}{}
	for _, rule := range textRules {
		for index, line := range lines {
			if !rule.pattern.MatchString(line) {
				continue
			}
			if rule.kind == "unbounded_dependency" && exactPinnedNodeInstall(line) {
				continue
			}
			key := rule.kind + "\x00" + strconv.Itoa(index+1)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, Finding{
				Type: rule.kind, Severity: rule.severity, File: file, Line: index + 1,
				EvidencePreview: sanitizeEvidence(safeLines[index]), ContentHash: contentHash,
			})
		}
	}
	return findings
}

func sanitizeEvidence(value string) string {
	if json.Valid([]byte(value)) {
		var decoded any
		decoder := json.NewDecoder(strings.NewReader(value))
		decoder.UseNumber()
		if decoder.Decode(&decoded) == nil {
			if safe, err := json.Marshal(sanitizeJSONEvidence(decoded)); err == nil {
				value = string(safe)
			}
		}
	} else {
		value = redactEvidenceText(value)
	}
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > maxEvidencePreviewRunes {
		value = string(runes[:maxEvidencePreviewRunes]) + "…"
	}
	return value
}

func redactEvidenceText(value string) string {
	return redactEvidenceTextDepth(value, 0)
}

func redactEvidenceTextDepth(value string, depth int) string {
	if depth >= 16 {
		return "[REDACTED_NESTED_TEXT]"
	}
	value = quotedJSONText.ReplaceAllStringFunc(value, func(quoted string) string {
		var decoded string
		if json.Unmarshal([]byte(quoted), &decoded) != nil {
			return quoted
		}
		safe, _ := json.Marshal(redactEvidenceTextDepth(decoded, depth+1))
		return string(safe)
	})
	value = redactPrivateKeys(value, false)
	value = bearerSecret.ReplaceAllString(value, "$1[REDACTED]")
	value = urlUserInfo.ReplaceAllString(value, "$1[REDACTED]@")
	value = urlQuerySecret.ReplaceAllString(value, "$1[REDACTED]")
	value = secretAssignment.ReplaceAllString(value, "$1[REDACTED]")
	return value
}

func sanitizeJSONEvidence(value any) any {
	switch item := value.(type) {
	case string:
		return redactEvidenceText(item)
	case []any:
		for i := range item {
			item[i] = sanitizeJSONEvidence(item[i])
		}
	case map[string]any:
		for key, child := range item {
			if secretAssignment.MatchString(key + "=value") {
				item[key] = "[REDACTED]"
			} else {
				item[key] = sanitizeJSONEvidence(child)
			}
		}
	}
	return value
}

// SanitizeFindings applies the scanner's evidence contract to stored or external results.
func SanitizeFindings(findings []Finding) []Finding {
	safe := append([]Finding{}, findings...)
	for i := range safe {
		safe[i].EvidencePreview = sanitizeEvidence(safe[i].EvidencePreview)
	}
	return safe
}

func redactPrivateKeys(value string, preserveLines bool) string {
	var redacted strings.Builder
	for {
		start := privateKeyStart.FindStringIndex(value)
		if start == nil {
			redacted.WriteString(value)
			return redacted.String()
		}
		end := len(value)
		if close := privateKeyEnd.FindStringIndex(value[start[1]:]); close != nil {
			end = start[1] + close[1]
		}
		redacted.WriteString(value[:start[0]])
		redacted.WriteString("[REDACTED_PRIVATE_KEY]")
		if preserveLines {
			redacted.WriteString(strings.Repeat("\n", strings.Count(value[start[0]:end], "\n")))
		}
		value = value[end:]
	}
}

func classifyFindings(findings []Finding) (RiskLevel, Decision) {
	risk := RiskLow
	decision := DecisionAllow
	for _, finding := range findings {
		if riskRank(finding.Severity) > riskRank(risk) {
			risk = finding.Severity
		}
		switch finding.Type {
		case "archive_violation", "dangerous_command", "credential_path", "metadata_access":
			decision = DecisionBlock
		default:
			if decision == DecisionAllow {
				decision = DecisionConfirm
			}
		}
	}
	return risk, decision
}

func riskRank(level RiskLevel) int {
	switch level {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	default:
		return 1
	}
}

func digestHex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}
