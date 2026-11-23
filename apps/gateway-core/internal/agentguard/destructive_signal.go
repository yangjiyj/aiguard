package agentguard

import (
	"path"
	"strings"
)

// DestructiveSignalPresent is the gate in front of the parse-rejected
// fail-safe. It answers one question about text the analyzers could not parse
// reliably (invalid tool-argument JSON, an unterminated shell quote, a budget
// overflow): could a destructive operation be hiding in it?
//
// A parse failure alone is not evidence of intent. Coding agents on Windows
// routinely emit `ls -la "C:\Users\x\"` or tool-argument JSON with raw `\U`
// escapes; blocking every one of those as destructive is a false positive the
// administrator cannot configure away. The scan is deliberately conservative in
// the other direction: any destructive command word the deterministic
// analyzer knows about, any output redirect to a real file, and any construct
// that hides the executed command (command substitution, eval, nested shells)
// keeps the fail-safe in force.
func DestructiveSignalPresent(text string) bool {
	text = strings.ToLower(text)
	if strings.TrimSpace(text) == "" {
		return false
	}
	if hidesExecutedCommand(text) || hasFileOutputRedirect(text) {
		return true
	}
	for _, words := range [][]string{signalWordsPOSIX(text), signalWordsWindows(text)} {
		if destructiveSignalWords(words) {
			return true
		}
	}
	return false
}

// DestructiveArgumentsSignalPresent is the gate for tool arguments whose JSON
// could not be decoded at all: the raw text may carry either a shell command or
// a SQL statement, so both vocabularies keep the fail-safe in force.
func DestructiveArgumentsSignalPresent(raw string) bool {
	if DestructiveSignalPresent(raw) {
		return true
	}
	present := map[string]bool{}
	for _, word := range signalWordsPOSIX(strings.ToLower(raw)) {
		present[word] = true
	}
	return present["drop"] || present["truncate"] || present["grant"] || present["revoke"] ||
		present["delete"] && present["from"] ||
		present["update"] && present["set"] ||
		present["alter"] && (present["table"] || present["database"] || present["schema"])
}

var destructiveSignalCommands = map[string]struct{}{
	"rm": {}, "rmdir": {}, "unlink": {}, "shred": {}, "srm": {}, "sdelete": {},
	"del": {}, "erase": {}, "rd": {}, "format": {}, "wipefs": {}, "dd": {},
	"truncate": {}, "diskpart": {}, "fdisk": {}, "parted": {}, "cipher": {},
	"remove-item": {}, "ri": {}, "clear-content": {}, "clc": {},
	"format-volume": {}, "clear-disk": {}, "remove-partition": {},
}

func destructiveSignalWords(words []string) bool {
	present := make(map[string]struct{}, len(words))
	for _, word := range words {
		word = strings.TrimSuffix(strings.TrimSuffix(word, ".exe"), ".cmd")
		if word == "" {
			continue
		}
		if _, ok := destructiveSignalCommands[word]; ok || strings.HasPrefix(word, "mkfs") {
			return true
		}
		present[word] = struct{}{}
	}
	has := func(values ...string) bool {
		for _, value := range values {
			if _, ok := present[value]; ok {
				return true
			}
		}
		return false
	}
	deletes := false
	for word := range present {
		deletes = deletes || word == "--del" || strings.HasPrefix(word, "--delete")
	}
	return has("git") && (has("reset", "clean") || has("push") && has("-f", "--force", "--force-with-lease")) ||
		has("dropdb") || has("mysqladmin") && has("drop") ||
		has("mysql", "mariadb", "psql") && has("drop", "truncate", "delete", "update") ||
		has("redis-cli") && has("flushall", "flushdb") ||
		has("aws") && has("rm") && has("--recursive") ||
		has("az") && has("storage") && has("delete", "delete-batch") ||
		has("ossutil", "ossutil64", "s3cmd") && has("rm", "del") ||
		has("rclone") && has("purge") ||
		has("rsync") && deletes ||
		has("set-content") ||
		has("docker", "podman") && has("prune", "rmi") ||
		has("docker", "docker-compose") && has("down") && has("-v", "--volumes") ||
		has("kubectl", "helm") && has("delete", "uninstall") ||
		has("terraform", "tofu", "pulumi") && has("destroy") ||
		has("find") && has("-delete", "-exec", "-execdir", "-ok")
}

// signalWordsPOSIX removes quotes and backslashes the way a POSIX shell would,
// so quoted or escaped fragments of a word (r\m, "r"m) still read as rm, and
// returns the basename of every word.
func signalWordsPOSIX(text string) []string {
	var cleaned strings.Builder
	cleaned.Grow(len(text))
	for index := 0; index < len(text); index++ {
		switch ch := text[index]; ch {
		case '\\', '\'', '"':
			continue
		default:
			cleaned.WriteByte(ch)
		}
	}
	return signalFields(cleaned.String(), false)
}

// signalWordsWindows keeps backslashes as path separators so a full Windows
// path such as C:\tools\rm.exe still reads as rm.
func signalWordsWindows(text string) []string {
	cleaned := strings.NewReplacer(`'`, " ", `"`, " ").Replace(text)
	return signalFields(cleaned, true)
}

func signalFields(text string, windowsPaths bool) []string {
	fields := strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case ' ', '\t', '\r', '\n', ';', '|', '&', '(', ')', '<', '>', '`', '{', '}', ',', '[', ']', ':', '=':
			return true
		default:
			return false
		}
	})
	words := make([]string, 0, len(fields))
	for _, field := range fields {
		if windowsPaths {
			field = strings.ReplaceAll(field, `\`, "/")
		}
		if strings.Contains(field, "/") {
			field = path.Base(field)
		}
		words = append(words, field)
	}
	return words
}

func hidesExecutedCommand(text string) bool {
	if strings.Contains(text, "$(") || strings.Contains(text, "`") {
		return true
	}
	words := signalWordsPOSIX(text)
	for index, word := range words {
		switch word {
		case "eval", "iex", "invoke-expression", "xargs", "source", "base64":
			return true
		case "sh", "bash", "dash", "zsh", "ksh", "pwsh", "powershell", "cmd", "python", "python3", "perl", "ruby", "node":
			for _, flag := range words[index+1:] {
				switch flag {
				case "-c", "/c", "/k", "-command", "-encodedcommand", "-enc", "-ec", "-e":
					return true
				}
			}
		}
	}
	return false
}

// hasFileOutputRedirect reports a `>`/`>>` whose target is not a sink
// (&1, &2, /dev/null, NUL, $null).
func hasFileOutputRedirect(text string) bool {
	for index := 0; index < len(text); index++ {
		if text[index] != '>' {
			continue
		}
		rest := text[index+1:]
		rest = strings.TrimPrefix(rest, ">")
		rest = strings.TrimPrefix(rest, "|")
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			continue
		}
		sink := false
		for _, candidate := range []string{"&1", "&2", "&-", "/dev/null", "nul", "$null", "null"} {
			if strings.HasPrefix(rest, candidate) {
				tail := rest[len(candidate):]
				if tail == "" || strings.ContainsAny(tail[:1], " \t\r\n;|&)\"'") {
					sink = true
					break
				}
			}
		}
		if !sink {
			return true
		}
	}
	return false
}
