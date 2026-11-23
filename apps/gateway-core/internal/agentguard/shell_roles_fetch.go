package agentguard

import (
	"net/url"
	"regexp"
	"strings"
)

// 把参数当 URL 用的程序（规格审查第 9 条）：git clone/fetch/pull/push/ls-remote/remote add/
// submodule add，pip install，npm/pnpm/yarn install/add，go get/install，helm repo add/install，
// docker pull。它们的远程 URL（含 --index-url=URL 这类选项值）整词不算文件；本地路径和
// file:// 照旧按读判定。其余程序里 URL 形状的词仍按 2.9.21 判定（见 shellWordCandidates）。

// looksLikeRemoteURL reports a URL with a host and any scheme but file
// (https, git, ssh, git+https ...). A loopback host (localhost, 127.0.0.0/8,
// ::1, 0.0.0.0) or a path with ".." segments (also %2e%2e) does not count: a
// local server may resolve it to a local file.
func looksLikeRemoteURL(word string) bool {
	word = strings.TrimSpace(word)
	if word == "" || strings.ContainsAny(word, " \t\n") {
		return false
	}
	parsed, err := url.Parse(word)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || strings.EqualFold(parsed.Scheme, "file") {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if ip, ok := parseIPLiteral(strings.Trim(host, "[]")); ok && (ip.Unmap().IsLoopback() || ip.IsUnspecified()) {
		return false
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == ".." {
			return false
		}
	}
	return !strings.Contains(strings.ToLower(parsed.EscapedPath()), "%2e%2e")
}

// looksLikeLocalRepository: a git repository operand written as a local path.
func looksLikeLocalRepository(word string) bool {
	if strings.HasPrefix(strings.ToLower(word), "file:") {
		return true
	}
	for _, prefix := range []string{"/", "~", "./", "../"} {
		if strings.HasPrefix(word, prefix) {
			return true
		}
	}
	return false
}

// scpRemote matches git's scp-like remote syntax user@host:path.
var scpRemote = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^/]`)

// markURLArguments marks the remote URLs among args[from:] (also as the value
// of --option=URL) as not files.
func markURLArguments(args []string, from int, roles map[int]shellArgRole) {
	for at := from; at < len(args); at++ {
		word := args[at]
		if looksLikeRemoteURL(word) {
			roles[at] = shellArgSkip
			continue
		}
		if name, value, ok := strings.Cut(word, "="); ok && strings.HasPrefix(name, "-") && looksLikeRemoteURL(value) {
			roles[at] = shellArgSkip
		}
	}
}

func firstOperandIndex(args []string) int {
	for at, word := range args {
		if !strings.HasPrefix(word, "-") {
			return at
		}
	}
	return -1
}

// fetchSubcommands lists, per program, the subcommands whose operands may be
// URLs to download from.
var fetchSubcommands = map[string]map[string]bool{
	"pip":  flagSet("install", "download", "wheel"),
	"pip3": flagSet("install", "download", "wheel"),
	"npm":  flagSet("install", "i", "add"),
	"pnpm": flagSet("install", "i", "add"),
	"yarn": flagSet("install", "add"),
	"go":   flagSet("get", "install"),
	"helm": flagSet("install", "upgrade", "pull"),
}

// fetchURLRoles: only the URLs are not files; options and other operands
// (requirements files, local packages and charts) are still read.
func fetchURLRoles(program string) shellRoleHandler {
	return func(args []string) (shellCommandRoles, bool) {
		sub := firstOperandIndex(args)
		if sub < 0 {
			return shellCommandRoles{}, false
		}
		roles := newShellCommandRoles()
		switch {
		case fetchSubcommands[program][args[sub]]:
			roles.roles[sub] = shellArgSkip
		case program == "helm" && args[sub] == "repo" && sub+1 < len(args) && args[sub+1] == "add":
			roles.roles[sub], roles.roles[sub+1] = shellArgSkip, shellArgSkip
			sub++
		default:
			return shellCommandRoles{}, false
		}
		markURLArguments(args, sub+1, roles.roles)
		return roles, true
	}
}

// dockerRoles: docker pull's operands are image references in a registry,
// never local files. Every other docker command is judged as in 2.9.21.
func dockerRoles(args []string) (shellCommandRoles, bool) {
	start := 0
	if len(args) > 1 && args[0] == "image" {
		start = 1
	}
	if len(args) <= start || args[start] != "pull" {
		return shellCommandRoles{}, false
	}
	roles := newShellCommandRoles()
	for at := start; at < len(args); at++ {
		roles.roles[at] = shellArgSkip
	}
	return roles, true
}
