package agentguard

import (
	"path/filepath"
	"strings"
)

// Using a private key is not reading it. ssh, scp and sftp authenticate with
// the key that -i or -o IdentityFile names, rsync -e and GIT_SSH_COMMAND run
// such an ssh, ssh-add loads keys into the agent, and ssh-keygen -l/-y prints
// only the fingerprint or the public half. None of them writes the private
// key to standard output, so exactly those words are not judged as reads.
//
// Everything else is judged as before: the key as a transfer source, a
// redirection into ssh, any other program reading it, and every other word of
// the same command. Options are parsed with OpenSSH's option tables and stop
// at the first operand, as OpenSSH does (ssh parses the options after the
// destination once more); an unknown option, an -o setting that is not known
// to only pick the key, host key policy, user, port or timeouts, or a word
// that is not literal cancels the exemption, and the key is judged as a read
// again.

// shortOptionTable lists short options: flags take no value, values take the
// rest of the cluster or the next word, denied cancel the exemption.
// reparse: the program parses options again after its first operand, as ssh
// does after the destination ("ssh host -o ProxyCommand=...").
type shortOptionTable struct {
	flags, values, denied string
	reparse               bool
}

// OpenSSH 9: ssh -F/-I, scp -D/-F/-S and sftp -b/-D/-F/-S/-s read a config
// or batch file, load a PKCS#11 provider or run another program.
var sshTransportOptions = map[string]shortOptionTable{
	"ssh":  {flags: "46AaCfGgKkMNnqsTtVvXxYy", values: "BbcDEeFIiJLlmOoPpQRSWw", denied: "FI", reparse: true},
	"scp":  {flags: "346ABCOpqRrsTv", values: "cDFiJloPSX", denied: "DFS"},
	"sftp": {flags: "46AaCfNpqrv", values: "BbcDFiJloPRSsX", denied: "bDFSs"},
}

// sshAddOptions: -S/-s/-e load a provider library.
var sshAddOptions = shortOptionTable{flags: "cCDdKkLlqvXxT", values: "EHht", denied: "Sse"}

// sshKeygenFingerprintOptions: only -l (fingerprint) and -y (public key) with
// -f; -i, -e, -p and the rest convert, rewrite or print key material.
var sshKeygenFingerprintOptions = shortOptionTable{flags: "lyvq", values: "fEP"}

// sshAllowedConfigKeys are the -o settings that keep the exemption: they pick
// the key, the host key policy, the user, port, authentication methods and
// timeouts. Every other setting cancels it, among them ProxyCommand,
// LocalCommand, KnownHostsCommand, XAuthLocation, Match, Include,
// PKCS11Provider and SecurityKeyProvider, which run a local program, load a
// library or read further settings.
var sshAllowedConfigKeys = map[string]bool{
	"identityfile": true, "identitiesonly": true, "user": true, "port": true,
	"stricthostkeychecking": true, "userknownhostsfile": true, "globalknownhostsfile": true,
	"checkhostip": true, "hashknownhosts": true, "updatehostkeys": true, "hostkeyalias": true,
	"hostkeyalgorithms": true, "pubkeyacceptedalgorithms": true, "pubkeyacceptedkeytypes": true,
	"batchmode": true, "passwordauthentication": true, "pubkeyauthentication": true,
	"kbdinteractiveauthentication": true, "challengeresponseauthentication": true,
	"preferredauthentications": true, "numberofpasswordprompts": true,
	"connecttimeout": true, "connectionattempts": true, "serveraliveinterval": true,
	"serveralivecountmax": true, "tcpkeepalive": true, "loglevel": true, "requesttty": true,
	"compression": true, "addressfamily": true,
}

// sshKeyUseContext carries facts about the whole command line.
type sshKeyUseContext struct {
	// gitSSHCommandMentions: how often the raw command names
	// GIT_SSH_COMMAND, counted once per command line.
	gitSSHCommandMentions int
	// stdinFed: standard input of this command may be a pipe, a file, a
	// here-document or a here-string (sftp then reads transfer commands).
	stdinFed bool
}

// rsyncShortFlags are rsync short options without a value. Only they, long
// options with an attached value and rsyncLongFlags may precede -e, so the
// -e value cannot be the value of another option or a transfer source.
const rsyncShortFlags = "vqcarRbulLkKHpEAXogDtUNOJmnWxCzPhiSdy"

var rsyncLongFlags = map[string]bool{
	"--archive": true, "--verbose": true, "--quiet": true, "--compress": true, "--recursive": true,
	"--progress": true, "--partial": true, "--human-readable": true, "--stats": true, "--dry-run": true,
	"--checksum": true, "--update": true, "--times": true, "--perms": true, "--links": true,
	"--delete": true, "--itemize-changes": true,
}

// sshKeyUseArguments returns the positions of args that only name a private
// key the program authenticates with.
func sshKeyUseArguments(program string, args []string, simple shellSimpleCommand, line sshKeyUseContext) map[int]bool {
	if simple.Substitution {
		return nil
	}
	switch program {
	case "ssh", "scp", "sftp":
		if program == "sftp" && (line.stdinFed || simple.StdinFeed || len(simple.InputRedirects) > 0) {
			// sftp reads transfer commands ("put ~/.ssh/id_rsa") from stdin,
			// also through a redirection on its group, loop, subshell or exec.
			return nil
		}
		used, ok := sshIdentityArguments(sshTransportOptions[program], args)
		if !ok {
			return nil
		}
		return used
	case "rsync":
		return rsyncRemoteShellArgument(args)
	case "ssh-add":
		return sshAddKeyArguments(args)
	case "ssh-keygen":
		return sshKeygenFingerprintArguments(args)
	case "export":
		used := map[int]bool{}
		for index, word := range args {
			if sshKeyCommandAssignment(word, line.gitSSHCommandMentions) {
				used[index] = true
			}
		}
		return used
	}
	return nil
}

// walkShortOptions parses the leading short options of args and calls visit
// for each option (at is -1 for a flag). It returns the index of the first
// operand, or false on an unknown or denied option, a missing value, or when
// visit returns false.
func walkShortOptions(table shortOptionTable, args []string, visit func(option byte, value string, at int) bool) (int, bool) {
	for index := 0; index < len(args); index++ {
		word := args[index]
		if word == "--" {
			return index + 1, true
		}
		if word == "-" || !strings.HasPrefix(word, "-") {
			return index, true
		}
		for pos := 1; pos < len(word); pos++ {
			option := word[pos]
			if strings.IndexByte(table.denied, option) >= 0 {
				return index, false
			}
			if strings.IndexByte(table.flags, option) >= 0 {
				if !visit(option, "", -1) {
					return index, false
				}
				continue
			}
			if strings.IndexByte(table.values, option) < 0 {
				return index, false
			}
			value, at := word[pos+1:], index
			if value == "" {
				if index+1 >= len(args) {
					return index, false
				}
				index++
				value, at = args[index], index
			}
			if !visit(option, value, at) {
				return index, false
			}
			break
		}
	}
	return len(args), true
}

// sshIdentityArguments returns the positions of an ssh, scp or sftp command
// that hold the value of -i or -o IdentityFile. Operands, including
// everything after the first one, are never exempt.
func sshIdentityArguments(table shortOptionTable, args []string) (map[int]bool, bool) {
	used := map[int]bool{}
	first, ok := walkShortOptions(table, args, func(option byte, value string, at int) bool {
		switch option {
		case 'i':
			if literalSSHKeyPath(value) {
				used[at] = true
			}
		case 'o':
			key, setting := splitSSHConfigOption(value)
			if !sshAllowedConfigKeys[key] {
				return false
			}
			if key == "identityfile" && literalSSHKeyPath(setting) {
				used[at] = true
			}
		}
		return true
	})
	if !ok {
		return nil, false
	}
	if table.reparse && first < len(args) {
		// Options after the destination take effect too. Their -i values
		// stay reads; only a setting that cancels the exemption matters.
		if _, ok := walkShortOptions(table, args[first+1:], func(option byte, value string, _ int) bool {
			if option != 'o' {
				return true
			}
			key, _ := splitSSHConfigOption(value)
			return sshAllowedConfigKeys[key]
		}); !ok {
			return nil, false
		}
	}
	return used, true
}

// splitSSHConfigOption splits "Key=value" or "Key value" as ssh -o does: the
// name starts after leading blanks and ends at a blank or "=", ssh drops the
// quotes around it and ignores its case. A name that still holds anything
// else matches no allowed setting.
func splitSSHConfigOption(value string) (string, string) {
	value = strings.TrimLeft(value, " \t")
	key, setting := value, ""
	if end := strings.IndexAny(value, "= \t"); end >= 0 {
		key = value[:end]
		setting = strings.TrimLeft(value[end:], " \t")
		setting = strings.TrimLeft(strings.TrimPrefix(setting, "="), " \t")
	}
	key = strings.ToLower(strings.NewReplacer(`"`, "", "'", "").Replace(key))
	return key, setting
}

// rsyncRemoteShellArgument returns the position of rsync's -e/--rsh value
// when it is an ssh command that only authenticates with a key.
func rsyncRemoteShellArgument(args []string) map[int]bool {
	for index := 0; index < len(args); index++ {
		word := args[index]
		value, at := "", -1
		switch {
		case word == "-e" || word == "--rsh":
			if index+1 >= len(args) {
				return nil
			}
			value, at = args[index+1], index+1
		case strings.HasPrefix(word, "--rsh="):
			value, at = strings.TrimPrefix(word, "--rsh="), index
		case strings.HasPrefix(word, "--"):
			if strings.Contains(word, "=") || rsyncLongFlags[word] {
				continue
			}
			return nil
		case strings.HasPrefix(word, "-") && len(word) > 1:
			for pos := 1; pos < len(word) && at < 0; pos++ {
				switch option := word[pos]; {
				case option == 'e' && pos+1 < len(word):
					value, at = word[pos+1:], index
				case option == 'e' && index+1 < len(args):
					value, at = args[index+1], index+1
				case strings.IndexByte(rsyncShortFlags, option) < 0:
					return nil
				}
			}
			if at < 0 {
				continue
			}
		default:
			return nil // an operand before -e
		}
		if sshKeyOnlyCommand(value) {
			return map[int]bool{at: true}
		}
		return nil
	}
	return nil
}

// sshAddKeyArguments returns the key files ssh-add loads into the agent.
func sshAddKeyArguments(args []string) map[int]bool {
	first, ok := walkShortOptions(sshAddOptions, args, func(byte, string, int) bool { return true })
	if !ok {
		return nil
	}
	used := map[int]bool{}
	for index := first; index < len(args); index++ {
		if strings.HasPrefix(args[index], "-") {
			return nil // an option after a key file, or "-" (stdin)
		}
		if literalSSHKeyPath(args[index]) {
			used[index] = true
		}
	}
	return used
}

// sshKeygenFingerprintArguments returns the -f value of ssh-keygen -l or -y.
func sshKeygenFingerprintArguments(args []string) map[int]bool {
	used := map[int]bool{}
	mode := false
	first, ok := walkShortOptions(sshKeygenFingerprintOptions, args, func(option byte, value string, at int) bool {
		switch option {
		case 'l', 'y':
			mode = true
		case 'f':
			if literalSSHKeyPath(value) {
				used[at] = true
			}
		}
		return true
	})
	if !ok || !mode || first != len(args) {
		return nil
	}
	return used
}

// sshKeyCommandAssignment reports GIT_SSH_COMMAND="ssh -i <key>". A command
// line that names the variable anywhere else could read the key path back
// out of it, so the assignment is then judged as a read like any other.
// mentions is how often the whole raw command names the variable, counted
// once per command line (sshKeyUseContext), never once per word.
func sshKeyCommandAssignment(word string, mentions int) bool {
	const name = "GIT_SSH_COMMAND="
	if mentions != 1 || !strings.HasPrefix(word, name) {
		return false
	}
	return sshKeyOnlyCommand(strings.TrimPrefix(word, name))
}

// sshKeyOnlyCommand reports a remote-shell command made of literal words
// that runs ssh and names a protected file only through -i or -o
// IdentityFile.
func sshKeyOnlyCommand(value string) bool {
	if strings.ContainsAny(value, "'\"`;&|<>(){}\\\n") {
		return false
	}
	tokens := strings.Fields(value)
	if len(tokens) == 0 || filepath.Base(tokens[0]) != "ssh" {
		return false
	}
	used, ok := sshIdentityArguments(sshTransportOptions["ssh"], tokens[1:])
	if !ok {
		return false
	}
	for index, token := range tokens[1:] {
		if used[index] {
			continue
		}
		if strings.ContainsAny(token, "$*?[") {
			return false
		}
		if _, protected := protectedShellWord(token, ""); protected {
			return false
		}
	}
	return true
}

// windowsHomePrefixes name the user's home directory on Windows: cmd's
// %USERPROFILE%, PowerShell's $env:USERPROFILE / ${env:USERPROFILE} / $HOME,
// and ~.
var windowsHomePrefixes = []string{"%USERPROFILE%", "$env:USERPROFILE", "${env:USERPROFILE}", "$HOME", "${HOME}", "~"}

// windowsSSHKeyPath rewrites a Windows key path to the form literalSSHKeyPath
// checks, as ssh -i ~/.ssh/id_rsa is checked on Linux (复核员乙，11-18):
// "%USERPROFILE%\.ssh\id_rsa" and the PowerShell forms become
// "~/.ssh/id_rsa", "C:\Users\dev\.ssh\id_rsa" becomes "C:/Users/dev/.ssh/id_rsa".
// The rest of the path must be literal like on Linux (no further variable,
// glob, quote or blank).
func windowsSSHKeyPath(value string) (string, bool) {
	for _, home := range windowsHomePrefixes {
		rest, ok := strings.CutPrefix(value, home+`\`)
		if !ok {
			if home == "~" || !strings.HasPrefix(value, home+"/") {
				continue
			}
			rest = strings.TrimPrefix(value, home+"/")
		}
		return "~/" + strings.ReplaceAll(rest, `\`, "/"), true
	}
	if len(value) > 3 && value[1] == ':' && (value[2] == '\\' || value[2] == '/') &&
		(value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') {
		return value[:2] + strings.ReplaceAll(value[2:], `\`, "/"), true
	}
	return "", false
}

// literalSSHKeyPath reports a word that names exactly one SSH private key
// file: no glob, quoting, whitespace, substitution, ssh %-token or variable
// other than a leading $HOME, so it cannot expand into further words or into
// another file.
func literalSSHKeyPath(value string) bool {
	path := value
	for _, home := range []string{"$HOME/", "${HOME}/"} {
		if strings.HasPrefix(path, home) {
			path = "~/" + strings.TrimPrefix(path, home)
			break
		}
	}
	if windows, ok := windowsSSHKeyPath(path); ok {
		path = windows
	}
	if path == "" || strings.ContainsAny(path, " \t\r\n'\"`$*?[]{}()<>|;&\\%") {
		return false
	}
	return isSSHPrivateKeyPath(strings.ToLower(normalizeFilePath(path)))
}
