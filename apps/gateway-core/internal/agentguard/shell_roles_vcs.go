package agentguard

import (
	"strings"
)

// gitSubcommand describes how a git subcommand uses its arguments.
type gitSubcommand struct {
	operand   shellArgRole            // role of operands, also after "--"
	values    map[string]shellArgRole // options with a separate value, by "-x" / "--long" name
	denied    map[string]bool         // options that show or edit content interactively
	firstSkip bool                    // the first operand is a pattern (git grep) unless -e/-f is given
}

var (
	gitPatchDenied = flagSet("-p", "--patch", "-i", "--interactive", "-e", "--edit")
	gitReader      = gitSubcommand{operand: shellArgRead, values: map[string]shellArgRole{
		"-n": shellArgSkip, "--max-count": shellArgSkip, "--format": shellArgSkip, "--pretty": shellArgSkip,
		"--grep": shellArgSkip, "--author": shellArgSkip, "--committer": shellArgSkip, "--since": shellArgSkip,
		"--until": shellArgSkip, "--after": shellArgSkip, "--before": shellArgSkip, "-S": shellArgSkip,
		"-G": shellArgSkip, "-U": shellArgSkip, "--unified": shellArgSkip, "-L": shellArgRead,
		"-o": shellArgWrite, "--output": shellArgWrite, "--prefix": shellArgSkip, "--date": shellArgSkip,
		"--skip": shellArgSkip, "--diff-filter": shellArgSkip, "-e": shellArgSkip, "-f": shellArgRead,
		"--format-patch": shellArgSkip, "--abbrev": shellArgSkip,
	}}
	// gitSubcommands lists the subcommands whose arguments are understood.
	// Content readers (show, diff, log ...) read their path operands, and
	// conservatively every other operand too (a rev may name a path). Branch,
	// ref and message arguments of the others are not files.
	gitSubcommands = map[string]gitSubcommand{
		"show": gitReader, "diff": gitReader, "log": gitReader, "blame": gitReader, "annotate": gitReader,
		"cat-file": gitReader, "archive": gitReader, "format-patch": gitReader, "whatchanged": gitReader,
		"difftool": gitReader, "shortlog": gitReader, "ls-tree": gitReader, "range-diff": gitReader,
		"apply": gitReader, "am": gitReader, "hash-object": gitReader,
		"grep": {operand: shellArgRead, values: gitReader.values, firstSkip: true},
		"add":  {operand: shellArgRead, values: map[string]shellArgRole{"--pathspec-from-file": shellArgRead, "--chmod": shellArgSkip}, denied: gitPatchDenied},
		"commit": {operand: shellArgRead, values: map[string]shellArgRole{
			"-m": shellArgSkip, "--message": shellArgSkip, "-F": shellArgRead, "--file": shellArgRead,
			"-t": shellArgRead, "--template": shellArgRead, "-C": shellArgSkip, "-c": shellArgSkip,
			"--reuse-message": shellArgSkip, "--reedit-message": shellArgSkip, "--fixup": shellArgSkip,
			"--squash": shellArgSkip, "--author": shellArgSkip, "--date": shellArgSkip, "--trailer": shellArgSkip,
			"--cleanup": shellArgSkip, "--pathspec-from-file": shellArgRead,
		}, denied: flagSet("-p", "--patch", "--interactive")},
		"checkout": {operand: shellArgWrite, values: map[string]shellArgRole{
			"-b": shellArgSkip, "-B": shellArgSkip, "--orphan": shellArgSkip, "--conflict": shellArgSkip,
			"--pathspec-from-file": shellArgRead,
		}, denied: flagSet("-p", "--patch")},
		"restore": {operand: shellArgWrite, values: map[string]shellArgRole{
			"-s": shellArgSkip, "--source": shellArgSkip, "--pathspec-from-file": shellArgRead,
		}, denied: flagSet("-p", "--patch")},
		"reset": {operand: shellArgWrite, values: map[string]shellArgRole{"--pathspec-from-file": shellArgRead}, denied: flagSet("-p", "--patch")},
		"switch": {operand: shellArgSkip, values: map[string]shellArgRole{
			"-c": shellArgSkip, "-C": shellArgSkip, "--create": shellArgSkip, "--force-create": shellArgSkip, "--orphan": shellArgSkip,
		}},
		"branch": {operand: shellArgSkip, values: map[string]shellArgRole{
			"-u": shellArgSkip, "--set-upstream-to": shellArgSkip, "--contains": shellArgSkip, "--no-contains": shellArgSkip,
			"--merged": shellArgSkip, "--no-merged": shellArgSkip, "--points-at": shellArgSkip, "--format": shellArgSkip,
			"--sort": shellArgSkip,
		}},
		"push": gitRemoteSubcommand, "fetch": gitRemoteSubcommand, "pull": gitRemoteSubcommand,
		"merge": {operand: shellArgSkip, values: map[string]shellArgRole{
			"-m": shellArgSkip, "--message": shellArgSkip, "-F": shellArgRead, "--file": shellArgRead,
			"-s": shellArgSkip, "--strategy": shellArgSkip, "-X": shellArgSkip, "--strategy-option": shellArgSkip,
			"--into-name": shellArgSkip,
		}},
		"rebase": {operand: shellArgSkip, values: map[string]shellArgRole{
			"--onto": shellArgSkip, "-s": shellArgSkip, "--strategy": shellArgSkip, "-X": shellArgSkip,
			"--strategy-option": shellArgSkip, "-x": shellArgRead, "--exec": shellArgRead,
		}},
		"tag": {operand: shellArgSkip, values: map[string]shellArgRole{
			"-m": shellArgSkip, "--message": shellArgSkip, "-F": shellArgRead, "--file": shellArgRead,
			"-u": shellArgSkip, "--local-user": shellArgSkip, "--contains": shellArgSkip, "--points-at": shellArgSkip,
			"--sort": shellArgSkip, "--format": shellArgSkip,
		}},
		"revert":       {operand: shellArgSkip, values: map[string]shellArgRole{"-m": shellArgSkip, "--mainline": shellArgSkip, "-X": shellArgSkip, "--strategy": shellArgSkip}},
		"cherry-pick":  {operand: shellArgSkip, values: map[string]shellArgRole{"-m": shellArgSkip, "--mainline": shellArgSkip, "-X": shellArgSkip, "--strategy": shellArgSkip}},
		"stash":        {operand: shellArgSkip, values: gitStashValues, denied: flagSet("-p", "--patch")},
		"describe":     {operand: shellArgSkip},
		"rev-parse":    {operand: shellArgSkip},
		"status":       {operand: shellArgSkip},
		"ls-files":     {operand: shellArgSkip},
		"rm":           {operand: shellArgSkip, values: map[string]shellArgRole{"--pathspec-from-file": shellArgRead}},
		"mv":           {operand: shellArgRead},
		"check-ignore": {operand: shellArgSkip},
		"remote":       {operand: shellArgSkip},
		"init":         {operand: shellArgSkip, values: map[string]shellArgRole{"--template": shellArgRead, "-b": shellArgSkip, "--initial-branch": shellArgSkip}},
		"config": {operand: shellArgSkip, values: map[string]shellArgRole{
			"-f": shellArgRead, "--file": shellArgRead, "--blob": shellArgSkip, "--type": shellArgSkip,
			"--default": shellArgRead, "--comment": shellArgSkip, "--value": shellArgRead, "--url": shellArgRead,
		}},
		"clone": {operand: shellArgRead, values: map[string]shellArgRole{
			"--template": shellArgRead, "-c": shellArgRead, "--config": shellArgRead, "--reference": shellArgRead,
			"--reference-if-able": shellArgRead, "-u": shellArgRead, "--upload-pack": shellArgRead,
			"--separate-git-dir": shellArgWrite, "-o": shellArgSkip, "--origin": shellArgSkip, "-b": shellArgSkip,
			"--branch": shellArgSkip, "--depth": shellArgSkip, "--shallow-since": shellArgSkip,
			"--shallow-exclude": shellArgSkip, "--filter": shellArgSkip, "-j": shellArgSkip, "--jobs": shellArgSkip,
		}},
		"ls-remote": {operand: shellArgRead, values: map[string]shellArgRole{
			"--upload-pack": shellArgRead, "-o": shellArgSkip, "--server-option": shellArgSkip, "--sort": shellArgSkip,
		}},
		"submodule": {operand: shellArgRead, values: map[string]shellArgRole{
			"-b": shellArgSkip, "--branch": shellArgSkip, "--name": shellArgSkip, "--reference": shellArgRead,
			"--depth": shellArgSkip,
		}},
	}
	gitStashValues = map[string]shellArgRole{"-m": shellArgSkip, "--message": shellArgSkip, "--pathspec-from-file": shellArgRead}
	// gitStashPush: stash push (also "git stash [options] -- paths") stores the
	// content of its path operands, which "stash show -p" prints.
	gitStashPush        = gitSubcommand{operand: shellArgRead, values: gitStashValues, denied: flagSet("-p", "--patch")}
	gitRemoteSubcommand = gitSubcommand{operand: shellArgSkip, values: map[string]shellArgRole{
		"-o": shellArgSkip, "--push-option": shellArgSkip, "--repo": shellArgSkip, "--depth": shellArgSkip,
		"--upload-pack": shellArgRead, "--receive-pack": shellArgRead, "--exec": shellArgRead,
		"-s": shellArgSkip, "--strategy": shellArgSkip, "-X": shellArgSkip, "--strategy-option": shellArgSkip,
	}}
	// gitGlobalValues are git's options before the subcommand that take a
	// value; the values are judged as reads (-C ~/.ssh, -c core.sshCommand=...).
	gitGlobalValues = flagSet("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env")
	gitGlobalFlags  = flagSet("--no-pager", "-P", "-p", "--paginate", "--bare", "--no-replace-objects",
		"--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks",
		"--no-lazy-fetch", "--version", "--help")
)

// git: branch names, refs and commit messages are not files; the paths of
// show/diff/log/blame/cat-file ... (after "--" and in <rev>:<path>) and of
// add/commit are read; checkout/restore/reset paths are written.
func gitRoles(args []string) (shellCommandRoles, bool) {
	roles := newShellCommandRoles()
	index := 0
	for ; index < len(args); index++ {
		word := args[index]
		name, _, attached := strings.Cut(word, "=")
		switch {
		case gitGlobalValues[name] && attached:
		case gitGlobalValues[word]:
			if index+1 >= len(args) {
				return shellCommandRoles{}, false
			}
			roles.roles[index] = shellArgSkip
			index++
		case gitGlobalFlags[word]:
			roles.roles[index] = shellArgSkip
		case strings.HasPrefix(word, "-"):
			return shellCommandRoles{}, false
		default:
			goto subcommand
		}
	}
	return roles, true
subcommand:
	spec, ok := gitSubcommands[strings.ToLower(args[index])]
	if !ok {
		return shellCommandRoles{}, false
	}
	roles.roles[index] = shellArgSkip
	subcommand := strings.ToLower(args[index])
	if subcommand == "submodule" {
		// Only "submodule add URL [path]" is understood; foreach runs commands.
		add := firstOperandIndex(args[index+1:])
		if add < 0 || args[index+1+add] != "add" {
			return shellCommandRoles{}, false
		}
		index += 1 + add
		roles.roles[index] = shellArgSkip
	}
	if strings.EqualFold(args[index], "stash") {
		// The stash action is its first operand; none (only options or "--")
		// means push.
		action, actionAt := "", -1
		for at := index + 1; at < len(args); at++ {
			word := args[at]
			if word == "--" {
				break
			}
			if word == "-m" || word == "--message" || word == "--pathspec-from-file" {
				at++
				continue
			}
			if !strings.HasPrefix(word, "-") {
				action, actionAt = strings.ToLower(word), at
				break
			}
		}
		switch action {
		case "show":
			spec = gitReader
		case "push", "":
			spec = gitStashPush
			if actionAt >= 0 {
				roles.roles[actionAt] = shellArgSkip
				index = actionAt
			}
		}
	}
	var operands []int
	patternGiven := false
	for at := index + 1; at < len(args); at++ {
		word := args[at]
		switch {
		case word == "--":
			roles.roles[at] = shellArgSkip
			for rest := at + 1; rest < len(args); rest++ {
				roles.roles[rest] = spec.operand
			}
			at = len(args)
		case spec.denied[word]:
			return shellCommandRoles{}, false
		case strings.HasPrefix(word, "--"):
			name, _, attached := strings.Cut(word, "=")
			if spec.denied[name] {
				return shellCommandRoles{}, false
			}
			role, takesValue := spec.values[name]
			patternGiven = patternGiven || name == "--regexp" || name == "--file"
			printedFormat := name == "--format" || name == "--pretty"
			switch {
			case takesValue && attached:
				roles.roles[at], roles.offsets[at] = role, len(name)+1
				if printedFormat {
					roles.markPrinted(at)
				}
			case takesValue:
				if at+1 >= len(args) {
					return shellCommandRoles{}, false
				}
				roles.roles[at], roles.roles[at+1] = shellArgSkip, role
				at++
				if printedFormat {
					roles.markPrinted(at)
				}
			case attached:
				// An unknown option with an attached value: judged as a read.
			default:
				roles.roles[at] = shellArgSkip
			}
		case len(word) > 1 && word[0] == '-':
			roles.roles[at] = shellArgSkip
			for pos := 1; pos < len(word); pos++ {
				name := "-" + string(word[pos])
				if spec.denied[name] {
					return shellCommandRoles{}, false
				}
				role, takesValue := spec.values[name]
				if !takesValue {
					continue
				}
				patternGiven = patternGiven || name == "-e" || name == "-f"
				if pos+1 < len(word) {
					roles.roles[at], roles.offsets[at] = role, pos+1
				} else if at+1 < len(args) {
					at++
					roles.roles[at] = role
				} else {
					return shellCommandRoles{}, false
				}
				break
			}
		default:
			operands = append(operands, at)
		}
	}
	if spec.firstSkip && !patternGiven && len(operands) > 0 {
		roles.roles[operands[0]] = shellArgSkip
		operands = operands[1:]
	}
	for _, at := range operands {
		roles.roles[at] = spec.operand
	}
	if subcommand == "config" && !gitConfigRoles(args, operands, roles.roles) {
		return shellCommandRoles{}, false
	}
	if gitURLSubcommands[subcommand] {
		// The repository may be a remote URL (or user@host:path): not a file.
		// clone and submodule add write the directory after it.
		for position, at := range operands {
			switch {
			case looksLikeRemoteURL(args[at]) || scpRemote.MatchString(args[at]):
				roles.roles[at] = shellArgSkip
			case position == 1 && (subcommand == "clone" || subcommand == "submodule"):
				roles.roles[at] = shellArgWrite
			case looksLikeLocalRepository(args[at]):
				// fetch/pull/push/remote add 的仓库写成本地路径：git 会读它。
				roles.roles[at] = shellArgRead
			}
		}
	}
	return roles, true
}

// gitURLSubcommands take a repository URL as an operand.
var gitURLSubcommands = flagSet("clone", "fetch", "pull", "push", "ls-remote", "remote", "submodule")

// kubectl options with a value, and the value's role. Every other value is a
// name, selector, template or setting, not a local file.
var kubectlValueOptions = map[string]shellArgRole{
	"-f": shellArgRead, "--filename": shellArgRead, "-k": shellArgRead, "--kustomize": shellArgRead,
	"--from-file": shellArgRead, "--from-env-file": shellArgRead, "--patch-file": shellArgRead,
	"--client-key": shellArgRead, "--client-certificate": shellArgRead, "--certificate-authority": shellArgRead,
	"--cert": shellArgRead, "--key": shellArgRead, "--custom": shellArgRead, "--www": shellArgRead,
	"--kubeconfig": shellArgUseKubeconfig, "--log-file": shellArgWrite, "--raw": shellArgSkip,
	"-n": shellArgSkip, "--namespace": shellArgSkip, "-o": shellArgSkip, "--output": shellArgSkip,
	"-l": shellArgSkip, "--selector": shellArgSkip, "--field-selector": shellArgSkip, "--context": shellArgSkip,
	"--cluster": shellArgSkip, "--user": shellArgSkip, "--as": shellArgSkip, "--as-group": shellArgSkip,
	"--as-uid": shellArgSkip, "-s": shellArgSkip, "--server": shellArgSkip, "--token": shellArgSkip,
	"--username": shellArgSkip, "--password": shellArgSkip, "--tls-server-name": shellArgSkip,
	"-c": shellArgSkip, "--container": shellArgSkip, "--tail": shellArgSkip, "--since": shellArgSkip,
	"--since-time": shellArgSkip, "--sort-by": shellArgSkip, "--template": shellArgSkip, "--type": shellArgSkip,
	"-p": shellArgSkip, "--patch": shellArgSkip, "--replicas": shellArgSkip, "--timeout": shellArgSkip,
	"--image": shellArgSkip, "--port": shellArgSkip, "--request-timeout": shellArgSkip, "--chunk-size": shellArgSkip,
	"-L": shellArgSkip, "--label-columns": shellArgSkip, "--limit-bytes": shellArgSkip,
	"--max-log-requests": shellArgSkip, "--pod-running-timeout": shellArgSkip, "--grace-period": shellArgSkip,
	"--cascade": shellArgSkip, "--overrides": shellArgSkip, "--env": shellArgSkip, "--labels": shellArgSkip,
	"--restart": shellArgSkip, "--field-manager": shellArgSkip, "--for": shellArgSkip,
	"--resource-version": shellArgSkip, "--from-literal": shellArgSkip, "--schedule": shellArgSkip,
	"--target-port": shellArgSkip, "--name": shellArgSkip, "--serviceaccount": shellArgSkip, "--min": shellArgSkip,
	"--max": shellArgSkip, "--cpu-percent": shellArgSkip, "--current-replicas": shellArgSkip,
	"--revision": shellArgSkip, "--to-revision": shellArgSkip, "-v": shellArgSkip, "--v": shellArgSkip,
	"--subresource": shellArgSkip, "--profile": shellArgSkip, "--address": shellArgSkip,
	"--cache-dir": shellArgSkip, "--image-pull-policy": shellArgSkip, "--attach": shellArgSkip,
	"--docker-server": shellArgSkip, "--docker-username": shellArgSkip, "--docker-password": shellArgSkip,
	"--docker-email": shellArgSkip, "--duration": shellArgSkip, "--audience": shellArgSkip,
	"--selector-columns": shellArgSkip, "--show-kind": shellArgSkip, "--filter": shellArgSkip,
	"--target": shellArgSkip, "--copy-to": shellArgSkip, "--namespace-selector": shellArgSkip,
}

var kubectlFlags = flagSet("-A", "--all-namespaces", "-w", "--watch", "--watch-only", "-i", "--stdin", "-t",
	"--tty", "-q", "--quiet", "-R", "--recursive", "--show-labels", "--no-headers", "--all", "--force", "--wait",
	"--ignore-not-found", "--previous", "--insecure-skip-tls-verify", "--local", "--overwrite", "--record",
	"--save-config", "--server-side", "--force-conflicts", "--prune", "--rm", "--follow", "--timestamps",
	"--prefix", "--ignore-errors", "--minify", "--flatten", "--raw", "--dry-run", "--validate", "--help", "-h",
	"--show-managed-fields", "--keep-annotations", "--append-hash", "--list", "--allow-missing-template-keys",
	"--include-uninitialized", "--current", "--client", "--short", "--reverse", "--chunk")

// kubectlSubcommands are understood; anything else (plugins) falls back.
var kubectlSubcommands = flagSet("get", "describe", "logs", "exec", "cp", "apply", "create", "delete", "edit",
	"patch", "replace", "rollout", "scale", "autoscale", "label", "annotate", "expose", "run", "set", "top",
	"explain", "api-resources", "api-versions", "cluster-info", "config", "auth", "port-forward", "proxy",
	"attach", "debug", "wait", "diff", "kustomize", "version", "events", "cordon", "uncordon", "drain", "taint",
	"certificate", "completion", "options")

// kubectlSubcommandOf returns kubectl's subcommand after its global options.
func kubectlSubcommandOf(args []string) string {
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			return ""
		case strings.HasPrefix(word, "-"):
			name, _, attached := strings.Cut(word, "=")
			if _, ok := kubectlValueOptions[name]; ok && !attached && len(name) == len(word) && !kubectlFlagsFor("", name) {
				index++
			}
		default:
			return word
		}
	}
	return ""
}

// kubectl: resource names, -o templates, selectors and namespaces are not
// files; -f/-k/--from-file are read, --kubeconfig is used, cp and kustomize
// operands are local paths, and the command after "--" (exec, debug, run) is
// judged as its own command.
func kubectlRoles(args []string) (shellCommandRoles, bool) {
	subcommand := ""
	for index := 0; index < len(args) && subcommand == ""; index++ {
		word := args[index]
		switch {
		case word == "--":
			index = len(args)
		case strings.HasPrefix(word, "-"):
			name, _, attached := strings.Cut(word, "=")
			if _, ok := kubectlValueOptions[name]; ok && !attached && len(name) == len(word) && !kubectlFlagsFor("", name) {
				index++
			}
		default:
			subcommand = word
		}
	}
	if subcommand != "" && !kubectlSubcommands[subcommand] {
		return shellCommandRoles{}, false
	}
	roles := newShellCommandRoles()
	var operands []int
	// outputs / templates: where the -o and --template values sit.
	type optionValue struct{ at, offset int }
	var outputs, templates []optionValue
	noteValue := func(name string, at, offset int) {
		switch name {
		case "-o", "--output":
			outputs = append(outputs, optionValue{at, offset})
		case "--template":
			templates = append(templates, optionValue{at, offset})
		}
	}
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			roles.roles[index] = shellArgSkip
			if index+1 < len(args) {
				for at := index + 1; at < len(args); at++ {
					roles.roles[at] = shellArgSkip
				}
				roles.nested = append(roles.nested, shellNested{at: index + 1, argv: args[index+1:]})
				for at := index + 2; at < len(args); at++ {
					roles.nested = append(roles.nested, shellNested{at: at})
				}
			}
			index = len(args)
		case strings.HasPrefix(word, "--"):
			name, _, attached := strings.Cut(word, "=")
			role, takesValue := kubectlValueOptions[name]
			switch {
			case kubectlFlagsFor(subcommand, name):
				roles.roles[index] = shellArgSkip
			case takesValue && attached:
				roles.roles[index], roles.offsets[index] = role, len(name)+1
				noteValue(name, index, len(name)+1)
			case takesValue:
				if index+1 >= len(args) {
					return shellCommandRoles{}, false
				}
				roles.roles[index], roles.roles[index+1] = shellArgSkip, role
				index++
				noteValue(name, index, 0)
			default:
				return shellCommandRoles{}, false
			}
		case len(word) > 1 && word[0] == '-':
			roles.roles[index] = shellArgSkip
			for pos := 1; pos < len(word); pos++ {
				name := "-" + string(word[pos])
				if kubectlFlagsFor(subcommand, name) {
					continue
				}
				role, takesValue := kubectlValueOptions[name]
				if !takesValue {
					return shellCommandRoles{}, false
				}
				if pos+1 < len(word) {
					roles.roles[index], roles.offsets[index] = role, pos+1
					if word[pos+1] == '=' {
						roles.offsets[index] = pos + 2
					}
					noteValue(name, index, roles.offsets[index])
				} else if index+1 < len(args) {
					index++
					roles.roles[index] = role
					noteValue(name, index, 0)
				} else {
					return shellCommandRoles{}, false
				}
				break
			}
		default:
			operands = append(operands, index)
		}
	}
	// -o go-template-file=PATH (templatefile, jsonpath-file, custom-columns-file)
	// reads a local template file; without "=PATH" the file is the --template
	// value. jsonpath=, custom-columns=, go-template= carry the template text.
	for _, output := range outputs {
		roles.markPrinted(output.at)
	}
	for _, template := range templates {
		roles.markPrinted(template.at)
	}
	templateFile := false
	for _, output := range outputs {
		format, _, hasFile := strings.Cut(args[output.at][output.offset:], "=")
		if !kubectlTemplateFileFormats[format] {
			continue
		}
		if !hasFile {
			templateFile = true
			continue
		}
		roles.roles[output.at], roles.offsets[output.at] = shellArgRead, output.offset+len(format)+1
	}
	if templateFile {
		for _, template := range templates {
			roles.roles[template.at] = shellArgRead
		}
	}
	operandRole := shellArgSkip
	switch subcommand {
	case "cp", "kustomize":
		operandRole = shellArgRead
	}
	for position, at := range operands {
		roles.roles[at] = operandRole
		if subcommand == "exec" && position == 2 {
			// Old form "kubectl exec POD CMD ...": the command runs in the pod.
			roles.nested = append(roles.nested, shellNested{at: at, argv: args[at:]})
			for rest := at + 1; rest < len(args); rest++ {
				roles.nested = append(roles.nested, shellNested{at: rest})
			}
			break
		}
	}
	return roles, true
}

// kubectlTemplateFileFormats are the -o formats whose template is a file.
var kubectlTemplateFileFormats = flagSet("go-template-file", "templatefile", "jsonpath-file", "custom-columns-file")

// kubectlFlagsFor reports an option that takes no value for this
// subcommand: logs/attach -f and -p are --follow and --previous, config
// view --raw prints the raw kubeconfig, get --raw takes a URI path.
func kubectlFlagsFor(subcommand, name string) bool {
	switch {
	case (subcommand == "logs" || subcommand == "attach") && (name == "-f" || name == "-p"):
		return true
	case name == "--raw" && subcommand != "config":
		return false
	}
	return kubectlFlags[name]
}

// gitConfigActions are the subcommands of "git config <action> ..." (git 2.46+).
var gitConfigActions = flagSet("get", "set", "unset", "list", "rename-section", "remove-section", "edit",
	"get-color", "get-colorbool")

// gitConfigCommandKeySuffixes: a key whose last segment is one of these
// (core.fsmonitor, core.sshCommand, core.pager, core.editor, sequence.editor,
// diff.external, credential.helper, gpg.program, filter.x.clean,
// mergetool.x.cmd, diff.x.textconv, include.path, url.x.insteadOf,
// protocol.ext.allow ...) runs a command, names a file git reads as
// configuration or a program, or rewrites a URL into one that runs a command.
var gitConfigCommandKeySuffixes = flagSet("fsmonitor", "sshcommand", "pager", "editor", "askpass", "gitproxy",
	"hookspath", "external", "helper", "program", "cmd", "command", "textconv", "driver", "clean", "smudge",
	"process", "packobjectshook", "uploadpack", "receivepack", "path", "tocmd", "cccmd", "sendmailcmd",
	"smtpserver", "insteadof", "pushinsteadof", "alternaterefscommand", "allow", "proxy")

// gitConfigRoles: the key of git config is not a file, its value operands
// (values, value patterns) are read. A key that runs a command (see
// gitConfigCommandKeySuffixes, pager.<cmd>, include / includeIf, an alias
// whose value starts with "!") returns false: the whole command is judged
// word by word.
func gitConfigRoles(args []string, operands []int, roles map[int]shellArgRole) bool {
	if len(operands) > 0 && gitConfigActions[strings.ToLower(args[operands[0]])] {
		roles[operands[0]] = shellArgSkip
		operands = operands[1:]
	}
	if len(operands) == 0 {
		return true
	}
	key := strings.ToLower(args[operands[0]])
	segments := strings.Split(key, ".")
	switch {
	case gitConfigCommandKeySuffixes[segments[len(segments)-1]],
		segments[0] == "pager", segments[0] == "include", segments[0] == "includeif":
		return false
	case segments[0] == "alias":
		for _, at := range operands[1:] {
			if strings.HasPrefix(strings.TrimSpace(args[at]), "!") {
				return false
			}
		}
	}
	roles[operands[0]] = shellArgSkip
	for _, at := range operands[1:] {
		roles[at] = shellArgRead
	}
	return true
}
