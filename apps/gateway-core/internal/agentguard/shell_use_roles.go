package agentguard

import "strings"

// “使用”角色的程序白名单（复核员乙 M1、M2，11-18）：--kubeconfig、KUBECONFIG= 只有 kube 客户端
// 拿来认证时算使用；--env-file 只有把文件加载成进程环境的“程序 + 子命令”算使用。其余一律按读判。

// kubeClientPrograms authenticate with a kubeconfig and never print it
// (config view --raw is found separately).
var kubeClientPrograms = flagSet("kubectl", "oc", "helm", "kubecolor", "k9s", "kustomize", "kubens", "kubectx",
	"stern", "kubeseal", "flux", "istioctl", "velero", "microk8s.kubectl")

// isKubeClient: a kube client, also "k3s / k0s / microk8s kubectl ...".
func isKubeClient(program string, args []string) bool {
	if kubeClientPrograms[program] {
		return true
	}
	_, ok := kubectlLikeArgs(program, args)
	return ok
}

// kubeconfigNeutralPrograms neither run code nor open a file named by an
// environment variable: on a line of kube clients they leave KUBECONFIG to
// the clients.
var kubeconfigNeutralPrograms = flagSet("export", "cd", "pushd", "popd", "echo", "printf", "true", "false", "sleep",
	"grep", "egrep", "fgrep", "rg", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "column", "cat", "ls",
	"jq", "yq", "date", "mkdir", "test", "[", "unset")

// kubeconfigWrappers may run a kube client without reading KUBECONFIG
// themselves (env is not one: it prints the environment or runs anything).
var kubeconfigWrappers = flagSet("sudo", "time", "timeout", "nice", "nohup", "command")

// kubeconfigVariableUse reports whether KUBECONFIG set on this line (a
// prefix assignment or export) is only read by kube clients: some command is
// a kube client, every other one is neutral, nothing runs behind env, and
// no line-wide switch is on (an unsafe pipe, a process substitution,
// source, a function or alias).
func kubeconfigVariableUse(commands []shellSimpleCommand, switches lineSwitches) bool {
	if switches.wholeWords || switches.voidUseAll {
		return false
	}
	client := false
	for _, simple := range commands {
		start := commandStart(simple.Words)
		for _, word := range simple.Words[:start] {
			if !isShellAssignment(word) && !shellKeywords[word] && !kubeconfigWrappers[strings.ToLower(word)] {
				return false
			}
		}
		program, args := trustedProgramAt(simple.Words, start), simple.Words[min(start+1, len(simple.Words)):]
		switch {
		case start >= len(simple.Words):
		case isKubeClient(program, args):
			client = true
		case !kubeconfigNeutralPrograms[program]:
			return false
		}
	}
	return client
}

// composeValueOptions are docker compose's global options with a value.
var composeValueOptions = flagSet("-f", "--file", "-p", "--project-name", "--env-file", "--profile",
	"--project-directory", "--ansi", "--parallel", "--progress")

// composeEnvFileSubcommands load --env-file into the services they run;
// config and convert print the interpolated values instead.
var composeEnvFileSubcommands = flagSet("up", "create", "start", "restart", "run", "build", "pull", "push", "down",
	"stop", "ps", "logs", "exec", "kill", "rm", "pause", "unpause", "top", "wait", "watch", "images", "port",
	"scale", "attach", "cp", "events", "ls", "version")

// composeSubcommand returns the subcommand after compose's global options.
func composeSubcommand(args []string) string {
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case composeValueOptions[word]:
			index++
		case strings.HasPrefix(word, "-"):
		default:
			return word
		}
	}
	return ""
}

// envFileUseLimit returns how many leading arguments may hold an --env-file
// the program loads into the environment of what it runs: docker / podman /
// nerdctl run, create (also container run/create) and compose with a
// subcommand that runs services; docker-compose / podman-compose likewise;
// node, deno run/serve/test/task and bun before the script, unless inline
// code (-e, -p, --eval, --print) runs instead. 0: none.
func envFileUseLimit(program string, args []string) int {
	switch program {
	case "docker", "podman", "nerdctl":
		sub := firstOperandIndex(args)
		if sub < 0 {
			return 0
		}
		rest := args[sub+1:]
		switch args[sub] {
		case "run", "create":
			return len(args)
		case "container":
			if next := firstOperandIndex(rest); next >= 0 && (rest[next] == "run" || rest[next] == "create") {
				return len(args)
			}
		case "compose":
			if composeEnvFileSubcommands[composeSubcommand(rest)] {
				return len(args)
			}
		}
	case "docker-compose", "podman-compose":
		if composeEnvFileSubcommands[composeSubcommand(args)] {
			return len(args)
		}
	case "node", "nodejs", "bun":
		script := operandAfterOptions(args, runtimeValueOptions)
		if program == "bun" && script >= 0 && args[script] == "run" {
			next := operandAfterOptions(args[script+1:], runtimeValueOptions)
			if next < 0 {
				return 0
			}
			script += 1 + next
		}
		if script < 0 {
			return 0
		}
		for _, word := range args[:script] {
			name, _, _ := strings.Cut(word, "=")
			switch name {
			case "-e", "-p", "--eval", "--print", "-i", "--interactive":
				return 0
			}
		}
		return script
	case "deno":
		sub := firstOperandIndex(args)
		if sub < 0 {
			return 0
		}
		switch args[sub] {
		case "run", "serve", "test", "task":
			if script := operandAfterOptions(args[sub+1:], runtimeValueOptions); script >= 0 {
				return sub + 1 + script
			}
		}
	}
	return 0
}

// runtimeValueOptions are node / bun / deno options with a separate value.
var runtimeValueOptions = flagSet("--env-file", "--env-file-if-exists", "-r", "--require", "--preload", "--import",
	"--loader", "--experimental-loader", "-C", "--conditions", "--title", "--cwd", "-c", "--config")

// operandAfterOptions returns the index of the first operand, skipping the
// values of the listed options, or -1.
func operandAfterOptions(args []string, valueOptions map[string]bool) int {
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			if index+1 < len(args) {
				return index + 1
			}
			return -1
		case valueOptions[word]:
			index++
		case strings.HasPrefix(word, "-"):
		default:
			return index
		}
	}
	return -1
}
