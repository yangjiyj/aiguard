package agentguard

import (
	"path"
	"regexp"
	"strings"
)

// 写入目标敏感度：重定向目标的分级只有这一处定义。
//
// 总原则：相对路径目标的真实目录在静态分析里永远不可完全确定（Claude Code 的 Bash 跨调用保留
// cwd，且不传工作目录），所以
//   - 绝对路径、~ 锚定的目标按目录表定级；
//   - 相对路径目标一律再按“敏感文件名/路径片段表”定级，不依赖 cd 是否可解析；
//     能解析出的 cd 目标与 WorkingDirectory 只是额外拼接，取最高；
//   - 无法证明安全的动态目标（命令替换、位置参数、运行时赋值的变量、通配符等）走兜底。
//
// 匹配前统一转小写（macOS 文件系统不区分大小写）并规范化路径。
//
// 已知局限（静态分析无法覆盖）：
//   - 跨调用保留的 cwd：上一次 Bash 调用里的 cd 对本次调用不可见，只能靠文件名表兜住；
//   - 跨调用保留的 cwd 下，系统文件名表只对不带目录的文件名生效：cron.d/job、sudoers.d/x 这类
//     带目录的相对写法，追加不报，覆盖只有 medium；
//   - 外部变量作命令名时信任外部环境（$c 实际可能是 eval、cd，不会被当成未知赋值）；
//   - 脚本里有 eval、source 时，~ 仍按家目录判定（HOME 可能已被改写）；
//   - $SHELL -c、"$BASH" -c 这类变量作 shell 名的嵌套脚本不解析（sudo sh -c、env X=… bash -c 已解析）；
//   - cd、赋值按脚本整体取全集，不区分先后、函数和子 shell 作用域，结果偏保守；
//   - 变量值来自外部环境、命令输出、文件内容的路径无法求值；
//   - tee、cp、install、sed -i 的写入目标复用本表，但只报敏感目标；它们的相对目标不与脚本里的 cd 目标拼接；
//   - nohup、time、nice、exec 等其它包装命令后面的写入不识别（sudo、env 已识别）；
//   - 花括号展开形成的命令词、cd 的外部变量、通配符、ANSI-C 引号、eval 和 CDPATH 无法求出真实目录；
//   - 词法兜底（cmd、PowerShell）的 cd 目标里的环境变量不展开；
//   - /dev/sg* 等其它设备按普通文件处理（覆盖写 medium）；dd of=\\.\PhysicalDrive 未检查。
var (
	writeTargetCriticalDirs = []string{"/etc", "/private/etc", "/boot", "/usr", "/var/log/audit", "/lib/systemd"}
	// 不看所在目录，路径里出现该片段即命中。
	writeTargetCriticalSegments = []string{"/windows/system32", "/library/launchdaemons"}
	writeTargetHighDirs         = []string{"/root", "/var/spool/cron", "/proc/sysrq-trigger", "/sys"}
	writeTargetHighSegments     = []string{
		"/.ssh", "/.git/hooks", "/.git/config", "/.config/git/config", "/.config/autostart", "/library/launchagents",
		"/.config/systemd", "/.bashrc.d", "/.config/environment.d",
	}
	// 不看所在目录的敏感文件名。
	writeTargetHighFiles = map[string]struct{}{
		"authorized_keys": {}, "authorized_keys2": {}, "sudoers": {}, "crontab": {},
		".bashrc": {}, ".bash_profile": {}, ".bash_login": {}, ".bash_logout": {}, ".profile": {},
		".zshrc": {}, ".zshenv": {}, ".zprofile": {}, ".zlogin": {}, ".zlogout": {},
		".gitconfig": {}, "microsoft.powershell_profile.ps1": {}, "profile.ps1": {},
	}
	// 相对路径目标的系统敏感文件名：目录不可确定时，basename 命中即按 high 处理。
	writeTargetSystemFiles = map[string]struct{}{
		"hosts": {}, "passwd": {}, "shadow": {}, "gshadow": {}, "group": {}, "sudoers": {},
		"ld.so.preload": {}, "ld.so.conf": {}, "rc.local": {}, "environment": {}, "resolv.conf": {},
		"fstab": {}, "profile": {}, "crontab": {}, "authorized_keys": {}, "authorized_keys2": {},
	}
	writeTargetTempDirs = []string{"/tmp", "/var/tmp", "/private/tmp"}
	// /dev 下会改写磁盘或内存内容的设备前缀；/dev/tcp、/dev/udp 是 shell 的网络伪设备。
	writeTargetBlockDevicePrefixes = []string{
		"sd", "hd", "vd", "xvd", "nvme", "mmcblk", "dm-", "md", "loop", "mapper/", "disk", "rdisk",
	}
	writeTargetBlockDeviceNames = map[string]struct{}{"mem": {}, "kmem": {}, "port": {}}
	// /dev 下不改写任何内容的设备：空设备、标准流、终端、/dev/fd、/dev/shm 等。
	writeTargetHarmlessDevices = map[string]struct{}{
		"/dev/null": {}, "/dev/zero": {}, "/dev/full": {}, "/dev/random": {}, "/dev/urandom": {},
		"/dev/stdin": {}, "/dev/stdout": {}, "/dev/stderr": {}, "/dev/tty": {}, "/dev/console": {},
	}
	writeTargetHarmlessDeviceDirs = []string{"/dev/fd", "/dev/shm", "/dev/pts", "/dev/tcp", "/dev/udp"}

	// 动态目标里的变量引用：$NAME、${...}、$(...)、%NAME%、$$ 等特殊参数。
	writeTargetVariableRef = regexp.MustCompile("\\$\\{[^}]*\\}|\\$\\([^)]*\\)|\\$[A-Za-z_][A-Za-z0-9_]*|\\$[0-9@*#?!$-]|%[A-Za-z_][A-Za-z0-9_ ]*%|`[^`]*`")
	writeTargetPercentVar  = regexp.MustCompile("%[A-Za-z_][A-Za-z0-9_ ]*%")
	// /proc/<pid>/root 是目标进程根文件系统的入口，去掉后按真实路径查表。
	writeTargetProcRoot = regexp.MustCompile("^/proc/(?:[0-9]+|self|thread-self)/root(?:/|$)")
	// \\.\C: 这类裸卷设备路径（规范化后为 /./c:）。
	writeTargetBareVolume = regexp.MustCompile("^/{1,2}\\./[a-z]:/?$")
)

const maxWriteTargetBases = 64

type writeTargetClass struct {
	Level       string
	Subcategory string
	// Exempt 表示目标是空设备、标准流、临时目录等，覆盖写和追加写都不报。
	Exempt bool
}

// normalizeTildeDir 把 ~+/ 当作 ./，~-/ 当作 $OLDPWD（都按相对路径处理）。
func normalizeTildeDir(value string) string {
	for _, prefix := range []string{"~+", "~-"} {
		if value == prefix {
			return "."
		}
		if strings.HasPrefix(value, prefix+"/") {
			return "." + value[2:]
		}
	}
	return value
}

func blockDeviceName(name string) bool {
	if _, ok := writeTargetBlockDeviceNames[name]; ok {
		return true
	}
	for _, prefix := range writeTargetBlockDevicePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// classifyWriteTarget 判断写入目标是否敏感，返回空 Level 表示不敏感。
// contains 为 true 时用于动态目标的字面片段：根目录类条目只在片段开头匹配，
// 路径片段类（.ssh/、.git/hooks/ 等）和文件名在任意位置匹配。
func classifyWriteTarget(target string, contains bool) writeTargetClass {
	value := strings.ToLower(strings.ReplaceAll(strings.Trim(strings.TrimSpace(target), `"'`), "\\", "/"))
	if value == "" {
		return writeTargetClass{}
	}
	if strings.Contains(value, "/./physicaldrive") || writeTargetBareVolume.MatchString(value) {
		return writeTargetClass{Level: "critical", Subcategory: "block_device_destroy"} // \\.\PhysicalDrive0
	}
	if len(value) >= 2 && value[1] == ':' && value[0] >= 'a' && value[0] <= 'z' {
		value = value[2:] // 盘符：c:/windows/... 按 /windows/... 匹配
	}
	value = normalizeTildeDir(value)
	switch {
	case value == "~":
		value = "/~home"
	case strings.HasPrefix(value, "~/"):
		value = "/~home/" + value[2:]
	case strings.HasPrefix(value, "$home/"):
		value = "/~home/" + value[6:]
	}
	cleaned := path.Clean(value)
	if !path.IsAbs(cleaned) && (cleaned == ".." || strings.HasPrefix(cleaned, "../")) {
		// 相对路径逃出当前目录：剥掉前导 ../ 后按绝对路径再查一次敏感表。
		for cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			cleaned = strings.TrimPrefix(strings.TrimPrefix(cleaned, ".."), "/")
		}
		cleaned = path.Clean("/" + cleaned)
	}
	if loc := writeTargetProcRoot.FindStringIndex(cleaned); loc != nil {
		cleaned = path.Clean("/" + cleaned[loc[1]:])
	}
	abs := path.IsAbs(cleaned)
	if abs {
		if cleaned == "/dev" || strings.HasPrefix(cleaned, "/dev/") {
			if _, harmless := writeTargetHarmlessDevices[cleaned]; harmless || pathUnder(cleaned, writeTargetHarmlessDeviceDirs...) {
				return writeTargetClass{Exempt: true}
			}
			if blockDeviceName(strings.TrimPrefix(cleaned, "/dev/")) {
				return writeTargetClass{Level: "critical", Subcategory: "block_device_destroy"}
			}
			return writeTargetClass{} // 其它设备：覆盖写按普通文件，追加不报
		}
		if !contains && pathUnder(cleaned, writeTargetTempDirs...) {
			return writeTargetClass{Exempt: true}
		}
	}
	padded := "/" + strings.TrimPrefix(cleaned, "/") + "/"
	underDir := func(dir string) bool {
		if contains {
			return strings.HasPrefix(padded, dir+"/")
		}
		return abs && pathUnder(cleaned, dir)
	}
	for _, dir := range writeTargetCriticalDirs {
		if underDir(dir) {
			return writeTargetClass{Level: "critical"}
		}
	}
	for _, segment := range writeTargetCriticalSegments {
		if strings.Contains(padded, segment+"/") {
			return writeTargetClass{Level: "critical"}
		}
	}
	for _, dir := range writeTargetHighDirs {
		if underDir(dir) {
			return writeTargetClass{Level: "high"}
		}
	}
	for _, segment := range writeTargetHighSegments {
		if strings.Contains(padded, segment+"/") {
			return writeTargetClass{Level: "high"}
		}
	}
	base := path.Base(cleaned)
	if _, ok := writeTargetHighFiles[base]; ok {
		return writeTargetClass{Level: "high"}
	}
	if base == "config.fish" && path.Base(path.Dir(cleaned)) == "fish" {
		return writeTargetClass{Level: "high"}
	}
	return writeTargetClass{}
}

// dynamicWriteTarget 判断目标是否还含未展开的变量引用。
func dynamicWriteTarget(target string) bool {
	return strings.Contains(target, "$") || writeTargetPercentVar.MatchString(target)
}

// classifyDynamicWriteTarget 对含变量引用的目标取变量以外的字面片段，逐段用同一张表做包含匹配。
func classifyDynamicWriteTarget(target string) writeTargetClass {
	if strings.Contains(strings.ToLower(target), "$profile") {
		return writeTargetClass{Level: "high"} // PowerShell 配置文件变量
	}
	best := writeTargetClass{}
	for _, fragment := range writeTargetVariableRef.Split(target, -1) {
		if strings.TrimSpace(fragment) == "" {
			continue
		}
		class := classifyWriteTarget(fragment, true)
		if destructiveRiskRank(class.Level) > destructiveRiskRank(best.Level) {
			best = class
		}
	}
	return best
}

// writeTargetRisk 按写入目标的敏感度给重定向定级。keep 为 false 表示不报：
// 空设备、标准流、临时目录，以及对普通文件的追加写。
// 级别只影响告警分级，处置由策略决定。
func writeTargetRisk(target string, appendMode bool) (risk, subcategory string, keep bool) {
	target = normalizeTildeDir(strings.Trim(strings.TrimSpace(target), `"'`))
	value := strings.ToLower(target)
	if value == "nul" || value == "$null" {
		return "", "", false
	}
	if dynamicWriteTarget(target) {
		if cut := strings.IndexAny(value, "$%"); cut > 0 {
			prefix := strings.ReplaceAll(value[:cut], "\\", "/")
			if path.IsAbs(prefix) && !strings.Contains(value, "..") &&
				pathUnder(path.Clean(prefix), writeTargetTempDirs...) {
				return "", "", false
			}
		}
		class := classifyDynamicWriteTarget(target)
		if class.Level != "" {
			return class.Level, class.Subcategory, true
		}
	} else {
		class := classifyWriteTarget(target, false)
		if class.Exempt {
			return "", "", false
		}
		if class.Level != "" {
			return class.Level, class.Subcategory, true
		}
	}
	if appendMode {
		return "", "", false
	}
	return "medium", "", true
}

// redirectTargetRisk 是 writeTargetRisk 的简化形式，只返回级别和是否保留。
func redirectTargetRisk(target string, appendMode bool) (risk string, keep bool) {
	risk, _, keep = writeTargetRisk(target, appendMode)
	return risk, keep
}

// relativeWriteTarget 判断目标是否依赖当前工作目录。
func relativeWriteTarget(target string) bool {
	value := strings.ReplaceAll(normalizeTildeDir(strings.Trim(strings.TrimSpace(target), `"'`)), "\\", "/")
	switch {
	case value == "" || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") || strings.HasPrefix(value, "$") || strings.HasPrefix(value, "%"):
		return false
	case len(value) >= 2 && value[1] == ':':
		return false
	}
	return true
}

func joinWriteBase(base, relative string) string {
	relative = strings.TrimPrefix(strings.ReplaceAll(strings.Trim(strings.TrimSpace(relative), `"'`), "\\", "/"), "./")
	return strings.TrimRight(base, `/\`) + "/" + relative
}

// expandWriteBases 去重，并让每个相对目录与其它非相对目录各拼一次（cd /var/spool && cd cron/crontabs），
// 结果设上限，防止脚本里的大量 cd 放大分析成本。
func expandWriteBases(bases []string) []string {
	result := make([]string, 0, len(bases))
	seen := map[string]struct{}{}
	add := func(value string) {
		if _, ok := seen[value]; ok || len(result) >= maxWriteTargetBases {
			return
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	for _, base := range bases {
		add(normalizeTildeDir(base))
	}
	for index, base := range bases {
		if !relativeWriteTarget(base) {
			continue
		}
		for other, anchor := range bases {
			if other != index && !relativeWriteTarget(anchor) {
				add(joinWriteBase(anchor, base))
			}
		}
	}
	return result
}

// writeTargetRiskWithBases 在原样判断之外：相对目标的文件名命中系统敏感文件名表时至少按 high，
// 并与每个可能的工作目录拼接后再判断，取最高。
func writeTargetRiskWithBases(target string, appendMode bool, bases []string) (risk, subcategory string, keep bool) {
	risk, subcategory, keep = writeTargetRisk(target, appendMode)
	if !relativeWriteTarget(target) {
		return risk, subcategory, keep
	}
	raise := func(candidateRisk, candidateSub string) {
		if !keep || destructiveRiskRank(candidateRisk) > destructiveRiskRank(risk) {
			risk, subcategory, keep = candidateRisk, candidateSub, true
		}
	}
	// 系统敏感文件名只对不带目录的文件名生效（hosts、./hosts、~+/hosts），inventory/hosts 不算。
	// 先 path.Clean，././hosts、.//hosts、./sub/../hosts 和 hosts 同样处理。
	plain := path.Clean(strings.ToLower(strings.ReplaceAll(normalizeTildeDir(strings.Trim(strings.TrimSpace(target), `"'`)), "\\", "/")))
	if _, ok := writeTargetSystemFiles[plain]; ok {
		raise("high", "")
	}
	for _, workDir := range expandWriteBases(bases) {
		if candidateRisk, candidateSub, candidateKeep := writeTargetRisk(joinWriteBase(workDir, target), appendMode); candidateKeep {
			raise(candidateRisk, candidateSub)
		}
	}
	return risk, subcategory, keep
}
