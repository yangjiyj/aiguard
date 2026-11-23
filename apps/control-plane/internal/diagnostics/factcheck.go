package diagnostics

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	// 请求编号：网关为 req_ 加 UUID，正向代理（proxy-server）为裸 UUID，两种都要认。
	reqIDRe  = regexp.MustCompile(`(?:req_)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	numberRe = regexp.MustCompile(`\d+(?:\.\d+)?%?`)
)

// numberWhitelisted 判断数字是否免于校验：0、1 到 24 的整数、四位年份、100%。
func numberWhitelisted(tok string) bool {
	if tok == "100%" {
		return true
	}
	if strings.HasSuffix(tok, "%") || strings.Contains(tok, ".") {
		return false
	}
	n, err := strconv.Atoi(tok)
	if err != nil {
		return false
	}
	if n >= 0 && n <= 24 {
		return true
	}
	return len(tok) == 4 && n >= 1900 && n <= 2099
}

// FactCheck 校验结论中的数字与请求编号都出现在工具返回中，防止模型编造。
// 检查范围：每条 Finding 的 Title、Impact 与 Advice.Text。
func FactCheck(r *Report) error {
	if r == nil {
		return nil
	}
	var sb strings.Builder
	for _, s := range r.Steps {
		sb.Write(s.Output)
		sb.WriteByte('\n')
	}
	corpus := sb.String()

	// 工具输出中出现过的数字集合（去掉百分号，按词元匹配，避免 500 误中 1500）。
	nums := map[string]bool{}
	// 先去掉编号再取数字，防止 uuid 里的数字片段让编造的数字蒙混过关。
	for _, tok := range numberRe.FindAllString(reqIDRe.ReplaceAllString(corpus, " "), -1) {
		nums[strings.TrimSuffix(tok, "%")] = true
	}

	for _, f := range r.Findings {
		// 证据里引用的请求编号同样必须是查出来的。
		for _, e := range f.Evidence {
			for _, id := range reqIDRe.FindAllString(e.Ref+" "+e.Summary, -1) {
				if !strings.Contains(corpus, id) {
					return fmt.Errorf("事实校验失败：证据中的请求编号 %s 未出现在工具返回中", id)
				}
			}
		}
		texts := []string{f.Title, f.Impact}
		for _, a := range f.Advice {
			texts = append(texts, a.Text)
		}
		for _, t := range texts {
			for _, id := range reqIDRe.FindAllString(t, -1) {
				if !strings.Contains(corpus, id) {
					return fmt.Errorf("事实校验失败：结论中的请求编号 %s 未出现在工具返回中", id)
				}
			}
			rest := reqIDRe.ReplaceAllString(t, " ")
			for _, tok := range numberRe.FindAllString(rest, -1) {
				if numberWhitelisted(tok) {
					continue
				}
				if !nums[strings.TrimSuffix(tok, "%")] {
					return fmt.Errorf("事实校验失败：结论中的数字 %s 未出现在工具返回中", tok)
				}
			}
		}
	}
	return nil
}
