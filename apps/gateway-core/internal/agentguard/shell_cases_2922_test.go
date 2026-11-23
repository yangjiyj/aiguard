package agentguard

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// testdata/shell_cases_2922.json 是本包与 handler 包共用的用例清单：智能体日常会发的典型命令，
// 和 64KB 附近的病态输入（每条由若干片段重复拼成；indexed 的片段用序号格式化，生成各不相同的词）。

type shellCasePart struct {
	Text    string `json:"text"`
	Repeat  int    `json:"repeat"`
	Indexed bool   `json:"indexed"`
}

type shellCaseFile struct {
	Typical      []string `json:"typical"`
	Pathological []struct {
		Name  string          `json:"name"`
		Parts []shellCasePart `json:"parts"`
	} `json:"pathological"`
}

// namedCommand is one pathological input.
type namedCommand struct{ name, command string }

func loadShellCases2922(tb testing.TB) ([]string, []namedCommand) {
	tb.Helper()
	raw, err := os.ReadFile("testdata/shell_cases_2922.json")
	if err != nil {
		tb.Fatal(err)
	}
	var file shellCaseFile
	if err := json.Unmarshal(raw, &file); err != nil {
		tb.Fatal(err)
	}
	var pathological []namedCommand
	for _, item := range file.Pathological {
		var b strings.Builder
		for _, part := range item.Parts {
			repeat := max(part.Repeat, 1)
			for i := 0; i < repeat; i++ {
				if part.Indexed {
					fmt.Fprintf(&b, part.Text, i)
				} else {
					b.WriteString(part.Text)
				}
			}
		}
		pathological = append(pathological, namedCommand{item.Name, b.String()})
	}
	return file.Typical, pathological
}
