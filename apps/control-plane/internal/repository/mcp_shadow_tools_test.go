package repository

import "testing"

func TestDetectShadowTools(t *testing.T) {
	names := map[string]string{"srv_a": "可信A", "srv_b": "可疑B", "srv_c": "服务C"}
	tools := []*MCPTool{
		{ToolName: "read_file", ServerID: "srv_a", SchemaHash: "h1"},
		{ToolName: "read_file", ServerID: "srv_b", SchemaHash: "h2"}, // 同名跨 server + 指纹不同
		{ToolName: "solo_tool", ServerID: "srv_a", SchemaHash: "h3"}, // 仅一台=非影子
		{ToolName: "list_dir", ServerID: "srv_a", SchemaHash: "h4"},
		{ToolName: "list_dir", ServerID: "srv_c", SchemaHash: "h4"}, // 同名跨 server + 指纹相同
		{ToolName: "removed_one", ServerID: "srv_a", SchemaHash: "h5", Removed: true},
		{ToolName: "removed_one", ServerID: "srv_b", SchemaHash: "h6", Removed: true}, // removed 不计
	}
	got := DetectShadowTools(tools, names)
	if len(got) != 2 {
		t.Fatalf("应检出 2 条影子工具(read_file/list_dir)，得到 %d: %+v", len(got), got)
	}
	byName := map[string]MCPShadowToolWarning{}
	for _, w := range got {
		byName[w.ToolName] = w
	}
	rf, ok := byName["read_file"]
	if !ok || !rf.SchemaDiverges || len(rf.Servers) != 2 {
		t.Fatalf("read_file 应 2 台且指纹发散: %+v", rf)
	}
	if rf.Servers[0].ServerName == "" || rf.Servers[0].ServerName == rf.Servers[0].ServerID {
		t.Fatalf("server 名应被解析为中文名: %+v", rf.Servers)
	}
	ld := byName["list_dir"]
	if ld.SchemaDiverges {
		t.Fatalf("list_dir 指纹相同不应标发散: %+v", ld)
	}
	if _, bad := byName["solo_tool"]; bad {
		t.Fatalf("solo_tool 仅一台不应告警")
	}
	if _, bad := byName["removed_one"]; bad {
		t.Fatalf("removed 工具不应参与影子检测")
	}
}

func TestDetectShadowToolsEmpty(t *testing.T) {
	if got := DetectShadowTools(nil, nil); len(got) != 0 {
		t.Fatalf("空输入应返回空: %+v", got)
	}
}
