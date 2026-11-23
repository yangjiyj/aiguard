package diagnostics

// HostView 是宿主机采集器快照的视图；Err 可能是 ErrAgentMissing。
// 由任务 10 定义，此处内容与之保持一致，合并时去重。
type HostView struct {
	Snapshot *HostSnapshot
	Err      error
}
