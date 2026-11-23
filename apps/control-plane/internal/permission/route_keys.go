package permission

// OfficerRouteKeys 返回 SoD 表里全部 "METHOD pattern" 键，供 handler 包的静态核对测试遍历（不含任何放行逻辑）。
func OfficerRouteKeys() map[string]SoDClass {
	out := make(map[string]SoDClass, len(sodRouteTable))
	for k, v := range sodRouteTable {
		out[k] = v
	}
	return out
}
