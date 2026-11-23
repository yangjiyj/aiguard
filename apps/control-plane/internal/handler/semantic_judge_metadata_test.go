package handler

import "testing"

// 元数据主机名清单只有一份（egresspolicy.IsMetadataHostname）。
func TestSemanticJudgeUsesSharedMetadataHostnames(t *testing.T) {
	for _, host := range []string{"metadata", "instance-data.ec2.internal", "metadata.goog", "localhost", "x.localhost"} {
		if !isForbiddenSemanticJudgeHostname(host) {
			t.Errorf("%s must be forbidden", host)
		}
	}
}
