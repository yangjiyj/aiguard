package agentguard

import "testing"

// 元数据主机名清单只有一份（egresspolicy.IsMetadataHostname）。
func TestAnalyzeTargetUsesSharedMetadataHostnames(t *testing.T) {
	for _, host := range []string{"metadata.goog", "metadata.oraclecloud.com", "metadata.google.internal", "instance-data.ec2.internal"} {
		if got := AnalyzeTarget("http://" + host + "/computeMetadata/v1/"); !got.Hit || got.Reason != targetReasonMetadataHostname {
			t.Errorf("%s: %+v", host, got)
		}
	}
}
