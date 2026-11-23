package repository

import "testing"

func TestParseRequestTiming(t *testing.T) {
	ttft := int64(100)
	for _, tc := range []struct {
		name, raw string
		latency   int
		tokens    int64
		speed     *float64
	}{
		{"新记录", `{"input_security_ms":12,"output_security_ms":20,"pre_upstream_ms":30,"generation_ms":500}`, 900, 50, floatPointer(100)},
		{"旧记录", `null`, 600, 50, floatPointer(100)},
		{"阈值", `{"generation_ms":200}`, 900, 50, floatPointer(250)},
		{"过短", `{"generation_ms":199}`, 900, 50, nil},
		{"无输出", `{"generation_ms":500}`, 900, 0, nil},
		{"坏字段", `{"generation_ms":"oops","input_security_ms":-1}`, 600, 50, floatPointer(100)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRequestTiming([]byte(tc.raw), tc.latency, &ttft, tc.tokens)
			if got.LatencyMS != tc.latency || got.UpstreamTTFTMS == nil || *got.UpstreamTTFTMS != ttft {
				t.Fatalf("总耗时/首事件丢失: %+v", got)
			}
			if (got.OutputTokensPerSec == nil) != (tc.speed == nil) || tc.speed != nil && *got.OutputTokensPerSec != *tc.speed {
				t.Fatalf("输出速度错误: %+v", got)
			}
			if tc.name == "新记录" && (got.InputSecurityMS == nil || *got.InputSecurityMS != 12 || got.GenerationMS == nil || *got.GenerationMS != 500) {
				t.Fatalf("分段解析失败: %+v", got)
			}
			if tc.name == "旧记录" && got.GenerationMS != nil {
				t.Fatal("不应伪造旧记录分段")
			}
			if tc.name == "坏字段" && got.InputSecurityMS != nil {
				t.Fatal("负数必须丢弃")
			}
		})
	}
}
func floatPointer(v float64) *float64 { return &v }

func TestParseRequestTimingWithoutFirstEvent(t *testing.T) {
	got := parseRequestTiming([]byte(`{"generation_ms":500,"pre_upstream_ms":null}`), 900, nil, 50)
	if got.UpstreamTTFTMS != nil || got.PreUpstreamMS != nil || got.OutputTokensPerSec == nil || *got.OutputTokensPerSec != 100 {
		t.Fatalf("独立生成计时应可用: %+v", got)
	}
	got = parseRequestTiming([]byte(`{}`), 900, nil, 50)
	if got.OutputTokensPerSec != nil {
		t.Fatal("没有首事件和生成时间时不得推测速度")
	}
}
