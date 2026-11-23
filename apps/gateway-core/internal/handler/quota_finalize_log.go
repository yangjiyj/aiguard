package handler

import (
	"errors"
	"log"
	"sync"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 结算阶段的"预占超出"日志。
//
// governor.Settle 的顺序是：先在 Redis 里按 actual 入账（TPM、日/月用量、金额，见
// governor/providers/atomic_admission.go Settle 里 settleAdmissionScript），入账成功之后才在
// actual 大于预占时返回 AdmissionOverrunError / AdmissionCostOverrunError。也就是说这类错误出现时
// 结算已经成功、超出的部分已经照实记账，原先日志写成"finalize ... failed"会让人误以为结算失败。
// 这里把它改成中文告警口径，并按（租户、主体、模型、类型、天）限频：
// 与 quota_overrun_alert.go 的消息中心聚合键一致，每天首次和第 10/100/1000… 次各记一行，
// 完整次数和累计超出量看消息中心里那条聚合通知。其他类型的 finalize 错误（Redis 故障等）
// 仍按"失败"记录，不受限频。

var quotaOverrunLogState = struct {
	sync.Mutex
	day    string
	counts map[string]int64
}{counts: map[string]int64{}}

const quotaOverrunLogMaxKeys = 4096

// quotaOverrunLogOccurrence 返回该聚合键当天第几次出现。跨天或键过多时整体清空，内存有界。
func quotaOverrunLogOccurrence(key, day string) int64 {
	state := &quotaOverrunLogState
	state.Lock()
	defer state.Unlock()
	if state.day != day || len(state.counts) >= quotaOverrunLogMaxKeys {
		state.day = day
		state.counts = map[string]int64{}
	}
	state.counts[key]++
	return state.counts[key]
}

func isLogMilestone(count int64) bool {
	if count <= 1 {
		return count == 1
	}
	for count%10 == 0 {
		count /= 10
	}
	return count == 1
}

// logQuotaFinalizeError 记录 QuotaFinalize 返回的错误。
func logQuotaFinalizeError(envelope *modelrouter.RequestEnvelope, err error) {
	if err == nil || envelope == nil {
		return
	}
	var tokenOverrun *governor.AdmissionOverrunError
	var costOverrun *governor.AdmissionCostOverrunError
	var eventType, unit string
	var estimated, actual int64
	switch {
	case errors.As(err, &tokenOverrun):
		eventType, unit = quotaOverrunTokenEvent, "token"
		estimated, actual = tokenOverrun.EstimatedTokens, tokenOverrun.ActualTokens
	case errors.As(err, &costOverrun):
		eventType, unit = quotaOverrunCostEvent, "金额微单位"
		estimated, actual = costOverrun.EstimatedMicros, costOverrun.ActualMicros
	default:
		log.Printf("[quota.admission] finalize request_id=%s failed: %v", envelope.RequestID, err)
		return
	}
	now := quotaOverrunNow()
	count := quotaOverrunLogOccurrence(quotaOverrunGroupKey(eventType, envelope, now), quotaOverrunDay(now))
	if !isLogMilestone(count) {
		return
	}
	over := actual - estimated
	if over < 0 {
		over = 0
	}
	log.Printf("[quota.admission] 预占超出告警（结算已成功，已按实际用量入账，不是结算失败）: request_id=%s 模型=%s 单位=%s 预占=%d 实际=%d 超出=%d 同主体同模型当日第%d次（本行仅记第1次和10的整数次幂次，完整次数见消息中心聚合通知）",
		envelope.RequestID, envelope.Model, unit, estimated, actual, over, count)
}
