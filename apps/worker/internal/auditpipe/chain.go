package auditpipe

import (
	"context"

	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
)

// ChainProcessor 把多个 Processor 串行执行。任一返回 error 即短路返回（由 outbox 重试）。
// 用于 worker：先写 DB(auditpipe.Sink) 再导 NAS(nasexport.Processor)。
// 注意：nasexport.Processor 不依赖本包，但实现同款 Process(ctx, outbox.Event) error 签名，
// 由 NewRunner(processor) 时以接口注入，故此处用 auditpipe.Processor 接口聚合。
type ChainProcessor struct {
	steps []Processor
}

func NewChainProcessor(steps ...Processor) *ChainProcessor {
	return &ChainProcessor{steps: steps}
}

func (c *ChainProcessor) Process(ctx context.Context, event outbox.Event) error {
	for _, s := range c.steps {
		if err := s.Process(ctx, event); err != nil {
			return err
		}
	}
	return nil
}
