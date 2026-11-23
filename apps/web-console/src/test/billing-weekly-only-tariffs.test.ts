import { describe, expect, it } from 'vitest'
import { newTariffRule, rulesFromPlan, serializeTariffRules } from '../components/billing/tariffTemplates'

describe('weekly-only tariff write policy', () => {
 it('keeps legacy date data readable but refuses to serialize it as an edit', () => {
  const rules=rulesFromPlan({rules:[{model_name:'model-a',name:'legacy-date',band:'valley',weekdays:[4],special_date:'2026-10-01T00:00:00Z',start_minute:1439,end_minute:1440,multiplier_ppm:712345}]})
  expect(rules[0]).toMatchObject({special_date:'2026-10-01',start_time:'23:59',end_time:'24:00',multiplier:0.712345})
  expect(()=>serializeTariffRules(rules)).toThrow()
 })
 it('interprets the end picker midnight as the following midnight for a full day', () => {
  expect(serializeTariffRules([newTariffRule('model-a',{start_time:'00:00',end_time:'00:00'})])[0]).toMatchObject({start_minute:0,end_minute:1440})
 })
})
