import { describe, it, expect } from 'vitest'
import { credentialAssessment, getFindingCategoryLabel } from '../utils/alertOccurrenceDisplay'

describe('credential assessment', () => {
 it('does not call a rule match a confirmed leak', () => {
  const r = credentialAssessment({category:'plain_password',validation_status:'literal_candidate',credential_validity:'unknown',model_review_status:'not_requested',confidence_kind:'heuristic_rule_score'})!
  expect(r.validation).toContain('待核验');expect(r.review).toBe('未进行模型复核');expect(r.validity).toContain('未验证');expect(r.confidence).toContain('不是泄露概率')
 })
 it('does not invent historical model execution', () => {
  expect(credentialAssessment({category:'code_leak_database_url'})?.review).toBe('未记录模型复核状态')
  expect(getFindingCategoryLabel('code_leak_database_url')).toContain('候选')
 })
 it('distinguishes incomplete model review', () => {
  expect(credentialAssessment({category:'openai_key',model_review_status:'incomplete'})?.review).toBe('模型复核未完成')
 })
})
