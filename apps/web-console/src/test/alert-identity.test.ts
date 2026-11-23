import { describe, expect, it } from 'vitest'
import type { AlertOccurrence } from '../services/alertOccurrences'
import { alertIdentityLabel, alertIdentityBasis, alertConnectionLabel, alertClientLabel } from '../utils/alertIdentity'
const row = (p: Partial<AlertOccurrence>) => p as AlertOccurrence
describe('alert identity and access attribution', () => {
  it('prioritizes actor, then credential account, then IP without changing attribution', () => {
    expect(alertIdentityLabel(row({actor_name:'Alice',key_owner_name:'Bob',credential_name:'Key',source_ip:'192.0.2.1'}))).toBe('Alice')
    expect(alertIdentityLabel(row({key_owner_name:'Bob',credential_name:'Key',source_ip:'192.0.2.1'}))).toBe('Bob')
    expect(alertIdentityBasis(row({key_owner_name:'Bob'}))).toBe('凭据绑定账户')
    expect(alertIdentityLabel(row({actor_user_id:'deleted',credential_name:'Key',principal_key:'upstream:credential:abc',source_ip:'192.0.2.1'}))).toBe('192.0.2.1')
    expect(alertIdentityLabel(row({credential_name:'Key'}))).toBe('账户与来源 IP 未记录')
  })
  it.each([
    [{identity_source:'api_key',access_direction:'chat_completion'},'API Key 接入'],
    [{access_direction:'forward'},'正向代理'],
    [{access_direction:'reverse'},'反向代理'],
    [{access_direction:'forward',access_type:'web'},'正向代理 · 网页 AI'],
    [{access_direction:'forward',access_type:'ai_ide'},'正向代理 · AI 编程工具'],
    [{access_type:'web_ai'},'网页 AI'],
    [{access_direction:'forward',access_type:'llm',client_product:'deepseek_chat'},'正向代理 · 网页 AI'],
    [{access_direction:'forward',access_type:'llm',client_product:'deepseek_api'},'正向代理 · 大模型访问'],
    [{access_direction:'new_internal_code'},'接入方式未记录'],
  ])('translates recorded connection metadata %j', (p, expected) => expect(alertConnectionLabel(row(p))).toBe(expected))
  it('uses recorded product and does not guess web usage from destination', () => {
    expect(alertClientLabel(row({client_product:'codebuddy'}))).toBe('腾讯 CodeBuddy')
    expect(alertConnectionLabel(row({target_host:'chatgpt.com'}))).toBe('接入方式未记录')
  })
})
