import { describe, it, expect } from 'vitest'
import { resolveProductIdentity } from '../product/profiles'
describe('independent gateway identity', () => {
 it('keeps gateway identity for stale platform server configuration', () => {
   expect(resolveProductIdentity({ product_profile: 'agent-platform', product_name: 'Platform', product_version: '3' })).toEqual({profile:'gateway', name:'JJDGuard', version:'3'})
 })
 it('keeps default gateway identity', () => { expect(resolveProductIdentity().profile).toBe('gateway') })
})
