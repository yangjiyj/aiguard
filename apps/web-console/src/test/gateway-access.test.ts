import {describe,it,expect} from 'vitest'
import {normalizeGatewayBase, gatewayAccessOptions, chooseGatewayEndpoint, inspectGatewayResponse} from '../utils/gatewayAccess'
describe('network-specific gateway access',()=>{
 it('uses the actual browser origin with its port; preserves configured customer domains',()=>{
  const settings={gateway_public_base_url:'https://models.customer.test/prefix/v1',gateway_public_endpoints:JSON.stringify([{name:'客户内网',url:'http://192.168.20.246:8084/v1'}])}
  const options=gatewayAccessOptions(settings,'https://100.64.0.36:444')
  expect(chooseGatewayEndpoint(options,settings)).toBe('https://100.64.0.36:444/v1')
  expect(options.map(v=>v.url)).toEqual(['https://100.64.0.36:444/v1','https://models.customer.test/prefix/v1','http://192.168.20.246:8084/v1'])
  expect(chooseGatewayEndpoint(options,settings,'http://192.168.20.246:8084/v1')).toBe('http://192.168.20.246:8084/v1')
  expect(chooseGatewayEndpoint(options,settings,'https://removed.test/v1')).toBe(options[0].url)
 })
 it('matches a configured prefix on the current origin, and respects fixed separate API hosts',()=>{
  const settings={gateway_public_base_url:'https://customer.test/gateway/v1'}
  expect(gatewayAccessOptions(settings,'https://customer.test')[0].url).toBe('https://customer.test/gateway/v1')
  const fixed={...settings,gateway_public_url_mode:'configured'};const options=gatewayAccessOptions(fixed,'https://console.test')
  expect(chooseGatewayEndpoint(options,fixed)).toBe(settings.gateway_public_base_url)
 })
 it('normalizes IPv6 and prefixes and rejects dangerous input',()=>{
  expect(normalizeGatewayBase('http://[2001:db8::1]:8084/proxy/v1/v1/')).toBe('http://[2001:db8::1]:8084/proxy/v1')
  for(const raw of ['javascript:alert(1)','https://u:p@a/v1','https://a/v1?key=secret','https://a/#x','https://a/../admin','https://a/%2e%2e/admin','https://a/a%2fb/v1'])expect(normalizeGatewayBase(raw)).toBe('')
  expect(gatewayAccessOptions({gateway_public_endpoints:'malformed'},'http://customer:8443')).toHaveLength(1)
 })
 it('distinguishes gateway auth, upstream proxy rejection and HTML routes',()=>{
  expect(inspectGatewayResponse(401,{error:{code:'unauthorized'}}).ok).toBe(true)
  expect(inspectGatewayResponse(401,{error:{type:'new_api_error',message:'Invalid token'}}).ok).toBe(false)
  expect(inspectGatewayResponse(200,'<!doctype html>')).toMatchObject({ok:false})
  expect(inspectGatewayResponse(404,{error:'not found'}).ok).toBe(false)
 })
})

it('follows the console hostname while preserving the configured API transport and port',()=>{
 const settings={gateway_public_base_url:'http://customer.test:8084/prefix/v1',gateway_public_url_mode:'current_host'}
 for(const [origin,want] of [['https://100.64.0.36','http://100.64.0.36:8084/prefix/v1'],['https://192.168.20.246:9443','http://192.168.20.246:8084/prefix/v1'],['https://domain.customer.test','http://domain.customer.test:8084/prefix/v1'],['https://[2001:db8::1]:9443','http://[2001:db8::1]:8084/prefix/v1']]){
  const options=gatewayAccessOptions(settings,origin);expect(chooseGatewayEndpoint(options,settings)).toBe(want)
  expect(options.some(e=>e.name.includes('VPN'))).toBe(false)
 }
})
