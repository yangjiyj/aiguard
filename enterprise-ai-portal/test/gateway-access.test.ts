import test from 'node:test';import assert from 'node:assert/strict';
import {gatewayClientConfig} from '../src/lib/gateway-client-config.js';
import {gatewayAccessOptions,chooseGatewayEndpoint} from '../src/lib/gateway-access.js';
test('portal selects the caller network without using forwarded headers or a container address',()=>{
 const settings={gateway_public_base_url:'https://api.customer.test/proxy/v1',gateway_public_endpoints:[{name:'内网',url:'http://192.168.1.10:8084/v1'}],gateway_public_url_mode:'current_origin'};
 const options=gatewayAccessOptions(settings,'https://100.64.0.36:444');assert.equal(chooseGatewayEndpoint(options,settings),'https://100.64.0.36:444/v1');assert.equal(options[1].url,settings.gateway_public_base_url);
 const config=gatewayClientConfig(settings.gateway_public_base_url,'',settings);assert.equal(config.access.gateway_public_endpoints.length,1);
 assert.equal(chooseGatewayEndpoint(options,{...settings,gateway_public_url_mode:'configured'}),settings.gateway_public_base_url);
});

test('portal keeps the real API protocol and port when following a different browser hostname',()=>{
 const settings={gateway_public_base_url:'http://customer.test:8080/v1',gateway_public_url_mode:'current_host'}
 const config=gatewayClientConfig(settings.gateway_public_base_url,'https://100.64.0.36',settings)
 assert.equal(config.access.gateway_public_url_mode,'current_host')
 assert.equal(chooseGatewayEndpoint(gatewayAccessOptions(config.access,'https://100.64.0.36'),config.access),'http://100.64.0.36:8080/v1')
})
