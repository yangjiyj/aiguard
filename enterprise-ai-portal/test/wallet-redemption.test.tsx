import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {redeemWalletCode,WalletRedemptionError} from '../src/lib/wallet-redemption.js';
import {RedemptionPanel,redemptionCopy} from '../src/components/redemption-panel.js';

test('redemption is a distinct panel with private code input and permanent-credit wording',()=>{
 const html=renderToStaticMarkup(React.createElement(RedemptionPanel,{currency:'CNY',onRedeemed:async()=>{}}));
 assert.ok(html.includes('data-testid="wallet-redemption"'));assert.ok(html.includes(redemptionCopy.title));
 assert.ok(html.includes('data-sensitive'));assert.ok(html.includes('maxLength="128"'));
 assert.ok(html.includes(redemptionCopy.permanent));assert.ok(html.includes('disabled=""'));
 assert.equal(html.includes('employee-monthly-allowance'),false);
});
test('successful redemption sends only the trimmed code and refreshes the authoritative wallet once',async()=>{
 let requests=0,refreshes=0;
 const result=await redeemWalletCode('  GIFT-TEST-ONE  ',{fetchImpl:async(input,init)=>{
  requests++;assert.equal(String(input),'/chat/api/me/billing/redeem');assert.equal(init?.method,'POST');
  assert.deepEqual(JSON.parse(String(init?.body)),{code:'GIFT-TEST-ONE'});
  return new Response('{}',{status:200});
 },refresh:async()=>{refreshes++;}});
 assert.equal(result,'redeemed');assert.equal(requests,1);assert.equal(refreshes,1);
});
test('a consumed or invalid code refuses redemption without refreshing the balance',async()=>{
 let refreshes=0;
 await assert.rejects(()=>redeemWalletCode('GIFT-TEST-ONE',{fetchImpl:async()=>Response.json({error:'redemption_unavailable'},{status:409}),refresh:async()=>{refreshes++;}}),error=>error instanceof WalletRedemptionError&&error.code==='redemption_unavailable');
 assert.equal(refreshes,0);
});
test('a committed redemption whose balance refresh fails is distinguished from a failed redemption',async()=>{
 let requests=0;
 const result=await redeemWalletCode('GIFT-TEST-ONE',{fetchImpl:async()=>{requests++;return new Response('{}',{status:200});},refresh:async()=>{throw new Error('network');}});
 assert.equal(result,'redeemed_refresh_pending');assert.equal(requests,1);
});
test('empty and oversized codes never reach the money endpoint',async()=>{
 let requests=0;
 for(const code of ['  ','x'.repeat(129)])await assert.rejects(()=>redeemWalletCode(code,{fetchImpl:async()=>{requests++;return new Response('{}',{status:200});},refresh:async()=>{}}),error=>error instanceof WalletRedemptionError&&error.code==='invalid_input');
 assert.equal(requests,0);
});

test('兑换错误保留错误码并区分同源、限频、依赖和登录失败',async()=>{
 for(const code of ['invalid_origin','redemption_unavailable','rate_limited','control_plane_unreachable','unauthorized']){
  await assert.rejects(()=>redeemWalletCode('GIFT-TEST-ONE',{fetchImpl:async()=>Response.json({error:code},{status:403}),refresh:async()=>{assert.fail('must not refresh')}}),error=>error instanceof WalletRedemptionError&&error.code===code);
 }
});
