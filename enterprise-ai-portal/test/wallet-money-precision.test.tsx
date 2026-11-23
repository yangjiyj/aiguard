import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {WalletSummaryPanel} from '../src/components/wallet-summary-panel.js';
import type {MonthlyWalletStatus} from '../src/lib/wallet-balances.js';
import {billingAmountPresentation} from '../src/lib/call-records.js';

const monthly:MonthlyWalletStatus={configured_micros:391,granted_micros:1,remaining_micros:391,reserved_micros:390,used_micros:0,expired_micros:0,adjusted_micros:0,currency:'CNY',timezone:'Asia/Shanghai',month_start:'2026-10-01T00:00:00Z',month_end:'2026-11-01T00:00:00Z',expires_at:'2026-11-01T00:00:00Z'};
function text(html:string,id:string){return new RegExp('data-testid="'+id+'"[^>]*>([^<]+)').exec(html)?.[1];}

test('rendered wallet and monthly gift retain one micro after a 390-micro reservation',()=>{
 const html=renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet:{currency:'CNY',balance_micros:391,reserved_micros:390,available_micros:1},monthly}));
 assert.equal(text(html,'wallet-total'),'¥0.000391');
 assert.equal(text(html,'wallet-reserved'),'¥0.00039');
 assert.equal(text(html,'wallet-available'),'¥0.000001');
 assert.equal(text(html,'wallet-monthly-granted'),'¥0.000001');
 assert.equal(text(html,'wallet-monthly-available'),'¥0.000001');
});

test('rendered negative and large wallet balances preserve the exact integer-micro value',()=>{
 for(const [balance,expected] of [[-1,'-¥0.000001'],[-390,'-¥0.00039'],[Number.MAX_SAFE_INTEGER,'¥9,007,199,254.740991'],[-Number.MAX_SAFE_INTEGER,'-¥9,007,199,254.740991']] as const){
  const html=renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet:{currency:'CNY',balance_micros:balance,reserved_micros:0,available_micros:balance},monthly:null}));
  assert.equal(text(html,'wallet-total'),expected);assert.equal(text(html,'wallet-available'),expected);
 }
});

test('settled call records show tiny charges and safe-integer boundary without rounding to zero',()=>{
 assert.equal(billingAmountPresentation('settled',1,'CNY'),'¥0.000001');
 assert.equal(billingAmountPresentation('settled',195,'CNY'),'¥0.000195');
 assert.equal(billingAmountPresentation('settled',390,'CNY'),'¥0.00039');
 assert.equal(billingAmountPresentation('settled',Number.MAX_SAFE_INTEGER,'CNY'),'¥9,007,199,254.740991');
});

test('settled amounts retain two minimum decimals and trim only insignificant later zeros',()=>{
 assert.equal(billingAmountPresentation('settled',0,'CNY'),'¥0.00');
 assert.equal(billingAmountPresentation('settled',1_250_000,'CNY'),'¥1.25');
 assert.equal(billingAmountPresentation('settled',123_400_000,'CNY'),'¥123.40');
 assert.equal(billingAmountPresentation('settled',123_000_000,'CNY'),'¥123.00');
});

test('micro amounts keep wallet and call-record currency consistent',()=>{
 const html=renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet:{currency:'USD',balance_micros:390,reserved_micros:1,available_micros:389},monthly:{...monthly,currency:'USD'}}));
 assert.equal(text(html,'wallet-total'),'US$0.00039');assert.equal(text(html,'wallet-reserved'),'US$0.000001');
 assert.equal(text(html,'wallet-available'),'US$0.000389');assert.equal(text(html,'wallet-monthly-available'),'US$0.000001');
 assert.equal(billingAmountPresentation('settled',390,'USD'),'US$0.00039');
});

test('钱包和赠金缺少币种时跟随租户，事实币种仍优先',()=>{
 const html=renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet:{currency:'',balance_micros:390,reserved_micros:0},monthly:{...monthly,currency:''},tenantCurrency:'USD'}));
 assert.equal(text(html,'wallet-total'),'US$0.00039');
 assert.equal(text(html,'wallet-monthly-granted'),'US$0.000001');
 const historical=renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet:{currency:'USD',balance_micros:390,reserved_micros:0},monthly,tenantCurrency:'USD'}));
 assert.equal(text(historical,'wallet-total'),'US$0.00039');
 assert.equal(text(historical,'wallet-monthly-granted'),'¥0.000001');
 assert.equal(billingAmountPresentation('settled',390,'','USD'),'US$0.00039');
 assert.equal(billingAmountPresentation('settled',390,'CNY','USD'),'¥0.00039');
});
