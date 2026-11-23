import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {walletAmounts,latestWalletRefresh,type MonthlyWalletStatus} from '../src/lib/wallet-balances.js';
import {WalletSummaryPanel,walletSummaryCopy} from '../src/components/wallet-summary-panel.js';

const monthly:MonthlyWalletStatus={configured_micros:100_000_000,granted_micros:100_000_000,remaining_micros:60_000_000,reserved_micros:10_000_000,used_micros:40_000_000,expired_micros:0,adjusted_micros:0,currency:'CNY',timezone:'Asia/Shanghai',month_start:'2026-09-30T16:00:00Z',month_end:'2026-10-31T16:00:00Z',expires_at:'2026-10-31T16:00:00Z'};
const wallet={currency:'CNY',balance_micros:185_000_000,reserved_micros:35_000_000,available_micros:150_000_000};
function text(html:string,id:string){return new RegExp('data-testid="'+id+'"[^>]*>([^<]+)').exec(html)?.[1];}
const money=(value:number)=>new Intl.NumberFormat('zh-CN',{style:'currency',currency:'CNY',minimumFractionDigits:2,maximumFractionDigits:6}).format(value/1_000_000);

test('wallet amounts keep prior-month frozen gifts in the real total and avoid a fabricated permanent split',()=>{
 assert.deepEqual(walletAmounts(wallet,monthly),{total:185_000_000,reserved:35_000_000,available:150_000_000,monthlyAvailable:50_000_000});
 assert.equal(Object.prototype.hasOwnProperty.call(walletAmounts(wallet,monthly),'permanent'),false);
 assert.equal(walletAmounts({...wallet,available_micros:149_999_999},monthly).available,149_999_999);
});
test('wallet cards reconcile the real total, all reservations, and the current monthly gift separately',()=>{
 const html=renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet,monthly}));
 assert.equal(text(html,'wallet-total'),money(185_000_000));
 assert.equal(text(html,'wallet-reserved'),money(35_000_000));
 assert.equal(text(html,'wallet-available'),money(150_000_000));
 assert.equal(text(html,'wallet-monthly-granted'),money(100_000_000));
 assert.equal(text(html,'wallet-monthly-available'),money(50_000_000));
 assert.ok(html.includes(walletSummaryCopy.permanent));
 assert.ok(html.includes(walletSummaryCopy.expires));
 const period=text(html,'wallet-monthly-period')||'';
 assert.ok(period.includes('2026')&&period.includes('10'));
});
test('explicit zero gift and wallet remain zero amounts, without an employee quota or exhaustion notice',()=>{
 const zero={...monthly,configured_micros:0,granted_micros:0,remaining_micros:0,reserved_micros:0,used_micros:0};
 const html=renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet:{currency:'CNY',balance_micros:0,reserved_micros:0},monthly:zero}));
 assert.equal(text(html,'wallet-total'),money(0));assert.equal(text(html,'wallet-available'),money(0));assert.ok(html.includes('本月暂无赠送额度'));assert.equal(text(html,'wallet-monthly-available'),undefined);
 assert.equal(html.includes('employee-monthly-allowance'),false);
 assert.equal(html.includes('role="alert"'),false);
});
test('missing monthly data does not pretend that the real wallet is unlimited or zero',()=>{
 const html=renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet,monthly:null}));
 assert.equal(text(html,'wallet-total'),money(185_000_000));assert.ok(html.includes(walletSummaryCopy.monthlyUnavailable));
 assert.equal(walletAmounts({currency:'CNY',balance_micros:2_000_000,reserved_micros:250_000},null).available,1_750_000);
});

test('a stale metadata balance cannot overwrite the refreshed balance after a redemption',async()=>{
 let requests=0;let releaseOld:(value:number)=>void=()=>{};const applied:number[]=[];
 const refresh=latestWalletRefresh(async()=>{requests++;if(requests===1)return new Promise<number>(resolve=>{releaseOld=resolve;});return 200;},snapshot=>{applied.push(snapshot);});
 const old=refresh();await refresh();releaseOld(100);await old;
 assert.deepEqual(applied,[200]);
});
