import test from 'node:test';import assert from 'node:assert/strict';import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';
import type {MonthlyWalletStatus} from '../src/lib/wallet-balances';
import {watermarkLines,watermarkAccount} from '../src/lib/watermark';
import {WalletSummaryPanel,walletBalanceTone} from '../src/components/wallet-summary-panel';
test('水印优先邮箱或用户名，UUID 仅前八位，全空无水印',()=>{
 assert.equal(watermarkAccount({id:'3f1e1499-8871-4796-92b0-000000000000'}),'3f1e1499');
 assert.deepEqual(watermarkLines({name:'测试',id:'uuid'},'时间'),['测试','时间']);
 assert.deepEqual(watermarkLines({name:'测试',email:'tester@example.test'},'时间'),['测试 tester','时间']);
 assert.deepEqual(watermarkLines({},'时间'),[]);
});
test('余额色阶按零余额和三天日均消费计算，不改变金额',()=>{
 assert.equal(walletBalanceTone(0,100),'empty');assert.equal(walletBalanceTone(300,100),'low');
 assert.equal(walletBalanceTone(301,100),'normal');assert.equal(walletBalanceTone(1,0),'normal');
});
test('未设置赠送时收成一行，保留真实总额与预占',()=>{
 const html=renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet:{currency:'CNY',balance_micros:1000000,reserved_micros:0},monthly:{configured_micros:null,granted_micros:0,remaining_micros:0,reserved_micros:0} as MonthlyWalletStatus}));
 assert.ok(html.includes('本月暂无赠送额度'));assert.ok(!html.includes('wallet-monthly-expires'));
});

test('赠送仅在到期前七天提示，未来八天及已到期均不误报',()=>{
 const monthly:MonthlyWalletStatus={configured_micros:1000000,granted_micros:1000000,remaining_micros:1000000,reserved_micros:0,used_micros:0,expired_micros:0,adjusted_micros:0,currency:'CNY',timezone:'Asia/Shanghai',month_start:'2026-10-01T00:00:00Z',month_end:'2026-11-01T00:00:00Z',expires_at:'2026-10-22T00:00:00Z'};
 const render=(now:string)=>renderToStaticMarkup(React.createElement(WalletSummaryPanel,{wallet:{currency:'CNY',balance_micros:1000000,reserved_micros:0},monthly,now:Date.parse(now)}));
 assert.ok(render('2026-10-15T00:00:00Z').includes('赠送额度将在 7 天内到期'));
 assert.ok(!render('2026-10-14T00:00:00Z').includes('赠送额度将在 7 天内到期'));
 assert.ok(!render('2026-10-22T00:00:00Z').includes('赠送额度将在 7 天内到期'));
});
