import test from 'node:test';
import assert from 'node:assert/strict';
import {formatMoneyMicros,moneyLimitLabel} from '../src/lib/money-micros.js';

test('integer-micro money retains every significant fraction with two minimum decimals',()=>{
 const cases:ReadonlyArray<readonly [number,string]>=[
  [0,'¥0.00'],[-0,'¥0.00'],[1,'¥0.000001'],[10,'¥0.00001'],[100,'¥0.0001'],
  [1_000,'¥0.001'],[10_000,'¥0.01'],[100_000,'¥0.10'],[1_000_000,'¥1.00'],
  [390,'¥0.00039'],[1_250_000,'¥1.25'],[123_400_000,'¥123.40'],
 ];
 for(const [value,expected] of cases)assert.equal(formatMoneyMicros(value,'CNY'),expected);
});

test('negative micro debits never become a positive zero or negative zero',()=>{
 for(const [value,expected] of [[-1,'-¥0.000001'],[-195,'-¥0.000195'],[-390,'-¥0.00039'],[-1_250_000,'-¥1.25']] as const)assert.equal(formatMoneyMicros(value,'CNY'),expected);
});

test('safe-integer limits retain the final micro with grouping and currency',()=>{
 assert.equal(formatMoneyMicros(Number.MAX_SAFE_INTEGER,'CNY'),'¥9,007,199,254.740991');
 assert.equal(formatMoneyMicros(-Number.MAX_SAFE_INTEGER,'CNY'),'-¥9,007,199,254.740991');
 assert.equal(formatMoneyMicros(Number.MAX_SAFE_INTEGER,'USD'),'US$9,007,199,254.740991');
 assert.equal(formatMoneyMicros(-1,'USD'),'-US$0.000001');
});

test('invalid fractional, non-finite and unsafe micros never display a fabricated amount',()=>{
 for(const value of [NaN,Infinity,-Infinity,1.5,Number.MAX_SAFE_INTEGER+1])assert.equal(formatMoneyMicros(value,'CNY'),'\u2014');
});

test('缺少事实币种时使用租户币种，绝不默认人民币或换算金额',()=>{
 assert.equal(formatMoneyMicros(1_250_000,undefined,'USD'),'US$1.25');
 assert.equal(formatMoneyMicros(1_250_000,'','USD'),'US$1.25');
 assert.equal(formatMoneyMicros(1_250_000,'CNY','USD'),'¥1.25');
 assert.equal(formatMoneyMicros(1_250_000),'—');
 assert.equal(formatMoneyMicros(1_250_000,'invalid'),'—');
});

test('金额上限输入框的单位标签跟随币种，不再写死「元」',()=>{
 assert.equal(moneyLimitLabel('当日金额上限','USD'),'当日金额上限（美元）');
 assert.equal(moneyLimitLabel('当月金额上限','usd'),'当月金额上限（美元）');
 assert.equal(moneyLimitLabel('当日金额上限','CNY'),'当日金额上限（元）');
 assert.equal(moneyLimitLabel('当月金额上限',''),'当月金额上限（元）');
 assert.equal(moneyLimitLabel('当月金额上限',undefined,'USD'),'当月金额上限（美元）');
 assert.equal(moneyLimitLabel('当月金额上限','CNY','USD'),'当月金额上限（元）');
});
