import test from 'node:test';import assert from 'node:assert/strict';
import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';
const price={model_name:'claude-sonnet-5-5',currency:'USD',pricing_mode:'direct',input_per_million_micros:2_000_000,cached_input_per_million_micros:200_000,cache_write_per_million_micros:2_500_000,output_per_million_micros:10_000_000,has_cached_input_price:true,has_cache_write_price:true,pricing_extras:{}};
const perf={model_name:'claude-sonnet-5-5',protocols:['chat','responses','messages'],samples:156,success_rate:0.987,ttft_p50_ms:9740,ttft_p95_ms:18200,tps_p50:41.2,latency_p50_ms:24100,latency_p95_ms:61000,hourly:[{at:'2026-10-28T00:00:00Z',samples:3,success_rate:1,ttft_p50_ms:8800,tps_p50:40},{at:'2026-10-28T01:00:00Z',samples:2,success_rate:0.5,ttft_p50_ms:9000,tps_p50:38}]};
const esc=(s:string)=>new RegExp(s.replace(/[.*+?^${}()|[\]\\/]/g,'\\$&'));

test('model card shows metrics, protocol tags, a 7-day sparkline and price',async()=>{
 Object.assign(globalThis,{React});
 const {ModelCard}=await import('../src/components/models/model-card.js');
 const html=renderToStaticMarkup(React.createElement(ModelCard,{row:{model:'claude-sonnet-5-5',price,perf},loading:false,selected:false,onSelect:()=>{},currency:'USD'}));
 for(const text of ['claude-sonnet-5-5','Anthropic','Chat','Responses','Messages','9.74s','41.2 t/s','98.7%','每百万 tokens'])assert.match(html,esc(text));
 assert.match(html,/<svg/);assert.doesNotMatch(html,/未定价/);
});

test('model card: loading placeholder, idle and thin samples, unpriced',async()=>{
 Object.assign(globalThis,{React});
 const {ModelCard}=await import('../src/components/models/model-card.js');
 const render=(over:Record<string,unknown>)=>renderToStaticMarkup(React.createElement(ModelCard,{row:{model:'deepseek-v4-pro',price:null,perf:null},loading:false,selected:false,onSelect:()=>{},...over}));
 const loading=render({loading:true});
 assert.match(loading,/data-loading/);assert.doesNotMatch(loading,/—|暂无调用/);
 assert.match(render({}),/近 7 天暂无调用/);
 assert.match(render({}),/未定价/);
 const thin=render({row:{model:'qwen3.8-27b-fp8',price:null,perf:{...perf,model_name:'qwen3.8-27b-fp8',samples:3,success_rate:null,ttft_p50_ms:null,tps_p50:null}}});
 assert.match(thin,/近 7 天 3 次调用，样本不足/);assert.doesNotMatch(thin,/<svg/);
 const bad=render({row:{model:'gpt-6-luna',price:null,perf:{...perf,model_name:'gpt-6-luna',success_rate:0.539}}});
 assert.match(bad,/data-health="bad"/);
});

test('drawer overview, performance and access tabs',async()=>{
 Object.assign(globalThis,{React});
 const {ModelDrawer}=await import('../src/components/models/model-drawer.js');
 const row={model:'claude-sonnet-5-5',price,perf};
 const base={row,onClose:()=>{},onTab:()=>{},onWindow:()=>{},window:168 as const,windowPerf:perf,baseUrl:'https://gw.test/v1',currency:'USD'};
 const overview=renderToStaticMarkup(React.createElement(ModelDrawer,{...base,tab:'overview'}));
 for(const text of ['TPS','首字延迟','成功率','标准价','缓存价','缓存命中','缓存写入','管理 API 密钥'])assert.match(overview,new RegExp(text));
 assert.match(overview,/href="[^"]*\/billing#api-keys"/);
 const perfTab=renderToStaticMarkup(React.createElement(ModelDrawer,{...base,tab:'performance'}));
 assert.match(perfTab,/24 小时/);assert.match(perfTab,/<svg/);assert.match(perfTab,/18\.2s/);assert.match(perfTab,/156/);
 const access=renderToStaticMarkup(React.createElement(ModelDrawer,{...base,tab:'access'}));
 assert.match(access,/https:\/\/gw\.test\/v1/);assert.match(access,/\$JJD_API_KEY/);assert.doesNotMatch(access,/sk-[A-Za-z0-9]/);
 const noCache=renderToStaticMarkup(React.createElement(ModelDrawer,{...base,tab:'overview',row:{...row,price:{...price,has_cached_input_price:false,has_cache_write_price:false}}}));
 assert.doesNotMatch(noCache,/缓存价/);
 const unpriced=renderToStaticMarkup(React.createElement(ModelDrawer,{...base,tab:'overview',row:{...row,price:null,perf:null}}));
 assert.match(unpriced,/未定价/);assert.match(unpriced,/—/);
});

test('billing page no longer embeds the price market and pages use the shell',async()=>{
 const {readFileSync,existsSync}=await import('node:fs');
 const read=(p:string)=>readFileSync(new URL(p,import.meta.url),'utf8');
 const billing=read('../src/components/billing-page.tsx');
 assert.doesNotMatch(billing,/ModelPriceMarket|价格超市|model-prices/);
 assert.equal(existsSync(new URL('../src/components/model-price-market.tsx',import.meta.url)),false);
 assert.match(read('../src/app/models/page.tsx'),/<PortalShell active="models"[ >]/);
 assert.match(read('../src/app/billing/page.tsx'),/<PortalShell active="billing"[ >]/);
 assert.match(read('../src/app/records/page.tsx'),/<PortalShell active="records"[ >]/);
});
