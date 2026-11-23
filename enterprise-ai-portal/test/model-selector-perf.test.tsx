import test from 'node:test';import assert from 'node:assert/strict';
import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';
const perf=(model_name:string,success_rate:number|null,ttft:number|null)=>({model_name,protocols:['chat'],samples:10,success_rate,ttft_p50_ms:ttft,ttft_p95_ms:null,tps_p50:null,latency_p50_ms:null,latency_p95_ms:null,hourly:[]});
const price=(model_name:string)=>({model_name,currency:'USD',pricing_mode:'direct',input_per_million_micros:2_000_000,cached_input_per_million_micros:0,cache_write_per_million_micros:0,output_per_million_micros:10_000_000,has_cached_input_price:false,has_cache_write_price:false,pricing_extras:{}});

test('model option list shows ttft, success rate, health dot and price',async()=>{
 Object.assign(globalThis,{React});
 const {ModelOptionList}=await import('../src/components/chat/model-selector.js');
 const html=renderToStaticMarkup(React.createElement(ModelOptionList,{models:[{id:'claude-a',displayName:'claude-a'},{id:'gpt-b',displayName:'gpt-b'}],current:'claude-a',query:'',perf:[perf('claude-a',0.987,9740),perf('gpt-b',0.5,4170)],prices:[price('claude-a')],onPick:()=>{}}));
 assert.match(html,/9\.74s/);assert.match(html,/98\.7%/);assert.match(html,/50\.0%/);
 assert.match(html,/data-health="good"/);assert.match(html,/data-health="bad"/);
 assert.match(html,/\$2/);assert.match(html,/全部模型/);assert.match(html,/href="[^"]*\/models"/);
 assert.match(html,/aria-selected="true"[^>]*>[\s\S]*?claude-a/);
 assert.doesNotMatch(html,/所有调用均按账号归因审计/);
});

test('model option list filters and still works without performance data',async()=>{
 Object.assign(globalThis,{React});
 const {ModelOptionList}=await import('../src/components/chat/model-selector.js');
 const html=renderToStaticMarkup(React.createElement(ModelOptionList,{models:[{id:'claude-a',displayName:'claude-a'}],current:'claude-a',query:'',perf:null,prices:[],onPick:()=>{}}));
 assert.match(html,/claude-a/);assert.doesNotMatch(html,/首字/);assert.doesNotMatch(html,/data-health/);
 const filtered=renderToStaticMarkup(React.createElement(ModelOptionList,{models:[{id:'claude-a',displayName:'claude-a'},{id:'gpt-b',displayName:'gpt-b'}],current:'claude-a',query:'gpt',perf:null,prices:[],onPick:()=>{}}));
 assert.doesNotMatch(filtered,/claude-a/);assert.match(filtered,/gpt-b/);
});
