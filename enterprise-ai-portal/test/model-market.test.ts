import test from 'node:test';import assert from 'node:assert/strict';
const price=(model_name:string,input:number,output:number)=>({model_name,currency:'USD',pricing_mode:'direct',input_per_million_micros:input,cached_input_per_million_micros:0,cache_write_per_million_micros:0,output_per_million_micros:output,has_cached_input_price:false,has_cache_write_price:false,pricing_extras:{}});
const perf=(model_name:string,over:Record<string,unknown>={})=>({model_name,protocols:['chat'],samples:10,success_rate:0.99,ttft_p50_ms:900,ttft_p95_ms:1500,tps_p50:40,latency_p50_ms:3000,latency_p95_ms:6000,hourly:[],...over});

test('buildMarketRows keeps every authorised model and only authorised models',async()=>{
 const {buildMarketRows}=await import('../src/lib/model-market.js');
 const rows=buildMarketRows(['b','a','c'],[price('a',1,2),price('x',1,1)],[perf('b'),perf('x')]);
 assert.deepEqual(rows.map(r=>r.model),['a','b','c']);
 assert.equal(rows[0].price?.model_name,'a');assert.equal(rows[0].perf,null);
 assert.equal(rows[1].perf?.model_name,'b');assert.equal(rows[2].price,null);
});

test('health thresholds and formatting',async()=>{
 const {healthOf,fmtMs,fmtTps,fmtRate}=await import('../src/lib/model-market.js');
 assert.equal(healthOf(0.95),'good');assert.equal(healthOf(0.9499),'warn');assert.equal(healthOf(0.8),'warn');assert.equal(healthOf(0.79),'bad');assert.equal(healthOf(null),'unknown');
 assert.equal(fmtMs(null),'—');assert.equal(fmtMs(850),'850ms');assert.equal(fmtMs(5290),'5.29s');assert.equal(fmtMs(12930),'12.9s');
 assert.equal(fmtTps(32.46),'32.5 t/s');assert.equal(fmtTps(null),'—');
 assert.equal(fmtRate(0.8976),'89.8%');assert.equal(fmtRate(null),'—');
});

test('sortRows puts missing values last in both directions and filterRows matches name and vendor',async()=>{
 const {buildMarketRows,sortRows,filterRows}=await import('../src/lib/model-market.js');
 const rows=buildMarketRows(['fast','slow','none'],[price('fast',1,1),price('slow',5,5)],[perf('fast',{ttft_p50_ms:500}),perf('slow',{ttft_p50_ms:9000}),perf('none',{ttft_p50_ms:null})]);
 assert.deepEqual(sortRows(rows,{key:'ttft',dir:'asc'}).map(r=>r.model),['fast','slow','none']);
 assert.deepEqual(sortRows(rows,{key:'ttft',dir:'desc'}).map(r=>r.model),['slow','fast','none']);
 assert.deepEqual(sortRows(rows,{key:'price',dir:'asc'}).map(r=>r.model),['fast','slow','none']);
 assert.deepEqual(filterRows(rows,' FA ').map(r=>r.model),['fast']);
});

test('curlExample uses placeholder key and protocol endpoint',async()=>{
 const {curlExample}=await import('../src/lib/model-market.js');
 const chat=curlExample('https://gw.test/v1','m1',['chat','messages']);
 assert.match(chat,/https:\/\/gw\.test\/v1\/chat\/completions/);assert.match(chat,/\$JJD_API_KEY/);assert.match(chat,/"model":"m1"/);
 assert.match(curlExample('https://gw.test/v1','m1',['messages']),/\/v1\/messages/);
 assert.match(curlExample('https://gw.test/v1','m1',['responses']),/\/v1\/responses/);
 assert.equal(curlExample('','m1',['chat']),'');
});

test('samples sort, vendor facets and vendor filter',async()=>{
 const {buildMarketRows,sortRows,filterRows,vendorFacets,SORT_OPTIONS,sortPreset}=await import('../src/lib/model-market.js');
 const rows=buildMarketRows(['gpt-a','claude-b','deepseek-c'],[],[perf('gpt-a',{samples:5}),perf('claude-b',{samples:50})]);
 assert.deepEqual(sortRows(rows,{key:'samples',dir:'desc'}).map(r=>r.model),['claude-b','gpt-a','deepseek-c']);
 assert.deepEqual(vendorFacets(rows),[{id:'deepseek',name:'DeepSeek',count:1},{id:'anthropic',name:'Anthropic',count:1},{id:'openai',name:'OpenAI',count:1}]);
 assert.deepEqual(filterRows(rows,'','anthropic').map(r=>r.model),['claude-b']);
 assert.deepEqual(filterRows(rows,'','all').length,3);
 assert.deepEqual(SORT_OPTIONS.map(o=>o[1]),['常用优先','首字最快','输出最快','成功率最高','名称']);
 assert.deepEqual(sortPreset('tps'),{key:'tps',dir:'desc'});assert.deepEqual(sortPreset('ttft'),{key:'ttft',dir:'asc'});
});
