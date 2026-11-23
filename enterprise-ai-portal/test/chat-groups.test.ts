import test from 'node:test';import assert from 'node:assert/strict';

test('groupByDate splits history into 今天 / 昨天 / 7 天内 / 更早',async()=>{
 const {groupByDate}=await import('../src/lib/chat-groups.js');
 const now=new Date(2026,9,29,10,0,0).getTime();
 const day=86400000;
 const list=[
  {id:'t',title:'今天的',updatedAt:now-3600000},
  {id:'y',title:'昨天的',updatedAt:now-day},
  {id:'w',title:'三天前',updatedAt:now-3*day},
  {id:'o',title:'八天前',updatedAt:now-8*day},
 ];
 const groups=groupByDate(list,now);
 assert.deepEqual(groups.map(g=>[g.label,g.items.map(i=>i.id)]),[['今天',['t']],['昨天',['y']],['7 天内',['w']],['更早',['o']]]);
 assert.deepEqual(groupByDate([list[3]],now).map(g=>g.label),['更早']);
});
