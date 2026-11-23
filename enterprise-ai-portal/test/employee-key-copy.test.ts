import assert from 'node:assert/strict';
import test from 'node:test';
import { copyEmployeeKey } from '../src/components/employee-key-panel.js';

test('private HTTP clipboard fallback selects a temporary field and removes it',async()=>{
  const originalNavigator=Object.getOwnPropertyDescriptor(globalThis,'navigator');
  const originalDocument=Object.getOwnPropertyDescriptor(globalThis,'document');
  let selected=false;let removed=false;let appended=false;let value='';
  const field={style:{position:'',opacity:''},setAttribute:()=>undefined,select:()=>{selected=true;},remove:()=>{removed=true;},
    get value(){return value;},set value(next:string){value=next;}};
  Object.defineProperty(globalThis,'navigator',{configurable:true,value:{clipboard:{writeText:async()=>{throw new Error('blocked');}}}});
  Object.defineProperty(globalThis,'document',{configurable:true,value:{createElement:(name:string)=>{assert.equal(name,'textarea');return field;},
    body:{appendChild:()=>{appended=true;}},execCommand:(command:string)=>{assert.equal(command,'copy');return true;}}});
  try{await copyEmployeeKey('dummy-fixture-value');assert.equal(value,'dummy-fixture-value');assert.ok(selected&&removed&&appended);}
  finally{if(originalNavigator)Object.defineProperty(globalThis,'navigator',originalNavigator);else Reflect.deleteProperty(globalThis,'navigator');
    if(originalDocument)Object.defineProperty(globalThis,'document',originalDocument);else Reflect.deleteProperty(globalThis,'document');}
});

test('a failed native copy still removes the temporary field',async()=>{
  const originalNavigator=Object.getOwnPropertyDescriptor(globalThis,'navigator');
  const originalDocument=Object.getOwnPropertyDescriptor(globalThis,'document');let removed=false;
  Object.defineProperty(globalThis,'navigator',{configurable:true,value:{}});
  Object.defineProperty(globalThis,'document',{configurable:true,value:{createElement:()=>({value:'',style:{},setAttribute:()=>undefined,
    select:()=>undefined,remove:()=>{removed=true;}}),body:{appendChild:()=>undefined},execCommand:()=>false}});
  try{await assert.rejects(()=>copyEmployeeKey('dummy-fixture-value'));assert.ok(removed);}
  finally{if(originalNavigator)Object.defineProperty(globalThis,'navigator',originalNavigator);else Reflect.deleteProperty(globalThis,'navigator');
    if(originalDocument)Object.defineProperty(globalThis,'document',originalDocument);else Reflect.deleteProperty(globalThis,'document');}
});
