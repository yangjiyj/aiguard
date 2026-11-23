"use client";
import {useEffect,useRef,type RefObject} from 'react';
export function useDialogFocus(ref:RefObject<HTMLElement|null>,active:boolean,onClose:()=>void,fallback?:RefObject<HTMLElement|null>){
 const closeRef=useRef(onClose);useEffect(()=>{closeRef.current=onClose},[onClose]);
 useEffect(()=>{
  if(!active||!ref.current)return;
  const dialog=ref.current,previous=document.activeElement as HTMLElement|null;
  const candidates=()=>[...dialog.querySelectorAll<HTMLElement>('button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),a[href],[tabindex]:not([tabindex="-1"])')].filter(el=>!el.hasAttribute('hidden'));
  (dialog.querySelector<HTMLElement>('[data-dialog-autofocus]')??candidates()[0]??dialog).focus();
  const keydown=(event:KeyboardEvent)=>{
   if(event.key==='Escape'){event.preventDefault();event.stopPropagation();closeRef.current();return}
   if(event.key!=='Tab')return;
   const items=candidates(),first=items[0],last=items.at(-1);
   if(!first){event.preventDefault();dialog.focus();return}
   if(event.shiftKey&&(document.activeElement===first||!dialog.contains(document.activeElement))){event.preventDefault();last?.focus()}
   else if(!event.shiftKey&&(document.activeElement===last||!dialog.contains(document.activeElement))){event.preventDefault();first.focus()}
  };
  document.addEventListener('keydown',keydown);
  return()=>{document.removeEventListener('keydown',keydown);if(previous?.isConnected&&previous!==document.body)previous.focus();else fallback?.current?.focus()};
 },[active,ref,fallback]);
}
