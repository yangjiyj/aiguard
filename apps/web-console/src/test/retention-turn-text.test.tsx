import {fireEvent,render,screen} from '@testing-library/react'
import {describe,it,expect} from 'vitest'
import {RetainedTurnText} from '../pages/AccessRetention'
describe('retained answer presentation',()=>{
 it('starts large JSON in a compact preview and expands the complete evidence',()=>{
  const content=JSON.stringify({results:Array.from({length:20},(_,i)=>({index:i,value:'result '+i}))})
  render(<RetainedTurnText content={content} kind="response" />)
  const code=screen.getByTestId('retained-code-block')
  expect(code).toHaveStyle({maxHeight:'150px',overflow:'hidden'})
  expect(code).toHaveTextContent('result 19')
  fireEvent.click(screen.getByRole('button',{name:/展开完整 JSON/}))
  expect(screen.getByRole('button',{name:'收起代码'})).toHaveAttribute('aria-expanded','true')
  expect(code.style.maxHeight).toBe('')
 })
 it('expands a code block containing the body-search hit below the preview',()=>{
  const content=JSON.stringify({rows:Array.from({length:30},(_,i)=>i===29?'继续检查':'普通记录')})
  render(<RetainedTurnText content={content} kind="response" keyword="继续" />)
  expect(screen.getByTestId('retained-code-block').style.maxHeight).toBe('')
  expect(screen.getByText('继续',{selector:'mark'})).toBeInTheDocument()
 })
 it('formats prose without interpreting retained HTML or loading remote media',()=>{
  const {container}=render(<RetainedTurnText content={'## 检查结果\n\n**继续**检查 `代码`。\n\n<img src="https://invalid.example/private">'} kind="response" keyword="继续" />)
  expect(screen.getByRole('heading',{name:'检查结果'})).toBeInTheDocument()
  expect(screen.getByText('继续',{selector:'mark'})).toBeInTheDocument()
  expect(container.querySelector('img')).toBeNull()
  expect(screen.getByText('<img src="https://invalid.example/private">')).toBeInTheDocument()
 })
})

describe('retained Markdown tables',()=>{
 it('renders the customer table with breaks, formatting and search highlights',()=>{
  const {container}=render(<RetainedTurnText content={'## 表格内容还原\n| 任务 | 智能体 |\n| --- | --- |\n| 分析图片<br>继续检查 | **CodeBuddy** |'} kind="response" keyword="继续" />)
  expect(screen.getByRole('table')).toBeInTheDocument()
  expect(screen.getAllByRole('columnheader')).toHaveLength(2)
  expect(screen.getByRole('heading',{name:'表格内容还原'})).toBeInTheDocument()
  expect(screen.getByText('继续',{selector:'mark'})).toBeInTheDocument()
  expect(container.querySelector('td br')).not.toBeNull()
 })
 it('keeps escaped pipes in cells and never interprets embedded active HTML',()=>{
  const {container}=render(<RetainedTurnText content={'| A | B |\n| --- | --- |\n| a\\|b | <img src="https://invalid.example/private" onerror="alert(1)"> |'} kind="response" />)
  expect(screen.getAllByRole('cell')).toHaveLength(2)
  expect(screen.getByRole('cell',{name:'a|b'})).toBeInTheDocument()
  expect(container.querySelector('img')).toBeNull()
 })
})
