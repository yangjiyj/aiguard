import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import RetentionKeywordText from '../components/RetentionKeywordText'
describe('literal retention highlighting',()=>{
 it('highlights punctuation literally and never interprets markup',()=>{
  const {container}=render(<RetentionKeywordText text={'<img src=x> A+B[继续] a+b[继续] axxb'} keyword="a+b[继续]" />)
  expect(container.querySelectorAll('mark')).toHaveLength(2)
  expect(container.querySelector('img')).toBeNull()
  expect(screen.getByText('A+B[继续]',{selector:'mark'})).toBeInTheDocument()
 })
})
