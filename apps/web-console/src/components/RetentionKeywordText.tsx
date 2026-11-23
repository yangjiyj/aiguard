import { Fragment } from 'react'

export default function RetentionKeywordText({ text, keyword = '' }: { text: string; keyword?: string }) {
 if (!keyword) return <>{text}</>
 const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
 const pattern = new RegExp(escaped, 'giu')
 const parts = []
 let from = 0
 for (const match of text.matchAll(pattern)) {
  const at = match.index!
  parts.push(<Fragment key={at}>{text.slice(from, at)}<mark style={{ background: '#ffe58f', color: '#613400', borderRadius: 2, padding: '0 1px' }}>{match[0]}</mark></Fragment>)
  from = at + match[0].length
 }
 return <>{parts}{text.slice(from)}</>
}
