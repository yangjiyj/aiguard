/**
 * 报告导出：把页面上的统计结论导出成两种交付物。
 *
 * - PDF / 打印：交给浏览器打印管线（调用方负责给报告容器挂 print css 类）。
 * - Word（.docx）：这里直接生成真正的 OOXML 包。
 *
 * 为什么手写而不是引第三方库：这个前端是要打进离线交付包的，新增一个 1MB 级别的
 * docx 依赖会牵动 package-lock、离线包体积和供应链审计。报告是纯文本 + 表格，
 * OOXML 最小文件集只有三个 XML，用 store（不压缩）方式的 ZIP 就足够，Word /
 * WPS / LibreOffice 都能正常打开。
 */

type ZipEntry = { name: string; content: string }

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i += 1) {
    let value = i
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
    }
    table[i] = value >>> 0
  }
  return table
})()

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff
  for (let i = 0; i < bytes.length; i += 1) {
    crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

// DOS 时间戳固定为 2026-09-15 00:00，避免同一份报告每次导出字节都不同。
const DOS_TIME = 0
const DOS_DATE = 15 | (9 << 5) | ((2026 - 1980) << 9)

// TS 5.7 把 Uint8Array 的 buffer 标注成 ArrayBufferLike（可能是 SharedArrayBuffer），
// 不能直接当 BlobPart 用；这里拷一份成真正的 ArrayBuffer，类型干净且避免共享缓冲区被改。
function toBlobPart(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(copy).set(bytes)
  return copy
}

function buildZip(entries: ZipEntry[]): Blob {
  const encoder = new TextEncoder()
  const parts: ArrayBuffer[] = []
  const centralDirectory: ArrayBuffer[] = []
  let offset = 0

  for (const entry of entries) {
    const nameBytes = encoder.encode(entry.name)
    const dataBytes = encoder.encode(entry.content)
    const checksum = crc32(dataBytes)

    const local = new Uint8Array(30 + nameBytes.length)
    const localView = new DataView(local.buffer)
    localView.setUint32(0, 0x04034b50, true)
    localView.setUint16(4, 20, true)
    localView.setUint16(6, 0, true)
    localView.setUint16(8, 0, true) // 0 = store，不压缩
    localView.setUint16(10, DOS_TIME, true)
    localView.setUint16(12, DOS_DATE, true)
    localView.setUint32(14, checksum, true)
    localView.setUint32(18, dataBytes.length, true)
    localView.setUint32(22, dataBytes.length, true)
    localView.setUint16(26, nameBytes.length, true)
    localView.setUint16(28, 0, true)
    local.set(nameBytes, 30)
    parts.push(toBlobPart(local), toBlobPart(dataBytes))

    const central = new Uint8Array(46 + nameBytes.length)
    const centralView = new DataView(central.buffer)
    centralView.setUint32(0, 0x02014b50, true)
    centralView.setUint16(4, 20, true)
    centralView.setUint16(6, 20, true)
    centralView.setUint16(8, 0, true)
    centralView.setUint16(10, 0, true)
    centralView.setUint16(12, DOS_TIME, true)
    centralView.setUint16(14, DOS_DATE, true)
    centralView.setUint32(16, checksum, true)
    centralView.setUint32(20, dataBytes.length, true)
    centralView.setUint32(24, dataBytes.length, true)
    centralView.setUint16(28, nameBytes.length, true)
    centralView.setUint16(30, 0, true)
    centralView.setUint16(32, 0, true)
    centralView.setUint16(34, 0, true)
    centralView.setUint16(36, 0, true)
    centralView.setUint32(38, 0, true)
    centralView.setUint32(42, offset, true)
    central.set(nameBytes, 46)
    centralDirectory.push(toBlobPart(central))

    offset += local.length + dataBytes.length
  }

  const centralSize = centralDirectory.reduce((sum, item) => sum + item.byteLength, 0)
  const end = new Uint8Array(22)
  const endView = new DataView(end.buffer)
  endView.setUint32(0, 0x06054b50, true)
  endView.setUint16(4, 0, true)
  endView.setUint16(6, 0, true)
  endView.setUint16(8, entries.length, true)
  endView.setUint16(10, entries.length, true)
  endView.setUint32(12, centralSize, true)
  endView.setUint32(16, offset, true)
  endView.setUint16(20, 0, true)

  return new Blob([...parts, ...centralDirectory, toBlobPart(end)], {
    type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  })
}

export type ReportBlock =
  | { type: 'heading'; text: string; level?: 1 | 2 | 3 }
  | { type: 'paragraph'; text: string }
  | { type: 'metrics'; items: { label: string; value: string; note?: string }[] }
  | { type: 'table'; columns: string[]; rows: string[][] }
  | { type: 'bullets'; items: string[] }

export type ReportDocument = {
  title: string
  subtitle?: string
  meta?: { label: string; value: string }[]
  blocks: ReportBlock[]
}

function escapeXml(value: string): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

const FONT = '<w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:eastAsia="微软雅黑"/>'

function run(text: string, options: { bold?: boolean; size?: number; color?: string } = {}) {
  const props = [
    FONT,
    options.bold ? '<w:b/>' : '',
    options.size ? `<w:sz w:val="${options.size}"/><w:szCs w:val="${options.size}"/>` : '',
    options.color ? `<w:color w:val="${options.color}"/>` : '',
  ].join('')
  // xml:space="preserve" 保住中英文之间的空格，否则 Word 会吃掉行首行尾空白。
  return `<w:r><w:rPr>${props}</w:rPr><w:t xml:space="preserve">${escapeXml(text)}</w:t></w:r>`
}

function paragraph(text: string, options: { bold?: boolean; size?: number; align?: string; color?: string; spacingBefore?: number } = {}) {
  const alignment = options.align ? `<w:jc w:val="${options.align}"/>` : ''
  const spacing = options.spacingBefore ? `<w:spacing w:before="${options.spacingBefore}"/>` : ''
  return `<w:p><w:pPr>${alignment}${spacing}</w:pPr>${run(text, options)}</w:p>`
}

function heading(text: string, level: 1 | 2 | 3) {
  const size = level === 1 ? 32 : level === 2 ? 28 : 24
  return paragraph(text, { bold: true, size, spacingBefore: 240 })
}

function table(columns: string[], rows: string[][]) {
  const border = '<w:tblBorders>'
    + ['top', 'left', 'bottom', 'right', 'insideH', 'insideV']
      .map((side) => `<w:${side} w:val="single" w:sz="6" w:space="0" w:color="BFBFBF"/>`)
      .join('')
    + '</w:tblBorders>'
  const headerCells = columns
    .map((column) => `<w:tc><w:tcPr><w:shd w:val="clear" w:fill="F2F2F2"/></w:tcPr>${paragraph(column, { bold: true, size: 20 })}</w:tc>`)
    .join('')
  const bodyRows = rows
    .map((row) => `<w:tr>${row.map((cell) => `<w:tc>${paragraph(cell, { size: 20 })}</w:tc>`).join('')}</w:tr>`)
    .join('')
  return `<w:tbl><w:tblPr>${border}</w:tblPr><w:tr>${headerCells}</w:tr>${bodyRows}</w:tbl>`
}

function renderBlock(block: ReportBlock): string {
  switch (block.type) {
    case 'heading':
      return heading(block.text, block.level || 2)
    case 'paragraph':
      return paragraph(block.text)
    case 'bullets':
      return block.items.map((item) => paragraph(`· ${item}`)).join('')
    case 'metrics':
      return table(
        ['指标', '数值', '说明'],
        block.items.map((item) => [item.label, item.value, item.note || '']),
      ) + paragraph('')
    case 'table':
      return table(block.columns, block.rows) + paragraph('')
    default:
      return ''
  }
}

export function buildReportDocx(document: ReportDocument): Blob {
  const contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    + '<Default Extension="xml" ContentType="application/xml"/>'
    + '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    + '</Types>'

  const relationships = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    + '</Relationships>'

  const body: string[] = []
  body.push(paragraph(document.title, { bold: true, size: 40, align: 'center' }))
  if (document.subtitle) body.push(paragraph(document.subtitle, { size: 20, align: 'center', color: '595959' }))
  if (document.meta && document.meta.length > 0) {
    body.push(table(['项目', '内容'], document.meta.map((item) => [item.label, item.value])))
    body.push(paragraph(''))
  }
  for (const block of document.blocks) body.push(renderBlock(block))
  body.push(paragraph(''))
  body.push(paragraph('本报告由系统按所选时间范围自动汇总生成，数据口径与页面展示一致。', { size: 18, color: '808080' }))

  const documentXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    + `<w:body>${body.join('')}`
    + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>'
    + '</w:body></w:document>'

  return buildZip([
    { name: '[Content_Types].xml', content: contentTypes },
    { name: '_rels/.rels', content: relationships },
    { name: 'word/document.xml', content: documentXml },
  ])
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  // 立刻 revoke 会让部分浏览器来不及起下载，延迟释放更稳。
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function safeFilename(parts: (string | undefined)[]): string {
  return parts
    .filter(Boolean)
    .join('-')
    .replace(/[\\/:*?"<>|\s]+/g, '_')
    .slice(0, 120)
}
