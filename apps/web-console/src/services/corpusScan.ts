import { apiClient } from './api'

// 训练语料扫描（规格第 5 节）：分片上传到控制面，后台扫描，生成报告和脱敏副本。
export const CORPUS_CHUNK_BYTES = 8 * 1024 * 1024
// 单个分片的上传预算：慢速链路上 8 MiB 也要能传完，与控制面放宽后的请求超时一致。
const CHUNK_TIMEOUT_MS = 10 * 60 * 1000

export type CorpusScanStatus = 'uploading' | 'queued' | 'running' | 'succeeded' | 'failed' | 'canceled' | 'interrupted'

export interface CorpusTypeStat { type: string; label: string; hits: number; records: number }
export interface CorpusSample { line: number; field: string; type: string; label: string; start: number; end: number; preview: string }
export interface CorpusUnscannedLine { line: number; reason: string }

export interface CorpusScanJob {
  job_id: string
  created_by: string
  file_name: string
  format: string
  size_bytes: number
  sha256: string
  status: CorpusScanStatus
  error_code: string
  cancel_requested: boolean
  uploaded_bytes: number
  next_chunk: number
  processed_bytes: number
  total_records: number
  scanned_records: number
  hit_records: number
  unscanned_records: number
  incomplete_records: number
  stats: CorpusTypeStat[]
  samples: CorpusSample[]
  unscanned: CorpusUnscannedLine[]
  notes: string[]
  masked_format: string
  rule_pack_version: string
  has_report: boolean
  has_masked: boolean
  expires_at: string
  created_at: string
  updated_at: string
  started_at: string | null
  completed_at: string | null
}

export const corpusScanApi = {
  list: () => apiClient.get<{ items: CorpusScanJob[]; local_storage: boolean }>('/security/corpus-scans'),
  get: (id: string) => apiClient.get<CorpusScanJob>(`/security/corpus-scans/${encodeURIComponent(id)}`),
  create: (data: { file_name: string; size_bytes: number; sha256: string }) =>
    apiClient.post<{ job_id: string; job: CorpusScanJob; chunk_size: number }>('/security/corpus-scans', data),
  uploadChunk: (id: string, index: number, chunk: Blob) =>
    apiClient.put<CorpusScanJob>(`/security/corpus-scans/${encodeURIComponent(id)}/chunks/${index}`, chunk, {
      headers: { 'Content-Type': 'application/octet-stream' },
      timeout: CHUNK_TIMEOUT_MS,
    }),
  start: (id: string) => apiClient.post<CorpusScanJob>(`/security/corpus-scans/${encodeURIComponent(id)}/start`),
  cancel: (id: string) => apiClient.post<CorpusScanJob>(`/security/corpus-scans/${encodeURIComponent(id)}/cancel`),
  remove: (id: string) => apiClient.delete<{ deleted: string }>(`/security/corpus-scans/${encodeURIComponent(id)}`),
}

// 下载走同源链接：浏览器带会话 cookie，文件不读进页面内存。
export const corpusDownloadUrl = (id: string, kind: 'report' | 'masked') =>
  `/admin/v1/security/corpus-scans/${encodeURIComponent(id)}/${kind}`

// —— SHA-256（流式，不把整个文件读进内存）——
// 浏览器的 crypto.subtle.digest 只能一次性处理整块数据，2 GB 文件会占满内存，所以这里按分片增量计算。

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

export class Sha256 {
  private h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])
  private block = new Uint8Array(64)
  private blockLength = 0
  private totalBytes = 0
  private w = new Uint32Array(64)

  update(data: Uint8Array): this {
    this.totalBytes += data.length
    let offset = 0
    if (this.blockLength > 0) {
      const take = Math.min(64 - this.blockLength, data.length)
      this.block.set(data.subarray(0, take), this.blockLength)
      this.blockLength += take
      offset = take
      if (this.blockLength === 64) {
        this.compress(this.block, 0)
        this.blockLength = 0
      }
    }
    while (offset + 64 <= data.length) {
      this.compress(data, offset)
      offset += 64
    }
    if (offset < data.length) {
      this.block.set(data.subarray(offset), 0)
      this.blockLength = data.length - offset
    }
    return this
  }

  hex(): string {
    const bits = this.totalBytes * 8
    // 0x80 + 0 填充到 56 (mod 64) + 8 字节大端位长度。
    const padLength = (this.blockLength < 56 ? 56 : 120) - this.blockLength
    const padding = new Uint8Array(padLength + 8)
    padding[0] = 0x80
    const view = new DataView(padding.buffer)
    view.setUint32(padLength, Math.floor(bits / 0x100000000))
    view.setUint32(padLength + 4, bits >>> 0)
    this.update(padding)
    return Array.from(this.h, (word) => word.toString(16).padStart(8, '0')).join('')
  }

  private compress(data: Uint8Array, offset: number) {
    const w = this.w
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4
      w[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3]
    }
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], b = w[i - 2]
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0
    }
    let [a, b, c, d, e, f, g, h] = this.h
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))
      const ch = (e & f) ^ (~e & g)
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) | 0
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0
    }
    this.h[0] += a; this.h[1] += b; this.h[2] += c; this.h[3] += d
    this.h[4] += e; this.h[5] += f; this.h[6] += g; this.h[7] += h
  }
}

const readBytes = async (blob: Blob) => new Uint8Array(await blob.arrayBuffer())

export async function sha256Hex(file: Blob, onProgress?: (done: number) => void): Promise<string> {
  const hash = new Sha256()
  for (let offset = 0; offset < file.size; offset += CORPUS_CHUNK_BYTES) {
    hash.update(await readBytes(file.slice(offset, offset + CORPUS_CHUNK_BYTES)))
    onProgress?.(Math.min(file.size, offset + CORPUS_CHUNK_BYTES))
  }
  return hash.hex()
}

type CorpusUploadApi = Pick<typeof corpusScanApi, 'create' | 'uploadChunk' | 'start' | 'cancel'>

// 计算 sha256、建任务、顺序上传分片、开始扫描。返回任务编号。
export async function uploadCorpusFile(
  file: File,
  onUpload: (uploaded: number) => void,
  onHash?: (hashed: number) => void,
  signal?: AbortSignal,
  api: CorpusUploadApi = corpusScanApi,
): Promise<string> {
  const digest = await sha256Hex(file, onHash)
  if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
  const created = await api.create({ file_name: file.name, size_bytes: file.size, sha256: digest })
  const id = created.data.job_id
  const chunkSize = Math.min(created.data.chunk_size || CORPUS_CHUNK_BYTES, CORPUS_CHUNK_BYTES)
  let index = 0
  for (let offset = 0; offset < file.size; offset += chunkSize, index++) {
    if (signal?.aborted) {
      await api.cancel(id).catch(() => undefined)
      throw new DOMException('aborted', 'AbortError')
    }
    await api.uploadChunk(id, index, file.slice(offset, offset + chunkSize))
    onUpload(Math.min(file.size, offset + chunkSize))
  }
  await api.start(id)
  return id
}
