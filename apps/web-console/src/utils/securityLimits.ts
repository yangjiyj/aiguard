// 与后端校验一致的取值范围与默认值（runtimeoptions、file_policy.go、semantic_effective_config.go）。

export const OUTPUT_STRICT_MAX_BYTES = { min: 1024, max: 64 * 1024 * 1024 } as const

export const DEFAULT_CONFIDENCE_THRESHOLD = 0.55

export type ZipLimitField = 'max_zip_entries' | 'max_zip_uncompressed_mb' | 'max_zip_nested'

export const ZIP_LIMITS: ReadonlyArray<{ field: ZipLimitField; label: string; max: number }> = [
  { field: 'max_zip_entries', label: '条目数上限', max: 100000 },
  { field: 'max_zip_uncompressed_mb', label: '解压后上限（MB）', max: 10240 },
  { field: 'max_zip_nested', label: '嵌套层数上限', max: 100 },
]

export const FILE_LIMITS = {
  max_file_mb: { min: 1, max: 100 },
  max_attachments: { min: 1, max: 100 },
  max_zip_ratio: { min: 1, max: 1000 },
} as const
