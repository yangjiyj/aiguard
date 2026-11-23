// 门户文件抽取的纯逻辑层：无 React、无 IO、无重依赖（客户端安全，可被 composer 组件 import）。
// 浏览器提交的 MIME 仅用于选择最佳努力的文本抽取器；文件类型门禁必须由控制面在真实字节上判定。

export type ExtractorKind = "pdf" | "docx" | "xlsx" | "pptx" | "text" | "unsupported";

const DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
const PPTX_MIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation";

export function mimeToExtractorKind(mime: string): ExtractorKind {
  const m = (mime || "").toLowerCase();
  if (m === "application/pdf") return "pdf";
  if (m === DOCX_MIME) return "docx";
  if (m === XLSX_MIME) return "xlsx";
  if (m === PPTX_MIME) return "pptx";
  if (
    m.startsWith("text/") ||
    m === "application/json" ||
    m === "application/xml" ||
    m === "application/javascript" ||
    m === "application/x-yaml"
  ) {
    return "text";
  }
  return "unsupported";
}

export function truncateText(s: string, max: number): string {
  const r = [...s];
  if (r.length <= max) return s;
  return r.slice(0, max).join("") + "…";
}

export type IngestRequestInput = {
  filename: string;
  mime: string;
  size: number;
  sha256: string;
  bytesBase64: string;
  extractedText: string;
  model?: string;
};

export type IngestRequest = {
  user_id?: string;
  filename: string;
  mime_type: string;
  size: number;
  sha256: string;
  bytes_base64: string;
  extracted_text: string;
  model?: string;
};

export function buildIngestRequest(input: IngestRequestInput): IngestRequest {
  return {
    filename: input.filename,
    mime_type: input.mime,
    size: input.size,
    sha256: input.sha256,
    bytes_base64: input.bytesBase64,
    extracted_text: input.extractedText,
    model: input.model,
  };
}
