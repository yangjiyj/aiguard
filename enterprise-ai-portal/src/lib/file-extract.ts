// 门户文件抽取实现层：含重依赖（pdf-parse/mammoth/exceljs/adm-zip），只在服务端 API 路由用。
// 客户端组件绝不可 import 此文件（否则 adm-zip 的 fs 依赖会进客户端包）。
// 纯逻辑层（策略/分派/payload）见 ./file-policy.ts，客户端安全。

// re-export 纯逻辑层，方便 API 路由统一从本文件 import
export {
  mimeToExtractorKind,
  truncateText,
  buildIngestRequest,
  type ExtractorKind,
  type IngestRequestInput,
  type IngestRequest,
} from "./file-policy";

import { mimeToExtractorKind } from "./file-policy";

export async function extractPdfText(buffer: Buffer): Promise<string> {
  // pdf-parse 无严格类型导出，运行时 default 是可调用函数
  const mod = await import("pdf-parse");
  const PdfParse = (mod as unknown as { default: (b: Buffer) => Promise<{ text?: string }> }).default;
  const data = await PdfParse(buffer);
  return data.text ?? "";
}

export async function extractDocxText(buffer: Buffer): Promise<string> {
  const Mammoth = await import("mammoth");
  const result = await Mammoth.extractRawText({ buffer });
  return result.value ?? "";
}

export async function extractXlsxText(buffer: Buffer): Promise<string> {
  const ExcelJS = await import("exceljs");
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.load(buffer as unknown as ArrayBuffer);
  const lines: string[] = [];
  wb.eachSheet((sheet) => {
    sheet.eachRow((row) => {
      const vals = row.values as unknown[];
      if (Array.isArray(vals)) {
        lines.push(vals.slice(1).filter((v) => v != null).map(String).join("\t"));
      }
    });
  });
  return lines.join("\n");
}

export async function extractPptxText(buffer: Buffer): Promise<string> {
  const AdmZip = (await import("adm-zip")).default;
  const zip = new AdmZip(buffer);
  const entries = zip.getEntries().filter((e: { entryName: string }) =>
    /^ppt\/slides\/slide\d+\.xml$/.test(e.entryName),
  );
  const texts: string[] = [];
  for (const entry of entries) {
    const xml: string = entry.getData().toString("utf8");
    const matches = xml.match(/<a:t>([^<]*)<\/a:t>/g) ?? [];
    texts.push(matches.map((m) => m.replace(/<\/?a:t>/g, "")).join(" "));
  }
  return texts.join("\n");
}

export async function extractPlainText(buffer: Buffer): Promise<string> {
  return buffer.toString("utf8");
}

/** 按 mime 分派到抽取器；unsupported 返回空串（调用方决定是否拒绝） */
export async function extractFileText(buffer: Buffer, mime: string): Promise<string> {
  const kind = mimeToExtractorKind(mime);
  switch (kind) {
    case "pdf": return extractPdfText(buffer);
    case "docx": return extractDocxText(buffer);
    case "xlsx": return extractXlsxText(buffer);
    case "pptx": return extractPptxText(buffer);
    case "text": return extractPlainText(buffer);
    default: return "";
  }
}
