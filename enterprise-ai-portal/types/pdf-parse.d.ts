declare module "pdf-parse" {
  const pdfParse: (data: Buffer | string) => Promise<{ text: string; numpages: number; info: unknown }>;
  export default pdfParse;
}
