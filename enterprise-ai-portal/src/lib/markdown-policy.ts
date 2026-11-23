/**
 * 6.8：模型输出里的 Markdown 图片会被浏览器自动请求，外链图片可把会话内容
 * 编码进 URL 带出（数据外带）。这里只放行不会产生跨域请求的来源：
 * - data:image/*（内联，不发请求）
 * - blob:（本页生成）
 * - 同源相对路径（"/x"、"./x"、"x"，但不含 "//host" 协议相对写法）
 * 其余一律视为外链，渲染为不可自动加载的占位。
 */
export function isAllowedImageSrc(src: unknown): boolean {
  if (typeof src !== "string") return false;
  const value = src.trim();
  if (!value) return false;
  // 去掉控制字符与空白后再判断 scheme，防止 "java\tscript:" / " http:" 之类绕过
  const compact = value.replace(/[\u0000-\u0020\u007f]/g, "");
  if (/^data:image\/(png|jpe?g|gif|webp|avif|bmp);/i.test(compact)) return true;
  if (/^blob:/i.test(compact)) return true;
  if (compact.startsWith("//") || compact.startsWith("\\\\") || compact.startsWith("/\\")) return false;
  // 任何显式 scheme（http:、https:、ftp:、javascript:、data:text 等）都拒绝
  if (/^[a-z][a-z0-9+.-]*:/i.test(compact)) return false;
  return true;
}
