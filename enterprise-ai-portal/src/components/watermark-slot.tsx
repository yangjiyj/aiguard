import { connection } from "next/server";
import { Watermark } from "@/components/watermark";
import { watermarkConfig } from "@/lib/watermark";

/**
 * 服务端插槽：在请求期读取 PORTAL_WATERMARK*（connection() 保证不在构建期固化），
 * 再交给客户端水印层按会话身份渲染。
 */
export async function WatermarkSlot() {
  await connection();
  const config = watermarkConfig();
  return <Watermark enabled={config.enabled} extra={config.extra} />;
}
