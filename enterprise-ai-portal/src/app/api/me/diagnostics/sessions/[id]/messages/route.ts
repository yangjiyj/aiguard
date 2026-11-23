import { addDiagnosisMessage } from "@/lib/diagnostics-proxy";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return addDiagnosisMessage(request, id);
}
