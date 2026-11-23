import { getDiagnosisSession } from "@/lib/diagnostics-proxy";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return getDiagnosisSession(request, id);
}
