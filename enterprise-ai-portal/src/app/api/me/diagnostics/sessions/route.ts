import { createDiagnosisSession, listDiagnosisSessions } from "@/lib/diagnostics-proxy";

export const GET = listDiagnosisSessions;
export const POST = createDiagnosisSession;
