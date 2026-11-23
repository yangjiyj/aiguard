import {employeeKeyRequest} from '@/lib/employee-key-service';
export async function POST(request:Request){return employeeKeyRequest(request,'ensure');}
