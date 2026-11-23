import { employeeKeyRequest } from '@/lib/employee-key-service';

export async function GET(request:Request) {
  return employeeKeyRequest(request,'metadata');
}
