import {personalKeysRequest} from '@/lib/personal-keys';
export async function POST(request:Request,context:{params:Promise<{id:string}>}){
 return personalKeysRequest(request,(await context.params).id);
}
