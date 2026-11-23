import {apiClient} from './api'
export interface AccountMergePreview {
 source_user_id:string;target_user_id:string
 source:{username:string;role?:string;department_name?:string};target:{username:string;role?:string;department_name?:string}
 preview_version:string;required_choices:string[]
 source_identity_count:number;source_key_count:number
 billing_history:string;session_history:string
 identity_links?:{id:string;source_type:string;external_subject:string}[]
 wallets?:{user_id:string;currency:string;balance_micros:number;reserved_micros:number}[]
 personal_policies?:{user_id:string;mode:string;model_names:string[]}[]
 extra_grants?:{id:string;user_id:string;model:string;reason:string;expires_at:string|null;revoked_at:string|null}[]
}
export const userAccountMergeApi={
 preview:(target:string,source:string)=>apiClient.post<{data:AccountMergePreview}>(`/users/${encodeURIComponent(target)}/merge/preview`,{source_user_id:source}),
 merge:(target:string,source:string,version:string,choices:Record<string,string>)=>apiClient.post<{data:AccountMergePreview}>(`/users/${encodeURIComponent(target)}/merge`,{source_user_id:source,preview_version:version,choices}),
 rebind:(source:string,link:string,target:string,version:string)=>apiClient.post(`/users/${encodeURIComponent(source)}/identity-links/${encodeURIComponent(link)}/rebind`,{target_user_id:target,preview_version:version}),
}
