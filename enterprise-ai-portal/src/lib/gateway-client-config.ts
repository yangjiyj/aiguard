import {parseGatewayEndpoints, type GatewayAccessSettings} from './gateway-access';
import {normalizeOpenAIBaseUrl} from './public-gateway-url';
function shellQuote(value:string){return "'"+value.replaceAll("'","'\\''")+"'";}
// 网关默认的明文 HTTP 端口：8080 模型 API、8082 正向代理、3000 控制台明文入口；前面没有 TLS，写成 https:// 只会得到“wrong version number”之类难懂的错误。
export const PLAINTEXT_GATEWAY_PORTS=[8080,8082,3000];
export function gatewayClientConfig(value:string,portalUrl='',settings:GatewayAccessSettings={}){
 const openai=normalizeOpenAIBaseUrl(value);const anthropic=openai.replace(/\/v1$/,'');
 const warnings:string[]=[];
 if(openai){
  const parsed=new URL(openai);
  const octets=parsed.hostname.split('.').map(Number);
  if(octets.length===4&&octets.every(n=>Number.isInteger(n)&&n>=0&&n<=255)&&(octets[0]===10||(octets[0]===172&&octets[1]>=16&&octets[1]<=31)||(octets[0]===192&&octets[1]===168)))warnings.push('调用地址为内网 IP，请确认客户端可以访问该网络。');
  if(parsed.hostname==='localhost'||(!parsed.hostname.includes('.')&&!parsed.hostname.includes(':'))||/\.(local|internal|svc)$/.test(parsed.hostname))warnings.push('调用地址包含内部主机名，请管理员确认客户端可以访问。');
  if(portalUrl.startsWith('https:')&&parsed.protocol==='http:')warnings.push('门户使用 HTTPS，但调用地址使用 HTTP，请管理员配置 HTTPS 调用地址。');
  if(parsed.protocol==='https:'&&PLAINTEXT_GATEWAY_PORTS.includes(Number(parsed.port)))warnings.push('调用地址使用 https，但端口 '+parsed.port+' 通常是网关的明文 HTTP 端口，客户端会报 TLS 握手错误。请管理员改成 http://，或确认该端口前面已配置 TLS。');
 }
 return {openai,anthropic,gemini:anthropic,warnings,access:{gateway_public_base_url:openai,gateway_public_url_mode:['configured','current_host'].includes(String(settings.gateway_public_url_mode))?String(settings.gateway_public_url_mode):'current_origin',gateway_public_endpoints:parseGatewayEndpoints(settings.gateway_public_endpoints).map(({name,url})=>({name,url}))},
  curlOpenAI:openai?`curl ${shellQuote(openai+'/chat/completions')} -H 'Authorization: Bearer YOUR_API_KEY' -H 'Content-Type: application/json' -d '{"model":"YOUR_MODEL","messages":[{"role":"user","content":"你好"}]}'`:'',
  curlAnthropic:anthropic?`curl ${shellQuote(anthropic+'/v1/messages')} -H 'x-api-key: YOUR_API_KEY' -H 'anthropic-version: 2023-06-01' -H 'Content-Type: application/json' -d '{"model":"YOUR_MODEL","max_tokens":32,"messages":[{"role":"user","content":"你好"}]}'`:'',
  curlGemini:anthropic?`curl ${shellQuote(anthropic+'/v1beta/models/YOUR_MODEL:generateContent')} -H 'x-goog-api-key: YOUR_API_KEY' -H 'Content-Type: application/json' -d '{"contents":[{"role":"user","parts":[{"text":"你好"}]}]}'`:'',
  codex:openai?`model_provider = "jjdguard"
model = "YOUR_MODEL"
[model_providers.jjdguard]
name = "JJDGuard"
base_url = ${JSON.stringify(openai)}
env_key = "JJDGUARD_API_KEY"
wire_api = "responses"`:'',
  claudeCode:anthropic?`export ANTHROPIC_BASE_URL=${shellQuote(anthropic)}
export ANTHROPIC_AUTH_TOKEN='YOUR_API_KEY'
claude --model YOUR_MODEL`:'',
 };
}
