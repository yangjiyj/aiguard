import {useGatewayAccess} from '../hooks/useGatewayAccess'
import { useEffect, useRef, useState } from 'react'
import { Button, Select, Space, Typography } from 'antd'
import { CopyOutlined } from '@ant-design/icons'
import { inspectGatewayResponse } from '../utils/gatewayAccess'
import ClientBaseUrlGuide from './ClientBaseUrlGuide'
export default function GatewayAccess({ access, onCopy, showClientGuide = true }: { access: ReturnType<typeof useGatewayAccess>; onCopy?: (value: string) => unknown; showClientGuide?: boolean }) {
  const [checking, setChecking] = useState(false)
  const [notice, setNotice] = useState<{ok:boolean;message:string}|null>(null)
  const sequence = useRef({current:0,active:true})
  useEffect(() => { const state={current:0,active:true};sequence.current=state;setNotice(null);setChecking(false);return ()=>{state.active=false} }, [access.url])
  const local = access.url && new URL(access.url).origin === window.location.origin
  const check = async () => {
    const state=sequence.current
    const requestSequence = ++state.current
    setChecking(true);setNotice(null)
    try {
      // No session cookie, bearer token or API Key is sent by this network check.
      const response = await fetch(access.url + '/models', { credentials:'omit', redirect:'error', cache:'no-store', signal:AbortSignal.timeout(8000) })
      const result = inspectGatewayResponse(response.status, await response.json().catch(() => null))
      if(requestSequence===state.current && state.active)setNotice(result)
    } catch { if(requestSequence===state.current && state.active)setNotice({ok:false,message:'当前浏览器无法访问此入口，请检查网络、域名解析、HTTPS 证书及转发路径。'}) }
    finally { if(requestSequence===state.current && state.active)setChecking(false) }
  }
  return <Space direction="vertical" size={8} style={{width:'100%'}}>
    <Select aria-label="调用入口" value={access.url || undefined} onChange={access.select} style={{width:'100%'}} options={access.options.map(e=>({value:e.url,label:`${e.name} · ${e.url}`}))}/>
    <Space wrap><Typography.Text code>{access.url}</Typography.Text>
      {onCopy && <Button size="small" icon={<CopyOutlined />} onClick={()=>void onCopy(access.url)}>复制</Button>}
      {local ? <Button size="small" loading={checking} onClick={()=>void check()}>检查当前入口</Button> : <a href={access.url+'/models'} target="_blank" rel="noreferrer">打开接口检查</a>}
    </Space>
    <Typography.Text type="secondary" style={{fontSize:12}}>按调用客户端所在网络选择入口；切换会同步更新本机的调用示例。HTTPS 证书须被客户端信任。</Typography.Text>
    {notice && <Typography.Text role="status" type={notice.ok?'success':'danger'}>{notice.message}</Typography.Text>}
    {showClientGuide && access.url && <ClientBaseUrlGuide url={access.url} onCopy={onCopy} omitOpenAIAddress/>}
  </Space>
}
