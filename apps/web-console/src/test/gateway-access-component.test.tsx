import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {act,fireEvent,render,screen,waitFor} from '@testing-library/react'
import GatewayAccess from '../components/GatewayAccess'
import {useGatewayAccess} from '../hooks/useGatewayAccess'
const copy=vi.fn()
function Harness(){const access=useGatewayAccess({gateway_public_base_url:'https://customer.example/custom/v1'});return <GatewayAccess access={access} onCopy={copy}/>}
describe('gateway access browser check',()=>{
 beforeEach(()=>{localStorage.clear();copy.mockReset()})
 afterEach(()=>{vi.unstubAllGlobals();localStorage.clear()})
 it('checks the actual current origin without sending login credentials or API keys',async()=>{
  const fetch=vi.fn().mockResolvedValue({status:401,json:async()=>({error:{code:'unauthorized'}})});vi.stubGlobal('fetch',fetch)
  render(<Harness/>);fireEvent.click(screen.getByRole('button',{name:'检查当前入口'}))
  await screen.findByText(/当前浏览器已连接到网关模型接口/)
  expect(fetch).toHaveBeenCalledWith(window.location.origin+'/v1/models',expect.objectContaining({credentials:'omit',redirect:'error'}))
  expect(fetch.mock.calls[0][1].headers).toBeUndefined()
  fireEvent.click(screen.getByRole('button',{name:/^(?:copy)?复制$/}));expect(copy).toHaveBeenCalledWith(window.location.origin+'/v1')
 })
 it('switches to a configured domain and discards stale network success',async()=>{
  let finish!:(r:unknown)=>void;vi.stubGlobal('fetch',vi.fn().mockReturnValue(new Promise(resolve=>{finish=resolve})))
  render(<Harness/>);fireEvent.click(screen.getByRole('button',{name:'检查当前入口'}))
  act(()=>{localStorage.setItem('jjdguard.gateway.endpoint','https://customer.example/custom/v1');window.dispatchEvent(new Event('jjdguard-gateway-endpoint-change'))})
  expect(screen.getByRole('link',{name:'打开接口检查'})).toHaveAttribute('href','https://customer.example/custom/v1/models')
  await act(async()=>{finish({status:401,json:async()=>({error:{code:'unauthorized'}})})})
  await waitFor(()=>expect(screen.queryByText(/当前浏览器已连接到网关模型接口/)).toBeNull())
 })
})
