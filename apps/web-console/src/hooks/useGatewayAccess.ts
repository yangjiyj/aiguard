import {useEffect,useState} from 'react'
import {chooseGatewayEndpoint,gatewayAccessOptions,type GatewayAccessSettings} from '../utils/gatewayAccess'
const selectionKey = 'jjdguard.gateway.endpoint'
const eventName = 'jjdguard-gateway-endpoint-change'
const readPreference = () => { try { return localStorage.getItem(selectionKey) || '' } catch { return '' } }
export function useGatewayAccess(settings: GatewayAccessSettings = {}) {
  const [preferred, setPreferred] = useState(readPreference)
  useEffect(() => {
    const update = () => setPreferred(readPreference())
    window.addEventListener('storage', update); window.addEventListener(eventName, update)
    return () => { window.removeEventListener('storage', update); window.removeEventListener(eventName, update) }
  }, [])
  const options = gatewayAccessOptions(settings, window.location.origin)
  const url = chooseGatewayEndpoint(options, settings, preferred)
  const select = (value: string) => {
    setPreferred(value)
    try { localStorage.setItem(selectionKey, value); window.dispatchEvent(new Event(eventName)) } catch { /* Selection still works when storage is unavailable. */ }
  }
  return { options, url, select }
}
