import { useEffect, useState } from 'react'
import { productApi } from '../services/api'

export type ProductProfile = 'gateway' | 'agent-platform'

export interface ProductIdentity {
  profile: ProductProfile
  name: string
  version?: string
}

const DEFAULT_PRODUCT: ProductIdentity = { profile: 'gateway', name: 'JJDGuard' }

export function resolveProductIdentity(data?: { product_profile?: string; product_name?: string; product_version?: string }): ProductIdentity {
  // Gateway console has a fixed product identity. Platform is a separate build,
  // service, login and database; stale env/server profiles cannot switch it.
  return { ...DEFAULT_PRODUCT, version: data?.product_version }

}

export function useProductIdentity(): ProductIdentity {
  const [product, setProduct] = useState<ProductIdentity>(() => resolveProductIdentity())

  useEffect(() => {
    let active = true
    productApi.get().then(({ data }) => {
      if (active) setProduct(resolveProductIdentity(data))
    }).catch(() => {
      if (active) setProduct(resolveProductIdentity())
    })
    return () => { active = false }
  }, [])
  return product
}

export const productCopy = {
  gateway: {
    title: 'JJDGuard',
    subtitle: 'AI 算力安全网关',
    homeEyebrow: '模型网关与审计',
    homeDescription: '统一查看经网关的模型访问、Token 消耗、智能体行为和检测统计；用量、费用及各维度统计的时间范围在对应 Tab 内切换。',
  },
  'agent-platform': {
    title: 'JJDGuard Agent Platform',
    subtitle: '智能体安全平台',
    homeEyebrow: '智能体安全与模型网关',
    homeDescription: '基于已有网关与端点管理接口查看模型访问、端点状态和安全告警；未接入的端侧能力不展示为已生效。',
  },
} as const
