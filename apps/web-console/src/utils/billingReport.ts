import type { Dayjs } from 'dayjs'
import type { BillingAnalyticsParams } from '../services/api'

export type BillingReportFilters = {
  range: [Dayjs, Dayjs]
  departmentIds: string[]
  projectIds: string[]
  userIds: string[]
  modelIds: string[]
  providerIds: string[]
  agentTypes: string[]
}

export function buildBillingReportParams(filters: BillingReportFilters): BillingAnalyticsParams {
  const joined = (values: string[]) => values.length ? values.join(',') : undefined
  return {
    start_date: filters.range[0].format('YYYY-MM-DD'),
    end_date: filters.range[1].format('YYYY-MM-DD'),
    department_ids: joined(filters.departmentIds),
    project_ids: joined(filters.projectIds),
    user_ids: joined(filters.userIds),
    model_ids: joined(filters.modelIds),
    provider_ids: joined(filters.providerIds),
    agent_types: joined(filters.agentTypes),
  }
}
