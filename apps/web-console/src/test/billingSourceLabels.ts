import { WALLET_MANAGEMENT_LABELS } from '../components/billing/WalletManagement'
import prepaidSource from '../components/billing/sections/usePrepaidSection.tsx?raw'
import statementsSource from '../pages/billing/Statements.tsx?raw'
import ledgerSource from '../components/billing/sections/useStatementsSection.tsx?raw'

export const literal = (source: string, pattern: RegExp, group = 1) => {
  const match = source.match(pattern)
  if (!match) throw new Error('Expected production UI label was not found')
  return match[group]
}
export const billingSourceLabels = {
  accounts: WALLET_MANAGEMENT_LABELS.accounts,
  groups: WALLET_MANAGEMENT_LABELS.groups,
  credit: literal(prepaidSource, /<Modal title="([^"]+)"[^>]*open=\{creditOpen\}/),
  adjust: literal(prepaidSource, /<Modal title="([^"]+)"[^>]*open=\{adjustOpen\}/),
  statement: literal(statementsSource, /key: 'statement', label: '([^']+)'/),
  ledger: literal(ledgerSource, /key: 'ledger', label: '([^']+)'/),
  balance: literal(prepaidSource, /title: '([^']+)', dataIndex: 'balance_micros'/),
  redemption: literal(prepaidSource, /<Modal title="([^"]+)"[^>]*open=\{redemptionOpen\}/),
}
export const sourceRegex = (value: string) => new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
