import { screen, waitFor, within } from '@testing-library/react'
import type { UserEvent } from '@testing-library/user-event'

// 测试环境下 antd 的弹窗标题 id 固定为 test-id，批量套价弹窗与确认弹窗同时存在时
// 按无障碍名称查找会串台，所以按标题文本定位「确认价格变更」对话框。
export async function findPriceChangeDialog(): Promise<HTMLElement> {
  return waitFor(() => {
    const title = screen.getAllByText('确认价格变更').find(element => element.classList.contains('ant-modal-title'))
    const dialog = title?.closest('[role="dialog"]') as HTMLElement | null | undefined
    if (!dialog) throw new Error('未找到「确认价格变更」对话框')
    return dialog
  })
}

export const queryPriceChangeDialog = () => (
  screen.queryAllByText('确认价格变更').find(element => element.classList.contains('ant-modal-title')) ?? null
)

// antd 会在两个汉字的按钮文字中间插入空格（「取 消」），所以按钮名称用正则匹配。
// 找到「确认价格变更」对话框；出现「改成 0」确认复选框时先勾选，再点「确认写入」。
export async function confirmPriceChange(user: UserEvent) {
  const dialog = await findPriceChangeDialog()
  const acknowledge = within(dialog).queryByRole('checkbox', { name: /我已核对/ })
  if (acknowledge) await user.click(acknowledge)
  await user.click(within(dialog).getByRole('button', { name: /^确认写入/ }))
}

export async function cancelPriceChange(user: UserEvent) {
  const dialog = await findPriceChangeDialog()
  await user.click(within(dialog).getByRole('button', { name: /^取\s?消$/ }))
}
