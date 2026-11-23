import { useState, type ReactNode } from 'react'
import { Button } from 'antd'
import { DownOutlined, FilterOutlined, RightOutlined } from '@ant-design/icons'

type CollapsibleFiltersProps = {
  id: string
  primary: ReactNode
  advanced: ReactNode
  advancedActiveCount?: number
}

export default function CollapsibleFilters({ id, primary, advanced, advancedActiveCount = 0 }: CollapsibleFiltersProps) {
  const [open, setOpen] = useState(false)
  const buttonLabel = advancedActiveCount > 0 ? `高级筛选（已启用 ${advancedActiveCount}）` : '高级筛选'

  return (
    <div className="collapsible-filters">
      <div className="collapsible-filters-primary">
        {primary}
        <Button
          type="text"
          icon={<FilterOutlined />}
          aria-expanded={open}
          aria-controls={id}
          onClick={() => setOpen((value) => !value)}
        >
          {buttonLabel} {open ? <DownOutlined /> : <RightOutlined />}
        </Button>
      </div>
      {open ? <div className="collapsible-filters-advanced" id={id}>{advanced}</div> : null}
    </div>
  )
}
