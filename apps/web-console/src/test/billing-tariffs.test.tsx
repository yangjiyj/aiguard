import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import TariffPlanEditor from '../components/billing/TariffPlanEditor'
import { buildTariffTemplate, hasLegacyTariffDates, minuteToTime, newTariffRule, rulesFromPlan, serializeTariffRules, tariffEditorCopy as copy, tariffTemplateOptions, validateEditorRules } from '../components/billing/tariffTemplates'

afterEach(cleanup)
const models = [{ value: 'model-a', label: 'Model A' }, { value: 'model-b', label: 'Model B' }]
const planFromRules=(rules: ReturnType<typeof newTariffRule>[],status='draft')=>({name:'weekly-plan',version:1,status,timezone:'Asia/Shanghai',rules:serializeTariffRules(rules)})

describe('weekly tariff templates and boundaries', () => {
  it('covers every minute for every weekday and every selected model', () => {
    for (const template of tariffTemplateOptions) {
      const rules = buildTariffTemplate(template.value, ['model-a', 'model-b', 'model-a'])
      expect(validateEditorRules(rules)).toBe('')
      expect(rules.every(rule=>!rule.special_date)).toBe(true)
      for (const model of ['model-a', 'model-b']) for (const day of [1,2,3,4,5,6,7]) {
        const serialized=serializeTariffRules(rules.filter(rule=>rule.model_name===model&&rule.weekdays.includes(day)))
        for(let minute=0;minute<1440;minute++) expect(serialized.filter(rule=>rule.start_minute<=minute&&minute<rule.end_minute)).toHaveLength(1)
      }
    }
  })
  it('detects overlaps across Sunday midnight and accepts half-open adjacent periods', () => {
    const overlap=[newTariffRule('model-a',{name:'crossing',weekdays:[7],start_time:'23:45',end_time:'00:15'}),newTariffRule('model-a',{name:'monday',weekdays:[1],start_time:'00:10',end_time:'00:20'})]
    expect(validateEditorRules(overlap)).not.toBe('')
    expect(validateEditorRules([overlap[0],newTariffRule('model-a',{name:'monday',weekdays:[1],start_time:'00:15',end_time:'00:20'})])).toBe('')
    expect(validateEditorRules([newTariffRule('model-a',{end_time:'18:00junk'})])).not.toBe('')
    expect(minuteToTime(1439)).toBe('23:59')
    expect(minuteToTime(1440)).toBe('24:00')
  })
  it('preserves exact historical dates and multipliers for read-only inspection', () => {
    const original={rules:[{model_name:'model-a',name:'historical',band:'valley',weekdays:[4],start_minute:1439,end_minute:1440,special_date:'2026-10-01T00:00:00Z',multiplier_ppm:712345}]}
    const loaded=rulesFromPlan(original)
    expect(hasLegacyTariffDates(original)).toBe(true)
    expect(loaded[0]).toMatchObject({start_time:'23:59',end_time:'24:00',special_date:'2026-10-01',multiplier:0.712345})
    expect(()=>serializeTariffRules(loaded)).toThrow()
  })
})

describe('weekly tariff editor workflow', () => {
  it('applies a template to multiple models and ignores obsolete calendar inputs', async () => {
    const user=userEvent.setup(),save=vi.fn()
    render(<TariffPlanEditor open modelOptions={models} loading={false} onCancel={vi.fn()} onSave={save} {...{holidayYears:[{year:2026,builtin:true,holidays:[{date:'2026-10-01'}],workdays:[]}],holidayError:true}} />)
    expect(screen.queryByTestId('holidays-calendar')).not.toBeInTheDocument()
    expect(screen.queryByTestId('workdays-calendar')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button',{name:copy.selectAll}))
    await user.click(screen.getByRole('button',{name:copy.apply(2)}))
    await user.click(screen.getByRole('button',{name:copy.publish}))
    expect(save).toHaveBeenCalledOnce()
    const [payload,publish]=save.mock.calls[0]
    expect(publish).toBe(true)
    expect(payload.rules).toHaveLength(8)
    expect(payload.rules.every((rule:any)=>!Object.prototype.hasOwnProperty.call(rule,'special_date'))).toBe(true)
    expect(new Set(payload.rules.map((rule:any)=>rule.model_name))).toEqual(new Set(['model-a','model-b']))
  })
  it('creates a new draft version without modifying the other model', async () => {
    const user=userEvent.setup(),save=vi.fn()
    render(<TariffPlanEditor open plan={planFromRules([newTariffRule('model-a'),newTariffRule('model-b')],'active')} modelOptions={models} loading={false} onCancel={vi.fn()} onSave={save} />)
    await user.clear(screen.getByLabelText(copy.multiplier(1)))
    await user.type(screen.getByLabelText(copy.multiplier(1)),'0.6')
    await user.click(screen.getByRole('button',{name:copy.saveVersion}))
    expect(save.mock.calls[0][0].rules).toEqual(expect.arrayContaining([expect.objectContaining({model_name:'model-a',multiplier_ppm:600000}),expect.objectContaining({model_name:'model-b',multiplier_ppm:1000000})]))
    expect(save.mock.calls[0][1]).toBe(false)
  })
  it('refuses overlapping new periods and shows an error', async () => {
    const user=userEvent.setup(),save=vi.fn()
    render(<TariffPlanEditor open modelOptions={models} loading={false} onCancel={vi.fn()} onSave={save} />)
    await user.click(screen.getByRole('button',{name:copy.addPeriod}))
    await user.click(screen.getByRole('button',{name:copy.saveDraft}))
    expect(save).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })
  it('copies an adjusted model schedule without duplicate rules', async () => {
    const user=userEvent.setup(),save=vi.fn()
    render(<TariffPlanEditor open plan={planFromRules([newTariffRule('model-a'),newTariffRule('model-b')])} modelOptions={models} loading={false} onCancel={vi.fn()} onSave={save} />)
    await user.clear(screen.getByLabelText(copy.multiplier(1)))
    await user.type(screen.getByLabelText(copy.multiplier(1)),'0.8')
    await user.click(screen.getByRole('button',{name:copy.selectAll}))
    await user.click(screen.getByRole('button',{name:copy.copySchedule}))
    await user.click(screen.getByRole('button',{name:copy.saveDraft}))
    expect(save.mock.calls[0][0].rules).toHaveLength(2)
    expect(save.mock.calls[0][0].rules.every((rule:any)=>rule.multiplier_ppm===800000)).toBe(true)
  })
  it('commits the final minute through the HH:mm picker and keeps following midnight', async () => {
    const user=userEvent.setup(),save=vi.fn()
    render(<TariffPlanEditor open plan={planFromRules([newTariffRule('model-a',{weekdays:[1],start_time:'23:58',end_time:'24:00'})])} modelOptions={models} loading={false} onCancel={vi.fn()} onSave={save} />)
    const start=screen.getByLabelText(copy.start(1))
    expect(screen.getByLabelText(copy.end(1))).toHaveValue('00:00')
    await user.clear(start);await user.type(start,'23:59');await user.keyboard('{Enter}')
    await user.click(screen.getByRole('button',{name:copy.saveDraft}))
    expect(save).toHaveBeenCalledOnce()
    expect(save.mock.calls[0][0].rules[0]).toMatchObject({start_minute:1439,end_minute:1440,weekdays:[1]})
  })
  it.each(['draft','active','retired'])('makes a %s date plan read-only even when the date belongs to a hidden model', async status => {
    const user=userEvent.setup(),save=vi.fn()
    const plan={name:'historical-plan',version:3,status,timezone:'UTC',rules:[...serializeTariffRules([newTariffRule('model-a')]),{model_name:'model-b',name:'historical-date',band:'valley',special_date:'2026-10-01T00:00:00Z',weekdays:[4],start_minute:1439,end_minute:1440,multiplier_ppm:712345}]}
    render(<TariffPlanEditor open plan={plan} modelOptions={models} loading={false} onCancel={vi.fn()} onSave={save} />)
    expect(screen.getByTestId('legacy-tariff-read-only')).toBeInTheDocument()
    expect(screen.queryByRole('button',{name:copy.publish})).not.toBeInTheDocument()
    expect(screen.queryByRole('button',{name:copy.saveVersion})).not.toBeInTheDocument()
    expect(screen.queryByRole('button',{name:copy.saveDraft})).not.toBeInTheDocument()
    expect(screen.queryByRole('button',{name:copy.copySchedule})).not.toBeInTheDocument()
    expect(screen.getByLabelText(copy.start(1))).toBeDisabled()
    await user.click(screen.getByRole('combobox',{name:copy.editModel}))
    await user.click(screen.getByText('Model B',{selector:'.ant-select-item-option-content'}))
    expect(screen.getByLabelText(copy.legacyDate(1))).toHaveValue('2026-10-01')
    expect(screen.getByLabelText(copy.legacyDate(1))).toHaveAttribute('readonly')
    expect(screen.getByLabelText(copy.multiplier(1))).toHaveValue('0.712345')
    expect(save).not.toHaveBeenCalled()
  })
})
