import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import ProviderIdentity from '../components/providers/ProviderIdentity'
import deepseekLogo from '../assets/providers/deepseek.svg'
import qwenLogo from '../assets/providers/qwen.svg'

const source = readFileSync('src/pages/Providers.tsx', 'utf8')
const labelFor = (type: string) => {
  const labels = source.match(/const ptLabel: Record<string, string> = (\{[^\n]+\})/)?.[1] || ''
  if (type === 'vertex') return source.match(/ptLabel\.vertex = '([^']+)'/)![1]
  if (type === 'custom') return source.match(/\{ value: 'custom', label: '([^']+)' \}/)![1]
  return labels.match(new RegExp(`(?:^|[,{] )${type}: '([^']+)'`))?.[1] || type
}

afterEach(cleanup)

describe('ProviderIdentity', () => {
  it.each([['deepseek', deepseekLogo], ['qwen', qwenLogo]])('provider_type=%s', (providerType, logo) => {
    const { container } = render(<ProviderIdentity providerType={providerType} />)
    expect(screen.getByText(labelFor(providerType))).toBeInTheDocument()
    const image = container.querySelector('img')!
    expect(image).toHaveAttribute('src', logo)
    expect(image).toHaveAttribute('alt', '')
    expect(image.closest('.provider-identity__mark')).toHaveAttribute('aria-hidden', 'true')
    expect(image).toHaveAttribute('width', '18')
    expect(image).toHaveAttribute('height', '18')
    expect(image.src).not.toMatch(/^https?:\/\/(?!localhost(?::|\/))/)
  })

  it.each(['openai', 'anthropic', 'azure', 'bedrock', 'gemini', 'moonshot', 'kimi', 'zhipu', 'minimax', 'hunyuan', 'doubao', 'newapi', 'openrouter', 'xinference', 'vertex', 'custom'])('provider_type=%s -> API', (providerType) => {
    const { container } = render(<ProviderIdentity providerType={providerType} />)
    expect(screen.getByText(labelFor(providerType))).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('[data-icon="api"]')).not.toBeNull()
  })

  it.each([undefined, '', 'unknown-vendor', '__proto__', 'constructor', 'https://example.invalid/logo.svg'])('provider_type=%s -> API', (providerType) => {
    const { container } = render(<ProviderIdentity providerType={providerType} />)
    expect(screen.getByText('API')).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('[data-icon="api"]')).not.toBeNull()
  })

  it('provider_type != name', () => {
    const { container } = render(<ProviderIdentity providerType="custom" name="DeepSeek" strong />)
    expect(screen.getByText('DeepSeek')).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('.provider-identity')).toHaveClass('provider-identity--strong')
  })

  it('provider_type.trim().toLowerCase()', () => {
    const { container } = render(<ProviderIdentity providerType=" QWEN " name="Channel B" />)
    expect(screen.getByText('Channel B')).toBeInTheDocument()
    expect(container.querySelector('img')).toHaveAttribute('src', qwenLogo)
    expect(container.querySelector('.provider-identity')).toHaveAttribute('title', `Channel B · ${labelFor('qwen')}`)
  })

  it('name + undefined provider_type -> API', () => {
    const { container } = render(<ProviderIdentity name="DeepSeek" />)
    expect(screen.getByText('DeepSeek')).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('[data-icon="api"]')).not.toBeNull()
  })

  it('dark/light + 24px + ellipsis', () => {
    const styles = readFileSync('src/components/providers/ProviderIdentity.css', 'utf8')
    expect(styles).toContain('color: var(--text-primary)')
    expect(styles).toContain('color: var(--text-secondary)')
    expect(styles).toContain('background: var(--bg-elevated)')
    expect(styles).toContain('flex: 0 0 24px')
    expect(styles).toContain('text-overflow: ellipsis')
    expect(styles).toContain('.provider-identity__mark--brand {\n  background: #fff;')
    expect(styles).not.toMatch(/url\(\s*['"]?https?:/i)
  })

  it('SVG + MIT LICENSE', () => {
    for (const type of ['deepseek', 'qwen']) {
      const svg = readFileSync(`src/assets/providers/${type}.svg`, 'utf8')
      expect(svg).toContain('viewBox="0 0 24 24"')
      expect(svg).not.toMatch(/<script|<foreignObject|(?:href|src)=["']https?:|\son[a-z]+=/i)
    }
    const license = readFileSync('src/assets/providers/LICENSE.txt', 'utf8')
    expect(license).toContain('MIT License')
    expect(license).toContain('Copyright (c) 2023 LobeHub')
    expect(license).toContain('Brand marks remain subject to their respective owners')
    expect(readFileSync('public/provider-logos/LICENSE.txt', 'utf8')).toBe(license)
  })
})
