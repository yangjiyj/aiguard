import { describe, expect, it } from "vitest"
import { getRiskCategoryLabel } from "../utils/risk"
import { getStaticCapabilityLabel } from "../utils/securityCapabilityLabels"

describe("specific semantic risk labels", () => {
  it.each([
    ["semantic_harassment", "语义骚扰"],
    ["semantic_threat", "语义威胁"],
    ["semantic_hate", "语义仇恨"],
    ["semantic_instruction_override", "语义指令篡改"],
  ])("maps %s to %s", (category, label) => {
    expect(getRiskCategoryLabel(category)).toBe(label)
  })
})

describe("内置辱骂脏话能力名称", () => {
  it.each([
    ["content_profanity_abuse", "辱骂脏话"],
    ["harassment_profanity_cn", "中文强辱骂组合"],
  ])("%s 有中文名称，不暴露内部 key", (category, label) => {
    expect(getRiskCategoryLabel(category)).toBe(label)
    expect(getStaticCapabilityLabel(category)).toBe(label)
  })
})
