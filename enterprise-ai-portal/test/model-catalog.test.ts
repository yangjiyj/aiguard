import test from "node:test";
import assert from "node:assert/strict";
import {
  enrichModel,
  groupByVendor,
  filterModels,
  vendorFromId,
} from "../src/lib/model-catalog.js";

test("vendorFromId 按 id 前缀推断厂商", () => {
  assert.equal(vendorFromId("glm-5.2"), "zhipu");
  assert.equal(vendorFromId("deepseek-v3"), "deepseek");
  assert.equal(vendorFromId("qwen3-max"), "qwen");
  assert.equal(vendorFromId("claude-opus-4.7"), "anthropic");
  assert.equal(vendorFromId("gpt-5.5"), "openai");
  assert.equal(vendorFromId("codex-auto-review"), "openai");
  assert.equal(vendorFromId("doubao-seedance"), "doubao");
  assert.equal(vendorFromId("some-unknown-model"), "other");
});

test("enrichModel 从 capabilities.supports_image_input 读视觉能力", () => {
  const e = enrichModel({ id: "gpt-5.5", displayName: "GPT-5.5", capabilities: { supports_image_input: true } });
  assert.equal(e.vendorId, "openai");
  assert.equal(e.supportsImageInput, true);
});

test("enrichModel 无 capabilities → supportsImageInput 默认 false（fail-safe）", () => {
  const e = enrichModel({ id: "glm-5.2", displayName: "GLM-5.2" });
  assert.equal(e.supportsImageInput, false);
});

test("enrichModel capabilities.supports_image_input 非 true → false", () => {
  const e = enrichModel({ id: "x", displayName: "X", capabilities: { supports_image_input: false } });
  assert.equal(e.supportsImageInput, false);
});

test("groupByVendor 按 VENDORS 顺序分组、无空组", () => {
  const models = ["glm-5.2", "deepseek-v3", "qwen3-max"].map((id) =>
    enrichModel({ id, displayName: id }),
  );
  const groups = groupByVendor(models);
  assert.ok(groups.every((g) => g.models.length > 0));
  assert.deepEqual(groups.map((g) => g.vendor.id), ["zhipu", "deepseek", "qwen"]);
});

test("filterModels 按显示名大小写不敏感匹配", () => {
  const models = ["glm-5.2", "deepseek-v3"].map((id) =>
    enrichModel({ id, displayName: id }),
  );
  assert.equal(filterModels(models, "DEEP").length, 1);
  assert.equal(filterModels(models, "不可能xyz").length, 0);
  assert.equal(filterModels(models, "").length, 2);
});

test("filterModels 支持按厂商名/厂商 id 匹配", () => {
  const models = ["glm-5.2", "deepseek-v3"].map((id) =>
    enrichModel({ id, displayName: id }),
  );
  assert.equal(filterModels(models, "智谱").length, 1);
  assert.equal(filterModels(models, "zhipu").length, 1);
  assert.equal(filterModels(models, "deepseek").length, 1);
});
