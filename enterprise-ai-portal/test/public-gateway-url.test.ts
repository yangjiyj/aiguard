import test from "node:test";
import assert from "node:assert/strict";

import {
  normalizeOpenAIBaseUrl,
  resolvePublicGatewayUrl,
} from "../src/lib/public-gateway-url.js";

test("configured gateway URL is normalized to exactly one /v1 suffix", () => {
  assert.equal(normalizeOpenAIBaseUrl("http://gateway.test:8080"), "http://gateway.test:8080/v1");
  assert.equal(normalizeOpenAIBaseUrl("http://gateway.test:8080/v1/"), "http://gateway.test:8080/v1");
  assert.equal(normalizeOpenAIBaseUrl("http://gateway.test:8080/v1/v1"), "http://gateway.test:8080/v1");
});

test("unset gateway coordinate falls through to the control-plane system setting", () => {
  assert.equal(resolvePublicGatewayUrl({
    GATEWAY_PUBLIC_URL: "",
    PORTAL_PUBLIC_URL: "http://100.64.0.21/chat",
  }), "");
});

test("explicit gateway URL wins and invalid or absent values fail closed", () => {
  assert.equal(resolvePublicGatewayUrl({
    GATEWAY_PUBLIC_URL: " https://api.example.test/custom/v1 ",
    PORTAL_PUBLIC_URL: "https://portal.example.test/chat",
  }), "https://api.example.test/custom/v1");
  assert.equal(resolvePublicGatewayUrl({
    GATEWAY_PUBLIC_URL: "not-a-url",
    PORTAL_PUBLIC_URL: "also-not-a-url",
  }), "");
  assert.equal(resolvePublicGatewayUrl({}), "");
});

test('unconfigured gateway does not derive a container coordinate from the portal',()=>{
 assert.equal(resolvePublicGatewayUrl({PORTAL_PUBLIC_URL:'http://chat-edge:8180/chat'}),'');
});
