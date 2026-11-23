import http from "k6/http";
import { check } from "k6";

const baseURL = (__ENV.BASE_URL || "http://127.0.0.1:8080").replace(/\/$/, "");
const token = __ENV.API_KEY || "load-test-key";
const duration = __ENV.DURATION || "30s";

export const options = {
  scenarios: {
    sustained_sse_500: {
      executor: "constant-vus",
      vus: Number(__ENV.VUS || 500),
      duration,
      exec: "chatResponses",
    },
    native_responses: {
      executor: "constant-vus",
      vus: Number(__ENV.NATIVE_RESPONSES_VUS || 1),
      duration,
      exec: "nativeResponses",
      startTime: "1s",
    },
    native_messages: {
      executor: "constant-vus",
      vus: Number(__ENV.NATIVE_MESSAGES_VUS || 1),
      duration,
      exec: "nativeMessages",
      startTime: "1s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.05"],
    http_req_waiting: ["p(95)<2000"],
  },
};

function request(path, body, protocol) {
  const response = http.post(baseURL + path, JSON.stringify(body), {
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json",
      Accept: "text/event-stream",
    },
    tags: { client_protocol: protocol, stream: "true" },
    timeout: "5m",
  });
  check(response, { "gateway returned success": (r) => r.status >= 200 && r.status < 500 });
  return response;
}

export function chatResponses() {
  request("/v1/chat/completions", {
    model: __ENV.CHAT_MODEL || "load-test-chat",
    stream: true,
    messages: [{ role: "user", content: "stream probe" }],
  }, "chat_to_responses");
}

export function nativeResponses() {
  request("/v1/responses", {
    model: __ENV.RESPONSES_MODEL || "load-test-responses",
    stream: true,
    input: "stream probe",
  }, "responses");
}

export function nativeMessages() {
  request("/v1/messages", {
    model: __ENV.MESSAGES_MODEL || "load-test-messages",
    stream: true,
    max_tokens: 32,
    messages: [{ role: "user", content: "stream probe" }],
  }, "messages");
}
