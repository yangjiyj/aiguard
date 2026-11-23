"use client";

import { portalPath } from "@/lib/portal-path";

export function SessionError() {
  return <main style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24 }}>
    <section style={{ textAlign: "center" }}>
      <h1>登录状态已失效，请重新登录</h1>
      <p><a href={portalPath("/login?error=session_expired")}>重新登录</a></p>
    </section>
  </main>;
}
