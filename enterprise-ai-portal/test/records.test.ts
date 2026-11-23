import test from "node:test";
import assert from "node:assert/strict";
import {
  mergeRecords,
  type GatewayUploadEvent,
  type PortalUploadRow,
} from "../src/lib/records.js";

test("mergeRecords：网关与门户记录按 sha256 去重（网关权威）", () => {
  const gateway: GatewayUploadEvent[] = [
    { id: "g1", filename: "a.txt", mime_type: "text/plain", size: 10, sha256: "sha-a", reference: "ref-a", model: "glm-5.2", action_taken: "audit", findings: {}, created_at: "2026-07-04T10:00:00Z" },
  ];
  const portal: PortalUploadRow[] = [
    { id: "p1", filename: "a.txt", mime: "text/plain", size: 10, sha256: "sha-a", model: "glm-5.2", kind: "image", createdAt: "2026-07-04T09:00:00Z" },
    { id: "p2", filename: "b.png", mime: "image/png", size: 20, sha256: "sha-b", model: null, kind: "image", createdAt: "2026-07-04T11:00:00Z" },
  ];
  const merged = mergeRecords(gateway, portal);
  assert.equal(merged.length, 2);
  const aRow = merged.find((m) => m.sha256 === "sha-a");
  assert.equal(aRow?.source, "gateway");
  assert.equal(aRow?.reference, "ref-a");
  const bRow = merged.find((m) => m.sha256 === "sha-b");
  assert.equal(bRow?.source, "portal");
});

test("mergeRecords：按时间倒序", () => {
  const merged = mergeRecords(
    [{ id: "g1", filename: "x.txt", mime_type: "text/plain", size: 1, sha256: "s1", reference: "r1", model: "", action_taken: "audit", findings: {}, created_at: "2026-07-04T10:00:00Z" }],
    [{ id: "p1", filename: "y.png", mime: "image/png", size: 1, sha256: "s2", model: null, kind: "image", createdAt: "2026-07-04T12:00:00Z" }],
  );
  assert.ok(new Date(merged[0].createdAt).getTime() > new Date(merged[1].createdAt).getTime());
  assert.equal(merged[0].sha256, "s2");
});

test("repeated authoritative uploads preserve each event even for the same hash",()=>{
 const fixture={filename:"same.txt",mime_type:"text/plain",size:1,sha256:"same",reference:"ref",model:"model",action_taken:"audit",findings:{},created_at:"2026-10-13T00:00:00Z"};
 const records=mergeRecords([{...fixture,id:"first"},{...fixture,id:"second"}],[]);
 assert.equal(records.length,2);
});
