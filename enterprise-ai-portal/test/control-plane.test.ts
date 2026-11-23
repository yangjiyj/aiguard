import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type ServerResponse } from 'node:http';
import { once } from 'node:events';

import {
  ensurePortalUser,
  redeemChatLoginTicket,
  getCurrentPortalAuthorization,
  listPortalCallRecords,
  ControlPlaneError,
  PORTAL_DEFAULT_TENANT_ID,
} from '../src/lib/control-plane.js';

interface SeenRequest {
  url: string;
  method: string;
  authorization: string;
  tenant: string;
  body: string;
}

async function startCapturingServer(
  handler: (req: SeenRequest, res: ServerResponse) => void,
): Promise<{ baseUrl: string; seen: SeenRequest[]; close: () => Promise<void> }> {
  const seen: SeenRequest[] = [];
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += String(chunk);
    const captured: SeenRequest = {
      url: req.url ?? '',
      method: req.method ?? '',
      authorization: String(req.headers.authorization ?? ''),
      tenant: String(req.headers['x-jjdguard-tenant-id'] ?? ''),
      body,
    };
    seen.push(captured);
    handler(captured, res);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    seen,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

test('ensurePortalUser: 把 issuer/source_type=oidc/subject/username/email/groups 注入 body，浏览器 body 字段被忽略', async () => {
  const srv = await startCapturingServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      user_id: 'user_cp_1',
      department_id: 'dept_research',
      chat_allowed: true,
      resolution: 'automatic',
      created: true,
      department_version: 1000,
    }));
  });

  try {
    const resolution = await ensurePortalUser(
      PORTAL_DEFAULT_TENANT_ID,
      {
        issuer: 'https://sso.corp.test',
        subject: 'oidc-sub-42',
        username: 'alice@corp.test',
        email: 'alice@corp.test',
        groups: ['staff', 'engineering'],
        departments: ['SEC-E2E'],
      },
      {
        gateway: { baseUrl: srv.baseUrl, portalSecret: 'jjd-portal-secret' },
        // 注意：测试不传 env/fetchImpl，确保走全局 fetch（被 Node test 默认 fetch 兜底）
      },
    );

    assert.deepEqual(resolution, {
      userId: 'user_cp_1',
      departmentId: 'dept_research',
      projectId: '',
      chatAllowed: true,
      resolution: 'automatic',
      created: true,
      departmentVersion: 1000,
    });
    assert.equal(srv.seen.length, 1);
    const seen = srv.seen[0]!;
    assert.equal(seen.method, 'POST');
    assert.equal(seen.url, '/admin/v1/portal-integration/users');
    assert.equal(seen.authorization, 'Bearer jjd-portal-secret');
    assert.equal(seen.tenant, 'tenant_default');
    const body = JSON.parse(seen.body);
    assert.equal(body.issuer, 'https://sso.corp.test');
    assert.equal(body.source_type, 'oidc');
    assert.equal(body.external_subject, 'oidc-sub-42');
    assert.equal(body.username, 'alice@corp.test');
    assert.deepEqual(body.groups, ['staff', 'engineering']);
    assert.deepEqual(body.departments, ['SEC-E2E']);
  } finally {
    await srv.close();
  }
});

test('ensurePortalUser: 控制面拒绝时抛 ControlPlaneError，message 不含 DSN/secret', async () => {
  const srv = await startCapturingServer((_req, res) => {
    res.statusCode = 403;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ error: 'forbidden' }));
  });

  try {
    await assert.rejects(
      () =>
        ensurePortalUser(
          'tenant_default',
          {
            issuer: 'https://sso.corp.test',
            subject: 's',
            username: 'u',
            email: '',
            groups: [],
          },
          { gateway: { baseUrl: srv.baseUrl, portalSecret: 'leak-canary-secret' } },
        ),
      (err: unknown) => {
        assert.ok(err instanceof ControlPlaneError);
        assert.equal(err.code, 'forbidden');
        assert.equal(err.status, 403);
        const message = err.message;
        assert.doesNotMatch(message, /leak-canary-secret|dsn=|postgres:\/\//i);
        return true;
      },
    );
  } finally {
    await srv.close();
  }
});

test('ensurePortalUser: issuer/subject/username 任一缺失前置拒绝（不往返控制面）', async () => {
  let attempted = false;
  const srv = await startCapturingServer(() => {
    attempted = true;
    throw new Error('should not reach server');
  });

  try {
    await assert.rejects(
      () =>
        ensurePortalUser(
          'tenant_default',
          { issuer: '', subject: 's', username: 'u', email: '', groups: [] },
          { gateway: { baseUrl: srv.baseUrl, portalSecret: 's' } },
        ),
      (err: unknown) => {
        assert.ok(err instanceof ControlPlaneError);
        assert.equal(err.code, 'invalid_identity');
        return true;
      },
    );
    assert.equal(attempted, false, '前置校验失败不应往返控制面');
  } finally {
    await srv.close();
  }
});

test('ensurePortalUser: 控制面不可达抛 control_plane_unreachable，不泄露网络细节', async () => {
  // 指向一个保证不可达的端口（IPv4 1.0.0.0:1 一般被防火墙丢/拒）。
  await assert.rejects(
    () =>
      ensurePortalUser(
        'tenant_default',
        { issuer: 'https://sso.corp.test', subject: 's', username: 'u', email: '', groups: [] },
        { gateway: { baseUrl: 'http://127.0.0.1:1', portalSecret: 's' } },
      ),
    (err: unknown) => {
      assert.ok(err instanceof ControlPlaneError);
      assert.equal(err.code, 'control_plane_unreachable');
      // message 不能含原始 fetch 抛出的 ECONNREFUSED 等主机细节
      assert.doesNotMatch(err.message, /ECONN|127\.0\.0\.1|connect/i);
      return true;
    },
  );
});

test('ensurePortalUser: 控制面返回缺 user_id 抛 invalid_identity_response', async () => {
  const srv = await startCapturingServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ department_id: 'd' }));
  });

  try {
    await assert.rejects(
      () =>
        ensurePortalUser(
          'tenant_default',
          { issuer: 'https://sso.corp.test', subject: 's', username: 'u', email: '', groups: [] },
          { gateway: { baseUrl: srv.baseUrl, portalSecret: 's' } },
        ),
      (err: unknown) => {
        assert.ok(err instanceof ControlPlaneError);
        assert.equal(err.code, 'invalid_identity_response');
        return true;
      },
    );
  } finally {
    await srv.close();
  }
});

test('getCurrentPortalAuthorization: GET latest context and parse model_ids', async () => {
  const srv = await startCapturingServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      data: {
        user_id: 'user cp/1',
        department_id: 'dept_marketing',
        department_name: '市场部',
        department_version: 2000,
        chat_allowed: true,
        model_ids: ['model-b', 'model-a'],
      },
    }));
  });

  try {
    const context = await getCurrentPortalAuthorization('tenant_default', 'user cp/1', {
      gateway: { baseUrl: srv.baseUrl, portalSecret: 'latest-secret' },
    });
    assert.deepEqual(context, {
      userId: 'user cp/1',
      departmentId: 'dept_marketing',
      departmentName: '市场部',
      departmentVersion: 2000,
      chatAllowed: true,
      modelIds: ['model-b', 'model-a'],
    });
    assert.equal(srv.seen[0]?.method, 'GET');
    assert.equal(
      srv.seen[0]?.url,
      '/admin/v1/portal-integration/users/user%20cp%2F1/authorization-context',
    );
    assert.equal(srv.seen[0]?.authorization, 'Bearer latest-secret');
    assert.equal(srv.seen[0]?.tenant, 'tenant_default');
    assert.equal(srv.seen[0]?.body, '');
  } finally {
    await srv.close();
  }
});

test('getCurrentPortalAuthorization: inactive or emergency context fails closed', async () => {
  const srv = await startCapturingServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      data: {
        user_id: 'user_cp_1',
        department_id: 'dept_root',
        department_name: '根部门',
        department_version: 3000,
        chat_allowed: false,
        model_ids: ['must-not-escape'],
      },
    }));
  });
  try {
    await assert.rejects(
      () => getCurrentPortalAuthorization('tenant_default', 'user_cp_1', {
        gateway: { baseUrl: srv.baseUrl, portalSecret: 's' },
      }),
      (err: unknown) => err instanceof ControlPlaneError && err.code === 'authorization_denied',
    );
  } finally {
    await srv.close();
  }
});

test('getCurrentPortalAuthorization rejects an unsafe integer revision', async () => {
  const srv = await startCapturingServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      data: {
        user_id: 'user_cp_1',
        department_id: 'dept_root',
        department_name: '根部门',
        department_version: Number.MAX_SAFE_INTEGER + 1,
        chat_allowed: true,
        model_ids: [],
      },
    }));
  });
  try {
    await assert.rejects(
      () => getCurrentPortalAuthorization('tenant_default', 'user_cp_1', {
        gateway: { baseUrl: srv.baseUrl, portalSecret: 's' },
      }),
      (err: unknown) =>
        err instanceof ControlPlaneError && err.code === 'invalid_authorization_response',
    );
  } finally {
    await srv.close();
  }
});

test('ensurePortalUser rejects an unsafe integer revision', async () => {
  const srv = await startCapturingServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      user_id: 'user_cp_1',
      department_id: 'dept_root',
      department_version: Number.MAX_SAFE_INTEGER + 1,
      chat_allowed: true,
      resolution: 'automatic',
      created: false,
    }));
  });
  try {
    await assert.rejects(
      () => ensurePortalUser(
        'tenant_default',
        { issuer: 'https://sso.test', subject: 's', username: 'u', email: '', groups: [] },
        { gateway: { baseUrl: srv.baseUrl, portalSecret: 's' } },
      ),
      (err: unknown) =>
        err instanceof ControlPlaneError && err.code === 'invalid_identity_response',
    );
  } finally {
    await srv.close();
  }
});

test('listPortalCallRecords: encodes the bound user, carries the cursor and maps overview fields', async () => {
  const srv = await startCapturingServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      data: [{
        request_id: 'req-1',
        created_at: '2026-08-16T00:00:00Z',
        model: 'GPT 5.6',
        status: 'success',
        upstream_status: 200,
        input_tokens: 12,
        output_tokens: 8,
        total_tokens: 20,
        latency_ms: 321,
        session_id: 'session-1',
        agent_type: 'codex',
        endpoint_type: 'responses',
        input_action: '',
        output_action: 'audit',
        security_event_count: 0,
		billing_amount_micros: 0,
		billing_currency: 'CNY',
		billing_state: 'settled',
        prompt_text: 'must-not-reach-browser',
      }],
      total: 1,
      next_cursor: 'opaque-page-2',
    }));
  });

  try {
    const page = await listPortalCallRecords(
      'tenant_default',
      'user cp/1',
      { limit: 500, cursor: 'opaque-page-1', days: 180 },
      { gateway: { baseUrl: srv.baseUrl, portalSecret: 'call-record-secret' } },
    );
    assert.deepEqual(page, {
      records: [{
        requestId: 'req-1',
        createdAt: '2026-08-16T00:00:00Z',
        model: 'GPT 5.6',
        status: 'success',
        inputTokens: 12,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: 8,
        totalTokens: 20,
        latencyMs: 321,
        agentType: 'codex',
        endpointType: 'responses',
		billingAmountMicros: 0,
		billingCurrency: 'CNY',
		billingState: 'settled',
      }],
      total: 1,
      nextCursor: 'opaque-page-2',
    });
    assert.equal(srv.seen[0]?.method, 'GET');
    assert.equal(
      srv.seen[0]?.url,
      '/admin/v1/portal-integration/users/user%20cp%2F1/call-records?limit=200&cursor=opaque-page-1&days=90',
    );
    assert.equal(srv.seen[0]?.authorization, 'Bearer call-record-secret');
    assert.equal(srv.seen[0]?.tenant, 'tenant_default');
    assert.doesNotMatch(JSON.stringify(page), /must-not-reach-browser|prompt_text|timing|upstream|security|inputAction|outputAction/i);
  } finally {
    await srv.close();
  }
});

test('listPortalCallRecords: accepts legacy settled records without an amount', async () => {
	const srv = await startCapturingServer((_req, res) => {
		res.setHeader('content-type', 'application/json');
		res.end(JSON.stringify({
			data: [{
				request_id: 'req-legacy-billing',
				created_at: '2026-08-16T00:00:00Z',
				model: 'codex-auto-review',
				status: 'success',
				upstream_status: 200,
				input_tokens: 9,
				output_tokens: 103,
				total_tokens: 112,
				latency_ms: 5858,
				agent_type: '',
				endpoint_type: 'chat',
				input_action: '',
				output_action: 'allow',
				security_event_count: 1,
				billing_amount_micros: null,
				billing_currency: '',
				billing_state: 'settled',
			}],
			total: 1,
			next_cursor: '',
		}));
	});

	try {
		const page = await listPortalCallRecords(
			'tenant_default',
			'user-1',
			{},
			{ gateway: { baseUrl: srv.baseUrl, portalSecret: 'legacy-billing-secret' } },
		);
		assert.equal(page.records.length, 1);
		assert.equal(page.records[0]?.billingState, 'settled');
		assert.equal(page.records[0]?.billingAmountMicros, null);
		assert.equal(page.records[0]?.billingCurrency, '');
	} finally {
		await srv.close();
	}
});

test('listPortalCallRecords: rejects inconsistent token totals and unsafe values', async () => {
  const srv = await startCapturingServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      data: [{
        request_id: 'req-1',
        created_at: '2026-08-16T00:00:00Z',
        model: 'GPT 5.6',
        status: 'success',
        upstream_status: 200,
        input_tokens: 12,
        output_tokens: 8,
        total_tokens: 999,
        latency_ms: 321,
        session_id: '',
        agent_type: '',
        endpoint_type: 'chat',
        input_action: '',
        output_action: '',
        security_event_count: 0,
		billing_amount_micros: 0,
		billing_currency: 'CNY',
		billing_state: 'settled',
      }],
      total: 1,
      next_cursor: '',
    }));
  });

  try {
    await assert.rejects(
      () => listPortalCallRecords(
        'tenant_default',
        'user-1',
        {},
        { gateway: { baseUrl: srv.baseUrl, portalSecret: 'must-not-leak' } },
      ),
      (error: unknown) => {
        assert.ok(error instanceof ControlPlaneError);
        assert.equal(error.code, 'invalid_call_records_response');
        assert.doesNotMatch(error.message, /must-not-leak|postgres|dsn=/i);
        return true;
      },
    );
  } finally {
    await srv.close();
  }
});

test('listPortalCallRecords: rejects invalid billing amount and state shapes', async () => {
	const cases = [
		{ name: 'negative amount', patch: { billing_amount_micros: -1 } },
		{ name: 'unsafe amount', patch: { billing_amount_micros: Number.MAX_SAFE_INTEGER + 1 } },
		{ name: 'unknown state', patch: { billing_state: 'unknown' } },
		{ name: 'settled amount without currency', patch: { billing_currency: '' } },
		{ name: 'settled missing amount with stale currency', patch: { billing_amount_micros: null } },
		{
			name: 'reserved with settled amount',
			patch: { billing_state: 'reserved', billing_amount_micros: 0, billing_currency: '' },
		},
	] as const;

	for (const scenario of cases) {
		const srv = await startCapturingServer((_req, res) => {
			res.setHeader('content-type', 'application/json');
			res.end(JSON.stringify({
				data: [{
					request_id: 'req-billing',
					created_at: '2026-08-16T00:00:00Z',
					model: 'GPT 5.6',
					status: 'success',
					upstream_status: 200,
					input_tokens: 12,
					output_tokens: 8,
					total_tokens: 20,
					latency_ms: 321,
					agent_type: '',
					endpoint_type: 'chat',
					input_action: '',
					output_action: '',
					security_event_count: 0,
					billing_amount_micros: 0,
					billing_currency: 'CNY',
					billing_state: 'settled',
					...scenario.patch,
				}],
				total: 1,
				next_cursor: '',
			}));
		});

		try {
			await assert.rejects(
				() => listPortalCallRecords(
					'tenant_default',
					'user-1',
					{},
					{ gateway: { baseUrl: srv.baseUrl, portalSecret: 'billing-shape-secret' } },
				),
				(error: unknown) =>
					error instanceof ControlPlaneError && error.code === 'invalid_call_records_response',
				scenario.name,
			);
		} finally {
			await srv.close();
		}
	}
});


test('listPortalCallRecords accepts postpaid unpriced and failed usage facts', async () => {
  for (const state of ['unpriced', 'failed'] as const) {
    const row = {
      request_id: 'req-postpaid', created_at: '2026-09-07T20:23:28.019Z',
      model: '未识别模型', status: 'success', upstream_status: 200,
      input_tokens: 368, output_tokens: 4, total_tokens: 372, latency_ms: 2716,
      agent_type: '', endpoint_type: 'chat', input_action: '', output_action: 'allow',
      security_event_count: 0, billing_amount_micros: null, billing_currency: '', billing_state: state,
    };
    const page = await listPortalCallRecords('tenant_default', 'employee', {}, {
      gateway: { baseUrl: 'http://cp.test', portalSecret: 'test-only' },
      fetchImpl: async () => Response.json({ data: [row], total: 1, next_cursor: '' }),
    });
    assert.equal(page.records[0]?.billingState, state);
    assert.equal(page.records[0]?.totalTokens, 372);
    assert.equal(page.records[0]?.billingAmountMicros, null);
  }
});

test('Chat ticket redemption carries only the ticket and fixed tenant over the machine channel', async () => {
 let captured: RequestInit | undefined;
 const identity=await redeemChatLoginTicket('A'.repeat(43),{
  gateway:{baseUrl:'http://control-plane.test',portalSecret:'machine-secret'},
  fetchImpl:(async (url,options)=>{
   assert.equal(url,'http://control-plane.test/admin/v1/portal-integration/chat-login/redeem');
   captured=options;
   return Response.json({user_id:'cp-u',tenant_id:'tenant_default',username:'local',email:'',
    local_credential_version:1,external_subject:'trusted-subject',department_id:'dept',department_name:'研发部',department_version:2,chat_allowed:true});
  }) as typeof fetch,
 });
 assert.equal(identity.localCredentialVersion,1);assert.equal(identity.userId,'cp-u');assert.equal(identity.externalSubject,'trusted-subject');
 assert.deepEqual(JSON.parse(String(captured?.body)),{ticket:'A'.repeat(43)});
 assert.equal(new Headers(captured?.headers).get('authorization'),'Bearer machine-secret');
 assert.equal(new Headers(captured?.headers).get('X-JJDGuard-Tenant-Id'),'tenant_default');
 assert.equal(captured?.cache,'no-store');
});
test('Chat ticket identity cannot silently cross tenant or drop its trusted subject', async () => {
 for(const changes of [{tenant_id:'other-tenant'},{external_subject:''},{chat_allowed:false},{department_version:0},{local_credential_version:undefined},{local_credential_version:0},{local_credential_version:1.5}]) {
  await assert.rejects(redeemChatLoginTicket('A'.repeat(43),{
   gateway:{baseUrl:'http://control-plane.test',portalSecret:'machine-secret'},
   fetchImpl:(async()=>Response.json({user_id:'cp-u',tenant_id:'tenant_default',username:'local',email:'',
    local_credential_version:1,external_subject:'trusted-subject',department_id:'dept',department_name:'研发部',department_version:2,chat_allowed:true,...changes})) as typeof fetch,
  }), (error: unknown)=>error instanceof ControlPlaneError && error.code==='invalid_chat_identity');
 }
});


test('调用记录解析缓存新字段，旧响应缺失时补零，非法值仍拒绝', async () => {
  const row = {
    request_id: 'req-cache', created_at: '2026-10-22T00:00:00Z',
    model: 'Claude', status: 'success', upstream_status: 200,
    input_tokens: 90364, output_tokens: 4, total_tokens: 90368, latency_ms: 100,
    agent_type: 'claude-code', endpoint_type: 'messages', input_action: '', output_action: '',
    security_event_count: 0, billing_amount_micros: null, billing_currency: '', billing_state: 'unpriced',
  };
  const parse = (extra: Record<string, unknown>) => listPortalCallRecords('tenant_default', 'employee', {}, {
    gateway: { baseUrl: 'http://cp.test', portalSecret: 'test-only' },
    fetchImpl: async () => Response.json({ data: [{ ...row, ...extra }], total: 1, next_cursor: '' }),
  });
  const cached = (await parse({ cached_input_tokens: 90086, cache_write_input_tokens: 118 })).records[0];
  assert.equal(cached?.cachedInputTokens, 90086);
  assert.equal(cached?.cacheWriteInputTokens, 118);
  assert.equal(cached?.totalTokens, 90368);
  const legacy = (await parse({})).records[0];
  assert.equal(legacy?.cachedInputTokens, 0);
  assert.equal(legacy?.cacheWriteInputTokens, 0);
  for (const field of ['cached_input_tokens', 'cache_write_input_tokens']) {
    for (const value of [-1, 1.5, '12', null, Number.MAX_SAFE_INTEGER + 1]) {
      await assert.rejects(parse({ [field]: value }),
        (error: unknown) => error instanceof ControlPlaneError && error.code === 'invalid_call_records_response');
    }
  }
});


test('调用汇总白名单仅保留所选范围总耗时、成功率、请求数', async () => {
  const result = await listPortalCallRecords('tenant_default', 'employee', {days: 7}, {
    gateway: {baseUrl: 'http://unused.invalid', portalSecret: 'test'},
    fetchImpl: async () => Response.json({data: [], total: 0, next_cursor: '', summary: {
      requests: 100, average_latency_ms: 1200.5, success_rate: 0.98,
      timing: {input_security_ms: 900}, upstream: '不可透传',
    }}),
  });
  assert.deepEqual(result.summary, {requests: 100, averageLatencyMs: 1200.5, successRate: 0.98});
  assert.doesNotMatch(JSON.stringify(result), /timing|upstream|security/i);
});

test('调用汇总空窗口保留空值，错误成功率被拒绝', async () => {
  const parse = (summary: Record<string, unknown>) => listPortalCallRecords('tenant_default', 'employee', {}, {
    gateway: {baseUrl: 'http://unused.invalid', portalSecret: 'test'},
    fetchImpl: async () => Response.json({data: [], total: 0, next_cursor: '', summary}),
  });
  assert.deepEqual((await parse({requests: 0, average_latency_ms: null, success_rate: null})).summary,
    {requests: 0, averageLatencyMs: null, successRate: null});
  await assert.rejects(parse({requests: 1, average_latency_ms: 1, success_rate: 98}), /无效调用汇总/);
});

test('个人调用记录接受纯总耗时响应，丢弃额外分段与内部字段', async () => {
  const result = await listPortalCallRecords('tenant_default', 'employee', {}, {
    gateway: {baseUrl: 'http://unused.invalid', portalSecret: 'test'},
    fetchImpl: async () => Response.json({data: [{
      request_id: 'req-private', created_at: '2026-10-23T00:00:00Z', model: '模型', status: 'success',
      input_tokens: 1, output_tokens: 2, total_tokens: 3, latency_ms: 1500,
      agent_type: '', endpoint_type: 'chat', billing_state: 'unpriced', billing_amount_micros: null, billing_currency: '',
      timing: {generation_ms: 1000}, upstream_status: 200, input_action: 'allow', security_event_count: 0,
    }], total: 1, next_cursor: ''}),
  });
  assert.equal(result.records[0]?.latencyMs, 1500);
  assert.doesNotMatch(JSON.stringify(result), /timing|upstream|security|inputAction|outputAction/i);
});
