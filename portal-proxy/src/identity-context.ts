// 请求级身份上下文：直接身份模式下，server.ts 在请求入口把 DirectIdentity 存进来，
// jit 的 lookupEmployee 依赖读取它——有就直接返回，跳过 LobeHub PG 库查询。
// AsyncLocalStorage 保证请求隔离（并发安全），业务代码无感知。
import { AsyncLocalStorage } from 'node:async_hooks';
import type { DirectIdentity } from './direct-identity.js';
const store = new AsyncLocalStorage<DirectIdentity | null>();
/** 请求入口包裹：在回调内所有同步/异步代码都能取到 identity。 */
export function runWithIdentity<T>(identity: DirectIdentity | null, fn: () => T): T {
    return store.run(identity, fn);
}
/** jit.lookupEmployee 依赖读取：有直接身份就返回，没有返回 null（回落 LobeDb）。 */
export function getDirectIdentity() {
    return store.getStore() ?? null;
}
