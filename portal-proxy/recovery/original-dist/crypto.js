// 员工网关 key 的静态加密：AES-256-GCM，密文格式 base64(iv):base64(tag):base64(ct)
// 密钥由 env PORTAL_KEY_ENC_SECRET 经 SHA-256 派生为 32 字节。
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
const IV_LEN = 12;
const TAG_LEN = 16;
const MIN_SECRET_LEN = 16;
function deriveKey(secret) {
    if (typeof secret !== 'string' || secret.length < MIN_SECRET_LEN) {
        throw new Error(`PORTAL_KEY_ENC_SECRET 过短（最少 ${MIN_SECRET_LEN} 字符）`);
    }
    return createHash('sha256').update(secret, 'utf8').digest();
}
export function encryptKey(plaintext, secret) {
    const key = deriveKey(secret);
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
}
export function decryptKey(payload, secret) {
    const key = deriveKey(secret);
    const parts = payload.split(':');
    if (parts.length !== 3)
        throw new Error('密文格式非法：应为 iv:tag:ct 三段 base64');
    const iv = Buffer.from(parts[0], 'base64');
    const tag = Buffer.from(parts[1], 'base64');
    const ct = Buffer.from(parts[2], 'base64');
    if (iv.length !== IV_LEN || tag.length !== TAG_LEN)
        throw new Error('密文格式非法：iv/tag 长度不符');
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]); // 篡改在此抛错
    return pt.toString('utf8');
}
