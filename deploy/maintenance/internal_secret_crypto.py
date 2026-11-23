"""Rewrap JJDGuard's existing encrypted data without changing plaintext or AAD."""
import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CA_PREFIX = 'enc:ca:v1:'
CA_DOMAIN = b'jjdguard:proxy-ca-private-key:v1'
QUEUE_DOMAIN = b'jjdguard:inspection-queue:v1:'


def _open(value, key, aad):
    raw = base64.b64decode(value + '=' * (-len(value) % 4), validate=True)
    if len(raw) < 28:
        raise ValueError('invalid_ciphertext')
    return AESGCM(key).decrypt(raw[:12], raw[12:], aad)


def _seal(value, key, aad):
    nonce = os.urandom(12)
    return base64.b64encode(nonce + AESGCM(key).encrypt(nonce, value, aad)).decode().rstrip('=')


def ca_key(secret):
    return hmac.new(secret.encode(), CA_DOMAIN, hashlib.sha256).digest()


def queue_key(secret):
    return hashlib.sha256(QUEUE_DOMAIN + secret.encode()).digest()


def rewrap_ca(value, old_secret, new_secret):
    if not value.startswith(CA_PREFIX):
        return value
    plaintext = _open(value[len(CA_PREFIX):], ca_key(old_secret), CA_DOMAIN)
    revised = _seal(plaintext, ca_key(new_secret), CA_DOMAIN)
    if not hmac.compare_digest(plaintext, _open(revised, ca_key(new_secret), CA_DOMAIN)):
        raise ValueError('ca_rewrap_verification_failed')
    return CA_PREFIX + revised


def rewrap_part(value, tenant, request, index, kind, old_secret, new_secret):
    if not value:
        return value
    if kind not in {'payload', 'result'}:
        raise ValueError('invalid_queue_kind')
    aad = f'{tenant}/{request}/{index}/{kind}'.encode()
    plaintext = _open(value, queue_key(old_secret), aad)
    revised = _seal(plaintext, queue_key(new_secret), aad)
    if not hmac.compare_digest(plaintext, _open(revised, queue_key(new_secret), aad)):
        raise ValueError('queue_rewrap_verification_failed')
    return revised
