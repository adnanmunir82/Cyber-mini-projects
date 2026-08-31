import os
import json
import base64
import secrets
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PBKDF2_ITERATIONS = 200_000


def derive_key(secret_str, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(secret_str.encode("utf-8")))


def generate_recovery_key():
    """Human-friendly recovery key, e.g. XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"""
    raw = secrets.token_hex(15).upper()  # 30 hex chars
    groups = [raw[i:i + 5] for i in range(0, 30, 5)]
    return "-".join(groups)


def create_vault_config(master_password):
    """
    Generates a random Vault Key (VK) — the actual key used to encrypt files.
    Wraps VK twice: once under the master password, once under a recovery key.
    Either secret can independently unwrap VK. Returns (config_dict, recovery_key_plaintext).
    """
    vault_key = Fernet.generate_key()  # the real data-encryption key
    recovery_key = generate_recovery_key()

    salt_pw = secrets.token_bytes(16)
    kek_pw = derive_key(master_password, salt_pw)
    wrapped_vk_pw = Fernet(kek_pw).encrypt(vault_key)

    salt_rec = secrets.token_bytes(16)
    kek_rec = derive_key(recovery_key, salt_rec)
    wrapped_vk_rec = Fernet(kek_rec).encrypt(vault_key)

    config = {
        "salt_pw": base64.b64encode(salt_pw).decode(),
        "wrapped_vk_pw": wrapped_vk_pw.decode(),
        "salt_rec": base64.b64encode(salt_rec).decode(),
        "wrapped_vk_rec": wrapped_vk_rec.decode(),
    }
    return config, recovery_key


def unlock_with_password(config, password):
    salt_pw = base64.b64decode(config["salt_pw"])
    kek_pw = derive_key(password, salt_pw)
    try:
        vault_key = Fernet(kek_pw).decrypt(config["wrapped_vk_pw"].encode())
        return vault_key
    except InvalidToken:
        return None


def unlock_with_recovery_key(config, recovery_key):
    salt_rec = base64.b64decode(config["salt_rec"])
    kek_rec = derive_key(recovery_key.strip().upper(), salt_rec)
    try:
        vault_key = Fernet(kek_rec).decrypt(config["wrapped_vk_rec"].encode())
        return vault_key
    except InvalidToken:
        return None


def encrypt_bytes(vault_key, data):
    return Fernet(vault_key).encrypt(data)


def decrypt_bytes(vault_key, token):
    return Fernet(vault_key).decrypt(token)