from hashlib import sha256

# TODO: also support mtproto v1.0 kdf:
#  https://core.telegram.org/api/end-to-end_v1#serialization-and-encryption-of-outgoing-messages


def kdf_v2(key: bytes, msg_key: bytes, from_originator: bool) -> tuple[bytes, bytes]:
    x = 0 if from_originator else 8

    # sha256_a = SHA256 (msg_key + substr (key, x, 36));
    sha256_a = sha256(msg_key + key[x:x + 36]).digest()

    # sha256_b = SHA256 (substr (key, 40+x, 36) + msg_key);
    sha256_b = sha256(key[40 + x:40 + x + 36] + msg_key).digest()

    # aes_key = substr (sha256_a, 0, 8) + substr (sha256_b, 8, 16) + substr (sha256_a, 24, 8);
    aes_key = sha256_a[0:8] + sha256_b[8:8 + 16] + sha256_a[24:24 + 8]

    # aes_iv = substr (sha256_b, 0, 8) + substr (sha256_a, 8, 16) + substr (sha256_b, 24, 8);
    aes_iv = sha256_b[0:8] + sha256_a[8:8 + 16] + sha256_b[24:24 + 8]

    return aes_key, aes_iv

def msg_key_v2(key: bytes, padded_plaintext: bytes, from_originator: bool) -> bytes:
    x = 0 if from_originator else 8

    # msg_key_large = SHA256 (substr (key, 88+x, 32) + plaintext + random_padding)
    msg_key_large = sha256(key[88 + x: 88 + x + 32] + padded_plaintext).digest()

    # msg_key = substr (msg_key_large, 8, 16);
    msg_key = msg_key_large[8:8 + 16]

    return msg_key


def write_int(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def write_long(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=True)


def read_int(value: bytes) -> int:
    return int.from_bytes(value[:4], "little", signed=True)


def read_long(value: bytes) -> int:
    return int.from_bytes(value[:8], "little", signed=True)
