try:
    import tgcrypto
except ImportError:
    tgcrypto = None
try:
    import cryptg
except ImportError:
    cryptg = None
try:
    import pyaes
except ImportError:
    pyaes = None

if tgcrypto is not None:
    def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return tgcrypto.ige256_encrypt(data, key, iv)


    def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return tgcrypto.ige256_decrypt(data, key, iv)
elif cryptg is not None:
    def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return cryptg.encrypt_ige(data, key, iv)


    def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return cryptg.decrypt_ige(data, key, iv)
elif pyaes is not None:
    def xor(a: bytes, b: bytes) -> bytes:
        return int.to_bytes(
            int.from_bytes(a, "big") ^ int.from_bytes(b, "big"),
            len(a),
            "big",
        )

    def ige(data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
        cipher = pyaes.AES(key)

        iv_1 = iv[:16]
        iv_2 = iv[16:]

        data = [data[i: i + 16] for i in range(0, len(data), 16)]

        if encrypt:
            for i, chunk in enumerate(data):
                iv_1 = data[i] = xor(cipher.encrypt(xor(chunk, iv_1)), iv_2)
                iv_2 = chunk
        else:
            for i, chunk in enumerate(data):
                iv_2 = data[i] = xor(cipher.decrypt(xor(chunk, iv_2)), iv_1)
                iv_1 = chunk

        return b"".join(data)

    def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return ige(data, key, iv, True)


    def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return ige(data, key, iv, False)
else:
    raise ImportError("\"tgcrypto\", or \"pytgcrypto\", or \"cryptg\", or \"pyaes\" must be installed!")
