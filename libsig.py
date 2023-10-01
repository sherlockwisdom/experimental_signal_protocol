import dh
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512, SHA256, HMAC
from Crypto.Random import get_random_bytes

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def GENERATE_DH(ini_public_key=None):
    return dh.C_ECDH(ini_public_key)

def KDF_RK(rk, dh_out):
    length=32
    num_keys=2
    information=b'KDF_RK'
    return _hkdf(dh_out, rk, length, num_keys, information)

def KDF_CK(ck, ck_const, mk_const):
    d_ck = HMAC.new(ck, digestmod=SHA256)
    ck = d_ck.update(ck_const).hexdigest()
    mk = d_ck.update(mk_const).hexdigest()

    return ck, mk

def ENCRYPT(mk, plaintext, associated_data) -> bytes:
    hash_len = 80
    information = b'ENCRYPT'
    salt = bytes(hash_len)
    hkdf_out = _hkdf(mk, salt, hash_len, 1, information)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:hash_len]

    # vector = get_random_bytes(AES.block_size)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    cipher_text = iv + cipher.encrypt(pad(plaintext,  AES.block_size))

    hash_in = associated_data + cipher_text
    hash_out = HMAC.new(hash_in, digestmod=SHA256).hexdigest()
    
    return cipher_text + hash_out.encode()


def _hkdf(master_secret, salt=None, length=32, num_keys=2, information=None):
    if not salt:
        salt = get_random_bytes(16)
    
    return HKDF(master_secret, length, salt, SHA512, num_keys, context=information)


def decrypt(key: bytes, data: bytes) -> bytes:
    iv = data[:16]
    data = data[16:]

    decryption_cipher = AES.new(key, AES.MODE_CBC, iv)

    return unpad(decryption_cipher.decrypt(data), AES.block_size)

