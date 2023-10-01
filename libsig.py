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

    ck = d_ck.update(ck_const).digest()
    mk = d_ck.update(mk_const).digest()

    return ck, mk

def ENCRYPT(mk, plaintext, associated_data) -> bytes:
    key, auth_key, iv = _encrypt_params(mk)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = iv + cipher.encrypt(pad(plaintext,  AES.block_size))

    hmac = _build_hash_out(auth_key, associated_data, cipher_text)
    return cipher_text, cipher_text + hmac.digest()

def DECRYPT(mk, cipher_text):
    key, _, _ = _encrypt_params(mk)
    iv = cipher_text[:AES.block_size]
    data = cipher_text[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def _build_hash_out(auth_key, associated_data, cipher_text):
    return HMAC.new(auth_key, digestmod=SHA256).update(
            associated_data + cipher_text)

def _encrypt_params(mk):
    hash_len = 80
    information = b'ENCRYPT'
    salt = bytes(hash_len)
    hkdf_out = _hkdf(mk, salt, hash_len, 1, information)

    key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:hash_len]

    return key, auth_key, iv


def _hkdf(master_secret, salt=None, length=32, num_keys=2, information=None):
    if not salt:
        salt = get_random_bytes(16)
    
    return HKDF(master_secret, length, salt, SHA512, num_keys, context=information)

def _verify_cipher_text(mk, cipher_text, MAC, associated_data):
    """
    Throws ValueError – if the MAC does not match. 
    It means that the message has been tampered with or that 
        the MAC key is incorrect.
    """ 
    _, auth_key, _ = _encrypt_params(mk)
    hmac = _build_hash_out(auth_key, associated_data, cipher_text)
    mac = MAC[len(cipher_text):]
    hmac.verify(mac)
