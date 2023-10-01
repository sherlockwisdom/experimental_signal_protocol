#!/usr/bin/env python3

import libsig

class Person:
    def __init__(self, name, ini_public_key=None):
        self.name = name
        self.dh = libsig.GENERATE_DH(ini_public_key)

        if ini_public_key:
            self.dh_out = self.get_public_key()
            self.init(dh_out = self.dh_out)

    def get_public_key(self):
        return self.dh.get_public_key()

    def init(self, ini_public_key=None, dh_out=None):
        self.dh.generate_secret(ini_public_key)
        print(self.name, ": generated secret")

        if ini_public_key:
            self.dh_out = ini_public_key
        self.state = self.State(self.name, self.dh.b_secrets, self.dh_out)

    def ratched_encrypt(self, text):
        self.state.ratchet_ck()
        mk = self.state.mk
        AD = b"AD"
        cipher_text, MAC = libsig.ENCRYPT(mk, text.encode(), AD)
        print("\t", self.name, ": send:", cipher_text)
        print("\t", self.name, ": mac:", MAC)
        print()

        return cipher_text, MAC

    def ratched_decrypt(self, cipher_text, MAC):
        self.state.ratchet_ck()
        mk = self.state.mk
        AD = b"AD"

        try:
            libsig._verify_cipher_text(mk, cipher_text, MAC, AD)
        except ValueError as error:
            print("!!(KERNEL PANIC) - failed to verify cipher text")
            raise error
        except Exception as error:
            raise error
        else:
            text = libsig.DECRYPT(mk, cipher_text)
            print("\t", self.name, ": received:", text)
            print()

            return text

    class State:
        rk = None
        ck = None
        mk = None
        rk_iter = 0
        ck_iter = 0

        ck_const = 0
        mk_const = ck_const + 1
        def __init__(self, name, rk, dh_out):
            self.name =name

            self.rk, self.ck = libsig.KDF_RK(rk, dh_out)
            self.rk_iter += 1
            print(self.name, ": state changed - rk")
            print("\t+ rk_iter:", self.rk_iter)
            print("\t+ ck_iter:", self.ck_iter)
            print("\t+ rk:", self.rk)
            print("\t+ ck:", self.ck)
            print()

        def ratchet_ck(self):
            self.ck, self.mk = libsig.KDF_CK(
                    self.ck, bytes(self.ck_const), bytes(self.mk_const))

            """
            self.ck = ck.encode()
            self.mk = mk.encode()
            """

            self.ck_iter += 1
            self.ck_const += 1
            self.mk_const = self.ck_const + 1

            print(self.name, ": state changed - ck")
            print("\t+ ck_iter:", self.ck_iter)
            print("\t+ ck_const:", self.ck_const)
            print("\t+ mk_const:", self.mk_const)
            print("\t+ ck:", self.ck)
            print("\t+ mk:", self.mk)
            print()
