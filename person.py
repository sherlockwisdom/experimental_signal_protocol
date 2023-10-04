#!/usr/bin/env python3

import libsig
import logging

class Person:
    def __init__(self, name, log_level='DEBUG'):
        self.name = name
        self.logging = logging
        self.logging.basicConfig(level=log_level)

        self.dh = libsig.GENERATE_DH()


    def get_public_key(self):
        return self.dh.get_public_key()

    def get_dh_public_key(self):
        return self.state.DHs.get_public_key()

    def ini_with_public_key(self, peer_pub_key):
        self.dh.set_peer_public_key(peer_pub_key)

    def get_sk(self):
        self.dh.generate_secret()
        return self.dh.b_secrets

    def rt_init(self, SK, dh_pub_key):
        self.state = libsig.State(self.name)
        self.state.logging = self.logging
        self.state = libsig.DHRatchet.init(self.state, SK, dh_pub_key)
        self.state.report_status()

    def send_message(self, plaintext, AD):
        self.state.CKs, mk = libsig.KDF_CK(self.state.CKs)
        header = libsig.HEADER(self.state.DHs, self.state.PN, self.state.Ns)
        self.state.Ns += 1
        self.state.report_status()
        return header, libsig.ENCRYPT(mk, plaintext.encode(), 
                                      libsig.CONCAT(AD, header))

    def read_message(self, header, cipher_text, AD):
        if header.DH != self.state.DHr:
            self.state = libsig.DHRatchet(self.state, header)
        self.state.CKr, mk = libsig.KDF_CK(self.state.CKr)
        self.state.Nr += 1
        try:
            '''TODO
            return libsig.DECRYPT(mk, cipher_text, CONCAT(AD, header))
            '''
            plaintext = libsig.DECRYPT(mk, cipher_text, AD)
            self.state.report_status()
            return plaintext
        except ValueError as error:
            logging.error("%s: !!(KERNEL PANIC) - failed to verify cipher text", 
                          self.name)
            raise error
        except Exception as error:
            raise error

