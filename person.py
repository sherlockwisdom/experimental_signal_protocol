#!/usr/bin/env python3

import libsig
import logging

class Person:
    def __init__(self, name, log_level='DEBUG'):
        self.name = name
        self.state = self.State(self.name)
        self.logging = logging
        self.logging.basicConfig(level=log_level)
        self.state.logging = self.logging

    def init(self, SK, dh_pub_key=None):
        if SK == self.state.RK:
            self.state.ratchet_init_third(dh_pub_key)
        elif not dh_pub_key:
            self.state.ratchet_init(SK)
        else:
            self.state.ratchet_init_second(SK, dh_pub_key)
        self.state.report_status()
        return self.state.DHs.get_public_key()

    def send_message(self, plaintext, AD):
        self.state.CKs, mk = libsig.KDF_CK(self.state.CKs)
        self.state.Ns += 1
        '''TODO
        return libsig.ENCRYPT(mk, plaintext, libsig.CONCAT(AD, header))
        '''
        self.state.report_status()
        return libsig.ENCRYPT(mk, plaintext.encode(), AD.encode())

    def read_message(self, cipher_text, MAC, AD):
        self.state.CKr, mk = libsig.KDF_CK(self.state.CKr)
        self.state.Nr += 1
        try:
            '''TODO
            return libsig.DECRYPT(mk, cipher_text, CONCAT(AD, header))
            '''
            plaintext = libsig.DECRYPT(mk, cipher_text, AD.encode(), MAC)
            self.state.report_status()
            return plaintext
        except ValueError as error:
            logging.error("%s: !!(KERNEL PANIC) - failed to verify cipher text", 
                          self.name)
            raise error
        except Exception as error:
            raise error

    class State:
        DHs = None
        DHr = None

        RK = None
        CKs = None
        CKr = None

        Ns = 0
        Nr = 0

        logging = None

        def ratchet_init(self, SK):
            self.RK = SK
            self.logging.debug("%s: Initializing first ratchet (SK): %s", 
                               self.name, self.RK)

        def ratchet_init_second(self, SK, dh_pub_key):
            self.DHr = dh_pub_key
            self.RK, self.CKs = libsig.KDF_RK(SK, libsig.DH(self.DHs, self.DHr))
            self.logging.debug("%s: Initializing second ratchet (SK): %s", 
                               self.name, self.RK)

        def ratchet_init_third(self, dh_pub_key):
            self.DHr = dh_pub_key
            self.RK, self.CKr = libsig.KDF_RK(self.RK, libsig.DH(self.DHs, self.DHr))
            self.logging.debug("%s: Initializing third ratchet (RK): %s", 
                               self.name, self.RK)

        def report_status(self):
            self.logging.debug("%s: State parameters -", self.name)
            self.logging.debug("\t+ DHs: %s", self.DHs.get_public_key(False))
            self.logging.debug("\t+ DHr: %s", self.DHr)
            self.logging.debug("\t+ Ns: %d", self.Ns)
            self.logging.debug("\t+ Nr: %d", self.Nr)
            self.logging.debug("\t+ RK: %s", self.RK)
            self.logging.debug("\t+ CKs: %s", self.CKs)
            self.logging.debug("\t+ Ckr: %s\n", self.CKr)

        def __init__(self, name):
            self.name = name
            self.DHs = libsig.GENERATE_DH()
