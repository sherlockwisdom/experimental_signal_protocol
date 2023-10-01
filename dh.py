#!/usr/bin/env python3

from ecdsa import ECDH, NIST256p

class C_ECDH:
    def __init__(self, ini_public_key=None):
        """
        """
        self.ecdh = ECDH(curve=NIST256p)

        if ini_public_key:
            self.ecdh.load_received_public_key_pem(ini_public_key)

        self.ecdh.generate_private_key()

    def get_public_key(self):
        """
        """
        return self.ecdh.get_public_key().to_pem()


    def generate_secret(self, agree_public_key=None):
        """
        """

        """
        with open("remote_public_key.pem") as e:
            remote_public_key = e.read()
        """
        if agree_public_key:
            self.ecdh.load_received_public_key_pem(agree_public_key)
        self.b_secrets = self.ecdh.generate_sharedsecret_bytes()

        return self.b_secrets




if __name__ == "__main__":
    client1 = C_ECDH()
    client1_public_key = client1.get_public_key()

    client2 = C_ECDH(client1_public_key)
    client2_secrets = client2.generate_secret()

    client1_secrets = client1.generate_secret(client2.get_public_key())

    text = "hello world"

    e_text_client1 = client1.encrypt(text)
    e_text_client2 = client2.encrypt(text)

    assert(client1.decrypt(e_text_client1) == client2.decrypt(e_text_client2))
