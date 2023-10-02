#!/usr/bin/env python3
import logging

if __name__ == "__main__":
    from person import Person

    logging.basicConfig(level='DEBUG')

    SK = b"hereLiesOurAgreedInitiationSharedSecret"

    Bob = Person("Bob")
    bob_pub_key = Bob.init(SK)
    logging.info("%s: Handshake init: %s\n", Bob.name, bob_pub_key)

    Alice = Person("Alice")
    alice_pub_key = Alice.init(SK, bob_pub_key)
    logging.info("%s: Handshake init: %s\n", Alice.name, alice_pub_key)

    bob_pub_key = Bob.init(SK, alice_pub_key)

    alice_msg = "hello world"

    AD = "SEND_MSG"
    alice_cipher_text, MAC = Alice.send_message(alice_msg, AD)
    logging.info("%s: Sending encrypted message: %s", 
                 Alice.name, alice_cipher_text)
    logging.info("%s: Sending encrypted message (MAC): %s\n", 
                 Alice.name, MAC)

    alice_plaintext = Bob.read_message(alice_cipher_text, MAC, AD)

    logging.info("%s: Reading decrypted message: %s", Bob.name, alice_plaintext)
    assert(alice_plaintext.decode("utf-8") == alice_msg)
