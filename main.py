#!/usr/bin/env python3
import logging
import sys

if __name__ == "__main__":
    from person import Person

    log_level = 'DEBUG'
    if len(sys.argv) > 1:
        log_level = sys.argv[1]
    logging.basicConfig(level=log_level)

    SK = b"hereLiesOurAgreedInitiationSharedSecret"

    Bob = Person("Bob")
    bob_pub_key = Bob.init(SK)
    logging.info("%s: Handshake init: %s\n", Bob.name, bob_pub_key)

    Alice = Person("Alice")
    alice_pub_key = Alice.init(SK, bob_pub_key)
    logging.info("%s: Handshake init: %s\n", Alice.name, alice_pub_key)

    bob_pub_key = Bob.init(None, alice_pub_key)

    # Alice messaging
    AD = "SEND_MSG_ALICE"
    alice_msg = "hello world"
    alice_cipher_text, MAC = Alice.send_message(alice_msg, AD)
    logging.info("%s: Sending encrypted message: %s", 
                 Alice.name, alice_cipher_text)
    logging.info("%s: Sending encrypted message (MAC): %s", 
                 Alice.name, MAC)
    alice_plaintext = Bob.read_message(alice_cipher_text, MAC, AD)
    logging.info("%s: Reading decrypted message: %s\n", Bob.name, alice_plaintext)
    assert(alice_plaintext.decode("utf-8") == alice_msg)

    alice_pub_key = Alice.init(None, bob_pub_key)


    # Bob messaging
    AD = "SEND_MSG_BOB"
    bob_msg = "Hello friend! Hello friend? That's lame"
    bob_cipher_text, MAC = Bob.send_message(bob_msg, AD)
    logging.info("%s: Sending encrypted message: %s", 
                 Bob.name, alice_cipher_text)
    logging.info("%s: Sending encrypted message (MAC): %s", 
                 Bob.name, MAC)

    bob_plaintext = Alice.read_message(bob_cipher_text, MAC, AD)
    logging.info("%s: Reading decrypted message: %s\n", Alice.name, bob_plaintext)
    assert(bob_plaintext.decode("utf-8") == bob_msg)
