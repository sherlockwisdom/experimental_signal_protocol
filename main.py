#!/usr/bin/env python3
def init():
    """
    initialization:
        - We agree to use dh_out.public_key
    """
    Alice = GENERATE_DH()
    Bob = GENERATE_DH(Alice.get_public_key())

    Alice_rk = Alice.generate_secret(Bob.get_public_key())
    Bob_rk = Bob.generate_secret()

    assert(Alice_rk == Bob_rk)
    Alice_kdf_rk, Alice_kdf_ck = KDF_RK(Alice_rk, Bob)
    Bob_kdf_rk, Bob_kdf_ck = KDF_RK(Bob_rk, Bob)

    assert(Alice_kdf_rk == Bob_kdf_rk)
    assert(Alice_kdf_ck == Bob_kdf_ck)

    return Alice_kdf_rk, Alice_kdf_ck, Bob_kdf_rk, Bob_kdf_ck

if __name__ == "__main__":
    # Alice_kdf_rk, Alice_kdf_ck, Bob_kdf_rk, Bob_kdf_ck = init()
    from person import Person

    Alice = Person("Alice")
    alice_pub_key = Alice.get_public_key()
    print("- hs_init_", Alice.name, alice_pub_key)

    Bob = Person("Bob", alice_pub_key)
    bob_pub_key = Bob.get_public_key()
    print("- hs_init_", Bob.name, bob_pub_key)

    Alice.init(bob_pub_key)

    alice_msg = "hello world"

    enc_alice_message = Alice.ratched_encrypt(alice_msg)
    dec_alice_message = Bob.ratched_decrypt(enc_alice_message)

    assert(dec_alice_message.decode("utf-8") == alice_msg)
