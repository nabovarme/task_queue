from hashlib import sha256
import binascii
from Crypto.Cipher import AES
import os
import codecs
import hmac
import hashlib
import base64


def create_key_from_master(master_hex_key):
    master_key = bytes.fromhex(master_hex_key)
    hex_key = sha256(master_key[:16]).hexdigest()
    return hex_key[:32], hex_key[32:]


# mqtt_message_l = encrypt_aes_hmac_combined(mqtt_message, topic, strlen(topic) + 1, cleartext, strlen(cleartext) + 1);
def encrypt(topic, message, aes_key_hex, sha_key_hex):
    byte_topic = bytes(topic, 'ascii')
    byte_message = bytes(message, 'ascii')

    # zero padding 
    missing_zeros = 16 - (len(byte_message) % 16)
    byte_topic += (b"\x00" * missing_zeros)

    # zero padding 
    missing_zeros = 16 - (len(byte_message) % 16)
    byte_message  += (b"\x00" * missing_zeros)

    byte_aes_key = binascii.unhexlify(aes_key_hex)
    byte_sha_key = binascii.unhexlify(sha_key_hex)

    # encrypt
    IV = "ABABABABABABABABABABABABABABABAB" # os.urandom(16)
    byte_IV = binascii.unhexlify(IV)
    encryptor = AES.new(byte_aes_key, AES.MODE_CBC, IV=byte_IV)
    hex_message = byte_message.hex()
    # hex to bytes
    text = binascii.unhexlify(hex_message)
    ciphertext = encryptor.encrypt(text)
    print("\ninput")
    print(byte_IV.hex())
    print(ciphertext.hex())
    print(byte_topic)
    # calculate cryptographic checksum
    dig = hmac.new(byte_sha_key, digestmod=hashlib.sha256)
    dig.update(byte_topic)
    dig.update(byte_IV + ciphertext)
    bytes_digest = dig.digest()

    cipher_hex = bytes_digest.hex().upper()
    print(cipher_hex, IV, ciphertext.hex())
    return (cipher_hex + IV + ciphertext.hex()).upper(), (byte_topic, cipher_hex, byte_IV, ciphertext)



# mqtt_message_l = decrypt_aes_hmac_combined(buffer, topic, strlen(topic) + 1, mqtt_message, mqtt_message_l);
def decrypt(topic, message, aes_key_hex, sha_key_hex, params):
    byte_topic = bytes(topic, 'ascii') + b"\x00"
    byte_message = bytes(message, 'ascii') 

    # zero padding 
    missing_zeros = 16 - (len(byte_message) % 16)
    #byte_topic += (b"\x00" * missing_zeros)

    # zero padding 
    missing_zeros = 16 - (len(byte_message) % 16)
    byte_message  += (b"\x00" * missing_zeros)

    byte_aes_key = binascii.unhexlify(aes_key_hex)
    byte_sha_key = binascii.unhexlify(sha_key_hex)

    cipher_hex = byte_message[:64]
    IV = binascii.unhexlify(byte_message[64:64+32])
    ciphertext = binascii.unhexlify(byte_message[64+32:].split(b'\0',1)[0])

    print()
    print(cipher_hex, params[1], cipher_hex.decode('ascii') == params[1])
    print(IV, params[2], IV  == params[2])
    print(ciphertext, params[3], ciphertext == params[3])
    print(byte_topic==params[0])
    dig = hmac.new(byte_sha_key, digestmod=hashlib.sha256)
    dig.update(byte_topic)
    dig.update(IV + ciphertext)
    bytes_digest = dig.digest()

    print(cipher_hex, bytes_digest, cipher_hex == bytes_digest )

#0000000000000000000000000000000000000000000000000000000000000000ababababababababababababababababd9a7ac43ecde9c99ce296275309bcc8cd919eeda5ede7775a111ef580bd642605313d539759101eabc376d6da58de2dbd3ae734028eb91d8d19405aa019506c4dd383c11a459b2ea132d9137b8db9332147d2b55ea7134cf9254f3a38729e2841ea8cd6d22a09435e2b42cc2635c4476

def test():
    master_key = "2b7e151628aed2a6abf7158809cf4f3c"

    message =  'heap=21376&t1=23.61 C&t2=22.19 C&tdif=1.42 K&flow1=0 l/h&effect1=0.0 kW&hr=73327 h&v1=1321.27 m3&e1=56.726 MWh&'
    topic = "/sample/v2/7210086/1466572820"

    aes_key, hmac_key = create_key_from_master(master_key)
    print(f'master_key: {master_key}, aes:{aes_key}, hmac:{hmac_key}')


    asserted_aes_key = "d4ffb8b77f7d6b26196e9a070e983f67"
    print(f'asserted_aes_key:{asserted_aes_key} == {aes_key} : {asserted_aes_key == aes_key}')
    assert asserted_aes_key == aes_key

    asserted_hmac_key = "01a4c42dec813d4de1a535d20a7df536"
    print(f'asserted_hmac_key:{asserted_hmac_key} == {hmac_key} : {asserted_hmac_key == hmac_key}')
    assert asserted_hmac_key == hmac_key

    ciphertext, params = encrypt(topic, message, aes_key, hmac_key)
    print(f'cipher_text: {ciphertext}')
    decrypted_message = decrypt(topic, ciphertext, aes_key, hmac_key, params)

    print("")

    print(f"decrypted_message: '{decrypted_message}' == '{message}'")
    assert message == decrypted_message

if __name__ == "__main__":
    test()