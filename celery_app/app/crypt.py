from hashlib import sha256
import binascii
from Crypto.Cipher import AES
import os
import codecs
import hmac
import hashlib
import base64


class ChecksumError(ValueError):
    pass

def create_key_from_master(master_hex_key):
    master_key = bytes.fromhex(master_hex_key)
    hex_key = sha256(master_key[:16]).hexdigest()
    return hex_key[:32], hex_key[32:]


# mqtt_message_l = encrypt_aes_hmac_combined(mqtt_message, topic, strlen(topic) + 1, cleartext, strlen(cleartext) + 1);
def encrypt(topic, message, hex_aes_key, hex_sha_key):
    # turn the topic and message into bytearrays
    byte_topic = bytes(topic, 'ascii')
    byte_message = bytes(message, 'ascii')

    # zero pad the message
    missing_zeros = 16 - (len(byte_message) % 16)
    byte_message  += (b"\x00" * missing_zeros)

    # turn the hex crypto keys into bytearrays
    byte_aes_key = binascii.unhexlify(hex_aes_key)
    byte_sha_key = binascii.unhexlify(hex_sha_key)

    # create IV for use in hmac and resulting mqtt message
    byte_IV = os.urandom(16)

    # create aes encryptor
    encryptor = AES.new(byte_aes_key, AES.MODE_CBC, IV=byte_IV)

    # encrypt byte message with AES
    byte_encrypted_message = encryptor.encrypt(byte_message)

    # compute sha256 checksum
    dig = hmac.new(byte_sha_key, digestmod=hashlib.sha256)
    dig.update(byte_topic)
    dig.update(byte_IV + byte_encrypted_message)
    bytes_checksum = dig.digest()

    # create mqtt message in following format CHECKSUM + IV + ENCRYPTED_MESSAGE
    mqtt_message = (bytes_checksum.hex() + byte_IV.hex() + byte_encrypted_message.hex()).lower()
    return mqtt_message


# mqtt_message_l = decrypt_aes_hmac_combined(buffer, topic, strlen(topic) + 1, mqtt_message, mqtt_message_l);
def decrypt(topic, message, hex_aes_key, hex_sha_key):
    # turn the topic and message into bytearrays
    byte_topic = bytes(topic, 'ascii')
    byte_message = bytes(message, 'ascii')


    # turn the hex crypto keys into bytearrays
    byte_aes_key = binascii.unhexlify(hex_aes_key)
    byte_sha_key = binascii.unhexlify(hex_sha_key)

    # unpack checksum
    byte_checksum = byte_message[:64]
    hex_checksum = byte_checksum.decode('ascii')

    # unpack IV
    hex_IV = byte_message[64:64+32]
    byte_IV = binascii.unhexlify(hex_IV)

    # compute sha256 checksum
    hex_encrypted_message = byte_message[64+32:]
    byte_encrypted_message = binascii.unhexlify(hex_encrypted_message)

    # compute sha256 checksum
    dig = hmac.new(byte_sha_key, digestmod=hashlib.sha256)
    dig.update(byte_topic)
    dig.update(byte_IV + byte_encrypted_message)
    byte_checksum_calculated = dig.digest()

    # get calculated checksum as hex
    hex_checksum_calculated = byte_checksum_calculated.hex()
    
    # compare checksum with computed checksum
    if not hex_checksum == hex_checksum_calculated:
        raise ChecksumError(f"incomming checksum: '{hex_checksum}' is not equal to calculated checksum: '{hex_checksum_calculated}'")
        
    # create decryptor from AES key and IV
    decryptor = AES.new(byte_aes_key, AES.MODE_CBC, IV=byte_IV)

    # decrypt encrypted message
    decrypted_text = decryptor.decrypt(byte_encrypted_message)

    # decode message as ascii
    return decrypted_text.decode('ascii')

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

    ciphertext = encrypt(topic, message, aes_key, hmac_key)
    print(f'cipher_text: {ciphertext}')
    decrypted_message = decrypt(topic, ciphertext, aes_key, hmac_key)

    print(f"decrypted_message: '{decrypted_message}' == '{message}'")
    assert message == decrypted_message


def test_2():
    master_key = "2b7e151628aed2a6abf7158809cf4f3c"
    aes_key, hmac_key = create_key_from_master(master_key)

    message =  'heap=21376&t1=23.61 C&t2=22.19 C&tdif=1.42 K&flow1=0 l/h&effect1=0.0 kW&hr=73327 h&v1=1321.27 m3&e1=56.726 MWh&'
    topic = "/sample/v2/7210086/1466572820"
    ciphertext = encrypt(topic, message, aes_key, hmac_key)
    decrypted_message = decrypt(topic, ciphertext, aes_key, hmac_key)
    assert decrypted_message == message

if __name__ == "__main__":
    test_2()