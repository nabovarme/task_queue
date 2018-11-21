import logging
import asyncio
import time
import os
from hbmqtt.client import MQTTClient, ClientException
from hbmqtt.mqtt.constants import QOS_0,QOS_1, QOS_2
import crypt
import binascii

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MQTT_SERVER = os.environ['MQTT_SERVER']

def rpc_call(topic_pub, topic_sub, message, master_key, timeout=30):
    end_time = time.time() + timeout
    @asyncio.coroutine
    def inner_rpc_call():
        result = None
        aes_key, hmac_key = crypt.create_key_from_master(master_key)

        encrypted_message = crypt.encrypt(topic_pub, message, aes_key, hmac_key)
        encrypted_byte_message = bytearray.fromhex(encrypted_message)

        C = MQTTClient()
        yield from C.connect(MQTT_SERVER)
        yield from C.subscribe([
            (topic_sub, QOS_0)
        ])
        tasks = [
            asyncio.ensure_future(C.publish(topic_pub, encrypted_byte_message))
        ]
        yield from asyncio.wait(tasks)
     
        logger.info("messages published")
        try:
            timeout = end_time - time.time() 
            logging.info(f'timeout in {timeout}')
            encrypted_answer = yield from C.deliver_message(timeout=timeout)
            packet = encrypted_answer.publish_packet
            result_topic_name = packet.variable_header.topic_name
            result = packet.payload.data
            result = crypt.decrypt(topic_sub, result.hex(), aes_key, hmac_key)
            yield from C.unsubscribe([topic_sub])
        except ClientException as ce:
            logger.error("Client exception: %s" % ce)
        finally:
            yield from C.disconnect()
        return result

    return asyncio.get_event_loop().run_until_complete(inner_rpc_call())


def test():
    serial=os.environ['SERIAL']	
    unixtime = int(time.time())
    master_key= os.environ['MASTER_KEY']
    topic_sub = f"/uptime/v2/{serial}/#"
    topic_pub = f"/config/v2/{serial}/{unixtime}/uptime"
    message='1'
    print(rpc_call(topic_pub, topic_sub, message, master_key))

if __name__ == '__main__':
    os.environ['MQTT_SERVER'] = 'mqtt://test.mosquitto.org/'
    test()