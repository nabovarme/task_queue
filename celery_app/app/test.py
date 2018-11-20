import logging
import asyncio
import time
import os
from hbmqtt.client import MQTTClient, ClientException
from hbmqtt.mqtt.constants import QOS_1, QOS_2

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MQTT_SERVER = os.environ['MQTT_SERVER']


def rpc_call(topic_pub, topic_sub, params, timeout=30):
    end_time = time.time() + timeout
    @asyncio.coroutine
    def inner_rpc_call():
        result = None
        C = MQTTClient()
        yield from C.connect(MQTT_SERVER)
        yield from C.subscribe([
            (topic_sub, QOS_1)
        ])
        tasks = [
            asyncio.ensure_future(C.publish(topic_pub, b'TEST MESSAGE WITH QOS_0'))
        ]
        yield from asyncio.wait(tasks)
        logger.info("messages published")
        try:
            timeout = end_time - time.time() 
            logging.info(f'timeout in {timeout}')
            message = yield from C.deliver_message(timeout=timeout)
            packet = message.publish_packet
            result_topic_name = packet.variable_header.topic_name
            result = packet.payload.data
            yield from C.unsubscribe(['$SYS/broker/uptime', '$SYS/broker/load/#'])
        except ClientException as ce:
            logger.error("Client exception: %s" % ce)
        finally:
            yield from C.disconnect()
        return result

    return asyncio.get_event_loop().run_until_complete(inner_rpc_call())


def test():
    topic_sub = "$SYS/broker/uptime"
    topic_pub = "'a/b"
    print(rpc_call(topic_pub, topic_sub, {}))

if __name__ == '__main__':
    os.environ['MQTT_SERVER'] = 'mqtt://test.mosquitto.org/'
    test()