import paho.mqtt.client as mqtt
import time
import json
import paho.mqtt.publish as publish
import requests
from dotenv import load_dotenv

load_dotenv()
import os

mqtt_thingsboard = os.environ.get('MQTT_THINGSBOARD')
customer_username = os.environ.get('CUSTOMER_USERNAME')
customer_password = os.environ.get('CUSTOMER_PASSWORD')
mqttBroker = os.environ.get('MQTT_BROKER')
mqttName = os.environ.get('MQTT_NAME')

# mosquitto_pub -d -q 1 -h "www.springfield-analytics.com" -t "v1/devices/me/telemetry" -u "WTeQoQgxOKAmIQ81cD4C" -m "{"temperature":45}" -p 1883
device_keys = ["friendly_name", "ieee_address", "interview_completed","manufacturer", "model_id" ]
local_devices = {}
jwt = ''

def extract_devices(payload):
    login = {"email": customer_username, "password": customer_password}
    r = requests.post('http://127.0.0.1:5000/login', json=login)
    if r.status_code == 200:
        jwt = r.json()['token']
    else:
        print(r.status_code)

    for device in payload:
        if device["friendly_name"] == "Coordinator":
            continue
        if device["ieee_address"] not in local_devices:
            # add the device to the local set
            try:
                local_devices[device["ieee_address"]]  = {x:device[x] for x in device_keys}
            except KeyError:
                print('Unknown Deivce: ' + device["ieee_address"])
                continue
        # check if the device exists in thingsboard else create it
        if jwt != '':
            ieee_address = local_devices[device["ieee_address"]]
            if 'token' not in ieee_address:
                body = {"ieee_address": ieee_address["ieee_address"]}
                r = requests.get('http://127.0.0.1:5000/devicetoken', json=body, headers={'Authorization': 'bearer: ' + jwt})
                if r.status_code == 200:
                    ieee_address['token'] = r.json()['token']
                elif r.status_code == 401:
                    # create a new device
                    body = {"ieee_address": ieee_address["ieee_address"], "friendly_name": ieee_address["friendly_name"], "model_id": "default"}
                    r = requests.post('http://127.0.0.1:5000/register', json=body, headers={'Authorization': 'bearer: ' + jwt})
                    if r.status_code == 200:
                        body = {"ieee_address": ieee_address["ieee_address"]}
                        r = requests.get('http://127.0.0.1:5000/devicetoken', json=body, headers={'Authorization': 'bearer: ' + jwt})
                        if r.status_code == 200:
                            ieee_address['token'] = r.json()['token']
                    else:
                        print("Error:" + r.status_code)
                else:
                    print("Error:" + r.status_code)

    print(local_devices)

def on_message(client, userdata, message):

    print(str(message.topic))
    # # check for bridge info
    if "bridge/devices" in message.topic:
        extract_devices(json.loads(message.payload))
        print("bridge info updated")

    else:
        # only pass on actual devices to thingsboard server
        for device in local_devices:
            if str(message.topic).endswith(local_devices[device]['friendly_name']):
                #pass it on
                if 'token' in local_devices[device]:
                    token = local_devices[device]['token']
                    publish.single(topic="v1/devices/me/telemetry", payload=str(message.payload.decode("utf-8")), hostname=mqtt_thingsboard , auth={ 'username': token})
                    print("received message: " ,str(message.payload.decode("utf-8")))
                    print("received message topic: " ,str(message.topic))
                else:
                    print("invalid token. received message topic: " ,str(message.topic))



client = mqtt.Client(mqttName)
client.connect(mqttBroker)
client.subscribe("#")
client.on_message=on_message
client.loop_forever()
