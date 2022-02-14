import datetime
import logging

import asyncio

import aiocoap.resource as resource
import aiocoap
import json
import requests
from dotenv import load_dotenv

load_dotenv()
import os

mqtt_thingsboard = os.environ.get('MQTT_THINGSBOARD')
customer_username = os.environ.get('CUSTOMER_USERNAME')
customer_password = os.environ.get('CUSTOMER_PASSWORD')
mqttBroker = os.environ.get('MQTT_BROKER')
mqttName = os.environ.get('MQTT_NAME')

local_devices = {}
jwt = ''

class context():

    async def load_context(self):
        self.context = await aiocoap.Context.create_client_context()

context = context()

class BlockResource(resource.Resource):
    """Example resource which supports the GET and PUT methods. It sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()
        self.content = ""

    def add_device(self):
        print(self.content['eui64'])
        login = {"email": customer_username, "password": customer_password}
        r = requests.post('http://127.0.0.1:5000/login', json=login)
        if r.status_code == 200:
            jwt = r.json()['token']
        else:
            print(r.status_code)
        try:
            local_devices[self.content['eui64']] = {'eui64': self.content['eui64']}
        except KeyError:
            print('Unknown Deivce: ' + self.content['eui64'])

        # check if the device exists in thingsboard else create it
        if jwt != '':
            ieee_address = local_devices[self.content['eui64']]
            if 'token' not in ieee_address:
                body = {"ieee_address": ieee_address["eui64"]}
                r = requests.get('http://127.0.0.1:5000/devicetoken', json=body, headers={'Authorization': 'bearer: ' + jwt})
                if r.status_code == 200:
                    ieee_address['token'] = r.json()['token']
                elif r.status_code == 401:
                    # create a new device
                    body = {"ieee_address": ieee_address["eui64"], "friendly_name": ieee_address["eui64"], "model_id": "default"}
                    r = requests.post('http://127.0.0.1:5000/register', json=body, headers={'Authorization': 'bearer: ' + jwt})
                    if r.status_code == 200:
                        body = {"ieee_address": ieee_address["eui64"]}
                        r = requests.get('http://127.0.0.1:5000/devicetoken', json=body, headers={'Authorization': 'bearer: ' + jwt})
                        if r.status_code == 200:
                            ieee_address['token'] = r.json()['token']
                    else:
                        print("Error:" + r.status_code)
                else:
                    print("Error:" + r.status_code)

    # print(local_devices)


    async def render_get(self, request):
        return aiocoap.Message(payload=self.content)

    async def render_put(self, request):

        print('PUT payload: %s' % request.payload)
        self.content = json.loads(request.payload)
        self.content["eui64"] = '0x' + self.content["eui64"]
        if self.content["eui64"] not in local_devices:
            self.add_device()

        token = local_devices[self.content["eui64"]]['token']
        self.content.pop('eui64', None)
        self.content = json.dumps(self.content).encode('utf-8')
        request = aiocoap.Message(code=aiocoap.POST, payload=self.content, uri="coap://"+mqtt_thingsboard+"/api/v1/"+token+"/telemetry")
        response = await context.context.request(request).response
        print('Result: %s\n%r'%(response.code, response.payload))

        print(local_devices)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=request.payload)

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

async def main():
    await context.load_context()
    # Resource tree creation
    root = resource.Site()

    root.add_resource(['.well-known', 'core'],
                      resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['sensor', 'v1'], BlockResource())

    await aiocoap.Context.create_server_context(root)
    # await aiocoap.Context.create_server_context(root, bind = ("::", 5684))

    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())