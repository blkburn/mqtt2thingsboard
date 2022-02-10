# MQTT 2 Thingsboard

This is a simple helper to allow zigbee sensors (through zigbee2mqtt) to automatically register with ThingsBoard.

mqtt.py scans "zigbee2mqtt/bridge/devices" and checks if a device is regsitered on ThingsBoard,
if not, it registers the device and assigns a customer (defined in .env).
If a broadcast message ends in a friendlyname it is passed to the MQTT API of the ThingsBord server (IP address defined in .env)

app.y if a Flask App that brdiges the ThingsBoard API with mqtt.py. It handles the registration requests, get customer tokens, etc.

(not very robust yet - still in development)

run the flask app  
$ export FLASK_APP=app.py  
$ flask run  

run mqtt.py  
$ python3 mqtt.py  
