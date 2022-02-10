from flask import Flask, request, make_response

import json
from tb_rest_client.rest_client_ce import *
from tb_rest_client.rest import ApiException
import logging
import base64
from flask import json
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()
import os

# fix the URL for testing - TB setup on server
url = os.environ.get('URL')
tenant_username = os.environ.get('TENANT_USERNAME')
tenant_password = os.environ.get('TENANT_PASSWORD')

# This is supposed to be a rest API.... need to re-configure client every access (or login everytime you want to access TB)
def configureTBRestish(rest_client, token):
    rest_client.configuration.api_key_prefix["X-Authorization"] = "Bearer"
    rest_client.configuration.api_key["X-Authorization"] = token

    rest_client.api_client = ApiClient(rest_client.configuration)

    # rest_client.__load_controllers() - or just copy the requried code :(
    rest_client.audit_log_controller = AuditLogControllerApi(rest_client.api_client)
    rest_client.o_auth2_config_template_controller = OAuth2ConfigTemplateControllerApi(rest_client.api_client)
    rest_client.entity_view_controller = EntityViewControllerApi(rest_client.api_client)
    rest_client.entity_query_controller = EntityQueryControllerApi(rest_client.api_client)
    rest_client.o_auth2_controller = OAuth2ControllerApi(rest_client.api_client)
    rest_client.entity_relation_controller = EntityRelationControllerApi(rest_client.api_client)
    rest_client.rpc_v2_controller = RpcV2ControllerApi(rest_client.api_client)
    rest_client.edge_controller = EdgeControllerApi(rest_client.api_client)
    rest_client.admin_controller = AdminControllerApi(rest_client.api_client)
    rest_client.user_controller = UserControllerApi(rest_client.api_client)
    rest_client.asset_controller = AssetControllerApi(rest_client.api_client)
    rest_client.widgets_bundle_controller = WidgetsBundleControllerApi(rest_client.api_client)
    rest_client.tenant_profile_controller = TenantProfileControllerApi(rest_client.api_client)
    rest_client.event_controller = EventControllerApi(rest_client.api_client)
    rest_client.lwm2m_controller = Lwm2mControllerApi(rest_client.api_client)
    rest_client.dashboard_controller = DashboardControllerApi(rest_client.api_client)
    rest_client.component_descriptor_controller = ComponentDescriptorControllerApi(rest_client.api_client)
    rest_client.device_profile_controller = DeviceProfileControllerApi(rest_client.api_client)
    rest_client.customer_controller = CustomerControllerApi(rest_client.api_client)
    rest_client.telemetry_controller = TelemetryControllerApi(rest_client.api_client)
    rest_client.tenant_controller = TenantControllerApi(rest_client.api_client)
    rest_client.rpc_v1_controller = RpcV1ControllerApi(rest_client.api_client)
    rest_client.widget_type_controller = WidgetTypeControllerApi(rest_client.api_client)
    rest_client.device_controller = DeviceControllerApi(rest_client.api_client)
    rest_client.rule_chain_controller = RuleChainControllerApi(rest_client.api_client)
    rest_client.tb_resource_controller = TbResourceControllerApi(rest_client.api_client)
    rest_client.auth_controller = AuthControllerApi(rest_client.api_client)
    rest_client.queue_controller = QueueControllerApi(rest_client.api_client)
    rest_client.ota_package_controller = OtaPackageControllerApi(rest_client.api_client)
    rest_client.alarm_controller = AlarmControllerApi(rest_client.api_client)
    rest_client.edge_event_controller = EdgeEventControllerApi(rest_client.api_client)
    rest_client.sign_up_controller = SignUpControllerApi(rest_client.api_client)

    return rest_client

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(module)s - %(lineno)d - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

def get_custimer_id(token):

    # logging.info("Token info:\n%r", token)
    customer = json.loads(base64.b64decode(token.split('.')[1] + '====').decode('utf-8'))
    return customer['customerId'], customer['sub']

def get_customer_token(username, password):

    with RestClientCE(base_url=url) as rest_client:
        try:
            rest_client.login(username=username, password=password)
            # login never fails - need to call get_user() to see if user login was sucessful
            customer = rest_client.get_user()
            # logging.info("Token info:\n%r", rest_client.configuration.api_key["X-Authorization"])
            token = rest_client.configuration.api_key["X-Authorization"]

        except ApiException as e:
            logging.warning("failed to log in")
            return None, None

    return customer, token

def get_customer_devices(token):
    with RestClientCE(base_url=url) as rest_client:
        try:
            # rest_client.login(username=username, password=password)

            # logging.info("Token info:\n%r", rest_client.configuration.api_key["X-Authorization"])
            rest_client = configureTBRestish(rest_client, token)

            customer_id, email = get_custimer_id(token)
            res = rest_client.get_customer_device_infos(customer_id,page_size=str(100), page=str(0))

        except ApiException as e:
            logging.warning("failed to get devices")
            return None

    return res


def register_device_with_customer(customer_token, ieee_address, name, profile):

    with RestClientCE(base_url=url) as rest_client:
        if name is not None and profile is not None:
            try:

                tenant, token = get_customer_token(username=tenant_username, password=tenant_password)
                rest_client = configureTBRestish(rest_client, token)

                customer_id, email = get_custimer_id(customer_token)
                device = Device(name = ieee_address, label = name, type = profile)
                res = rest_client.save_device(device)
                logging.info("Device Created:\n")

            except ApiException as e:
                logging.warning("Device Exists:\n")

        try:
            res = rest_client.get_tenant_device(device_name = ieee_address)

            # update label and type if required
            if name is not None:
                res.label = name
            #  cannot change type :(
            # if type is not None:
            #     res.type = type
            if name is not None or profile is not None:
                res = rest_client.save_device(res)

        except ApiException as e:
            logging.warning("Unable to find devce:\n%r")
            return None

        try:
            up = rest_client.assign_device_to_customer(customer_id, res.id.id)
            # logging.info("Device info:\n%r", up)
            logging.info("Custioer assigned to device:\n")

        except ApiException as e:
            logging.warning("Unable to assign devce:\n%r")
            return None

    return up

def get_device_token(customer_token, mac):
    with RestClientCE(base_url=url) as rest_client:
        try:
            # rest_client.login(username=username, password=password)
            tenant, token = get_customer_token(username=tenant_username, password=tenant_password)
            rest_client = configureTBRestish(rest_client, token)

            customer_id, email = get_custimer_id(customer_token)
            res = rest_client.get_tenant_device(device_name = mac)

            if res.customer_id.id == customer_id:
                # customer has permission to get the token
                dev = rest_client.get_device_credentials_by_device_id(res)
                return dev.credentials_id

        except ApiException as e:
            logging.warning("failed to get devices")
            return None

    return res


@app.route('/login', methods=['POST'])
def login_user():

    auth = json.loads(request.data)
    if not auth or not auth['email'] or not auth['password']:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    customer, token = get_customer_token(auth['email'], auth['password'])

    if customer is None:
        return make_response({'Error': 'Failed to login'},  401 )

    print(customer.customer_id.id)
    # user = Users.query.filter_by(name=auth.username).first()

    # if check_password_hash(user.password, auth.password):
    #     token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    #     return jsonify({'token' : token.decode('UTF-8')})
    #

    return make_response({'sucess': 'true', 'token': token, 'customer': customer.customer_id.id},  200, )

# convert a list of devices to dicts
def list_to_dict(l):
    for i, s in enumerate(l):
        l[i] = s.to_dict()
    return l

@app.route('/device', methods=['GET'])
def get_all_devices():

    # body = json.loads(request.data)
    token = request.headers['authorization'].split(' ')[1]

    res = get_customer_devices(token)
    if res is None:
        return make_response({'Error': 'Failed to get devices'},  401 )

    data = list_to_dict(res.data)

    return make_response({'sucess': 'true', 'data': data},     200 )


@app.route('/register', methods=['POST'])
def register_device():

    body = json.loads(request.data)
    token = request.headers['authorization'].split(' ')[1]
    res = register_device_with_customer(token, body['ieee_address'], body['friendly_name'], 'default') # body['model_id'])
    if res is None:
        return make_response({'Error': 'Failed to create/update'},  401 )

    return make_response({'sucess': 'true', 'data': res.to_dict()},     200 )


@app.route('/devicetoken', methods=['GET'])
def get_token():

    if request.data == b'':
        return make_response({'Error': 'ieee_address required'},  401 )

    body = json.loads(request.data)
    token = request.headers['authorization'].split(' ')[1]

    res = get_device_token(token, body['ieee_address'])
    if res is None:
        return make_response({'Error': 'Failed to get device token'},  401 )

    return make_response({'sucess': 'true', 'token': res},     200 )

if  __name__ == '__main__':
    app.run(debug=True)
