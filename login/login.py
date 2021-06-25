from flask import Flask, redirect, request, render_template, make_response, Response
import os, requests, json, consulate, atexit, socket, configparser
from pymongo import MongoClient
from login_form import LoginForm
from datetime import timedelta, datetime
from uuid import uuid4
import urllib.parse
from bson import ObjectId


def graceful_shutdown():
    consul.agent.service.deregister('login')
    if os.environ['RUN_ENV'] == 'TEST':
        tokens_db.drop_collection(tokens_collection)


def get_services(service_name):
    services = consul.agent.services()
    return 'http://{0}:{1}'.format(services[0][service_name]['Address'], services[0][service_name]['Port'])


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def logpass_check(email, password):
    try:
        register_url = get_services('register')
    except KeyError:
        return 'Service unavailable'
    data = {'email': email,
            'password': password}
    resp = requests.post(
                        url='{}/logpass_check'.format(register_url), 
                        data=json.dumps(data), 
                        headers={'Content-type': 'application/json', 'Accept': 'text/plain'},
                        timeout=3)
    data = json.loads(resp.text)
    return data


LOCAL_PORT = 5000
LOCAL_IP = get_local_ip()
atexit.register(graceful_shutdown)
consul = consulate.Consul(host=os.environ['CONSUL_IP'], port=os.environ['CONSUL_PORT'])
consul.agent.service.register('login',
                              port=LOCAL_PORT,
                              tags=['login'],
                              interval='10s',
                              httpcheck='http://{0}:{1}/healthcheck'.format(LOCAL_IP, LOCAL_PORT),
                              address=LOCAL_IP)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.debug = True
app.url_map.strict_slashes = False

tokens_db = MongoClient('mongodb://{0}:{1}@{2}:27017/TokensDB'.format(
    os.environ['TOKENS_DB_LOGIN'],
    os.environ['TOKENS_DB_PASS'],
    os.environ['TOKENS_DB_IP']
))['TokensDB']

config = configparser.ConfigParser()
config.read('settings.ini')
tokens_collection = tokens_db[config[os.environ['RUN_ENV']]['tokens_collection']]




@app.route('/healthcheck')
def health_check():
    return '', 200


@app.route('/')
def index():
    if os.environ['RUN_ENV'] == 'TEST':
        return 'TEST'
    return 'Hello there!'


@app.route('/login', methods=['GET', 'POST'])
def login():
    token = request.cookies.get('token')
    db_token = tokens_collection.find_one({'token': token})
    if db_token is not None:
        if datetime.utcnow() <= db_token['token_expires_time']:
            return 'You are already logged in'
        else:
            tokens_collection.remove({'token': token})
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        data = logpass_check(form.email.data, form.password.data)
        if not data['success']:
            return 'Invalid credentials'
        token = str(uuid4())
        token_time = datetime.utcnow()
        new_token = {
            'token': token,
            'user_id': data['u_id'],
            'token_received_time': token_time,
            'token_expires_time': token_time + timedelta(days=31)
        }
        t_id = tokens_collection.insert_one(new_token)
        if request.form.get("next") != '':
            resp = make_response(redirect('https://' + os.environ['HOST_IP'] + ':5000/' + request.form.get("next")))
        else:
            resp = make_response({'success': t_id.acknowledged, 'token_id': str(t_id.inserted_id)})
        resp.set_cookie('token', token, expires=new_token['token_expires_time'])
        return resp
    return render_template('login.html', form=form)


@app.route('/token_check', methods=['POST'])
def token_check():
    req = request.get_json()
    data = {'u_id': '',
            'success': False}
    token = tokens_collection.find_one({'token': req['token']})
    if token is None:
        return data
    if datetime.utcnow() <= token['token_expires_time']:
        data['u_id'] = token['user_id']
        data['success'] = True
    return data


@app.route('/logout')
def logout():
    token = request.cookies.get('token')
    db_token = tokens_collection.find_one({'token': token})
    if db_token is not None:
        tokens_collection.remove({'token': token})
    resp = make_response('Logged out')
    resp.set_cookie('token', '', expires=0)
    return resp


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
