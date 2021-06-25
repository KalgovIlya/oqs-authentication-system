from flask import Flask, request, render_template, Response, send_file, redirect
import os, subprocess, consulate, atexit, socket, configparser, requests, json
from datetime import datetime, timedelta
from pymongo import MongoClient
import gridfs


def graceful_shutdown():
    consul.agent.service.deregister('certs')
    if os.environ['RUN_ENV'] == 'TEST':
        db.drop_collection(certs_collection)


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def run_command(cmd):
    p = subprocess.Popen(cmd)
    if p.wait() != 0:
        raise RuntimeError('Command failed')


def get_services(service_name):
    services = consul.agent.services()
    return 'http://{0}:{1}'.format(services[0][service_name]['Address'], services[0][service_name]['Port'])


def gen_cert_and_key(u_id):
    key_name = '{}.key'.format(u_id)
    crt_name = '{}.crt'.format(u_id)
    csr_name = '{}.csr'.format(u_id)
    run_command(['opt/openssl/apps/openssl', 'req', '-new', '-newkey',
                 'falcon1024', '-keyout', key_name,
                 '-out', csr_name, '-nodes', '-sha512', '-subj',
                 '/CN=Falcon1024 VPN Client/name=Falcon1024 Client', '-config',
                 'cert-exts.conf', '-extensions', 'client'])

    run_command(['opt/openssl/apps/openssl', 'x509', '-req', '-in', csr_name,
                 '-out', crt_name, '-CA', '/run/secrets/root_ca_crt',
                 '-CAkey', '/run/secrets/root_ca_key', '-CAcreateserial',
                 '-days', '30', '-sha512', '-extensions', 'client',
                 '-extfile', 'cert-exts.conf'])

    key_id = fs.put(open(key_name, 'rb'), filename=key_name, outdated=False, u_id=u_id)
    crt_id = fs.put(open(crt_name, 'rb'), filename=crt_name, outdated=False, u_id=u_id)

    run_command(['rm', key_name, crt_name, csr_name])

    data = {
        'user_id': u_id,
        'key_id': key_id,
        'crt_id': crt_id,
        'expiration_date': datetime.utcnow() + timedelta(days=30)
    }
    return data


def is_active(u_id):
    try:
        profile_url = get_services('register')
    except KeyError:
        return 'Service unavailable'
    resp = requests.post(
                        url='{}/is_active'.format(profile_url), 
                        data=json.dumps({'u_id': u_id}), 
                        headers={'Content-type': 'application/json', 'Accept': 'text/plain'}, 
                        timeout=3)
    data = json.loads(resp.text)         
    return data


def token_check(token):
    try:
        login_url = get_services('login')
    except KeyError:
        return 'Service unavailable'
    resp = requests.post(
                        url='{}/token_check'.format(login_url), 
                        data=json.dumps({'token': token}), 
                        headers={'Content-type': 'application/json', 'Accept': 'text/plain'},
                        timeout=3)
    data = json.loads(resp.text)
    return data


LOCAL_PORT = 5000
LOCAL_IP = get_local_ip()
atexit.register(graceful_shutdown)
consul = consulate.Consul(host=os.environ['CONSUL_IP'], port=os.environ['CONSUL_PORT'])
consul.agent.service.register('certs',
                              port=LOCAL_PORT,
                              tags=['certs'],
                              interval='10s',
                              httpcheck='http://{0}:{1}/healthcheck'.format(LOCAL_IP, LOCAL_PORT),
                              address=LOCAL_IP)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.debug = True
db = MongoClient('mongodb://{0}:{1}@{2}:27017/CertsDB'.format(
    os.environ['CERTS_DB_LOGIN'],
    os.environ['CERTS_DB_PASS'],
    os.environ['CERTS_DB_IP']
))['CertsDB']
config = configparser.ConfigParser()
config.read('settings.ini')
certs_collection = db[config[os.environ['RUN_ENV']]['certs_collection']]
fs = gridfs.GridFS(db)


@app.route('/healthcheck')
def health_check():
    return '', 200


@app.route('/')
@app.route('/cert', methods=['GET', 'POST'])
def cert():
    token = request.cookies.get('token')
    if token is None:
        return redirect('https://' + os.environ['HOST_IP'] + ':5000/login?next=cert', code=302)
    token_resp = token_check(token)
    if not token_resp['success']:
        return redirect('https://' + os.environ['HOST_IP'] + ':5000/login?next=cert', code=302)
    uid_check = is_active(token_resp['u_id'])
    if not uid_check['success']:
        return Response('Your account is inactive.', status=403)
    if request.method == 'GET':
        return render_template('cert.html')

    if request.form.get('ca_cert'):
        return send_file('/run/secrets/root_ca_crt', attachment_filename='ca.crt', as_attachment=True)
    if request.form.get('key'):
        file_format = 'key'
    elif request.form.get('crt'):
        file_format = 'crt'
    else:
        return 'Invalid request'

    headers = {"Content-disposition": "attachment; filename=client.{}".format(file_format)}
    user_entry = certs_collection.find_one({'user_id': token_resp['u_id']})
    if user_entry is not None:
        if user_entry['expiration_date'] > datetime.utcnow():
            return Response(fs.get(user_entry['{}_id'.format(file_format)]).read(), headers=headers)
        else:
            db.fs.files.update_one({'_id': user_entry['key_id']}, {'$set': {'outdated': True}})
            db.fs.files.update_one({'_id': user_entry['crt_id']}, {'$set': {'outdated': True}})
            updated_data = gen_cert_and_key(user_entry['u_id'])
            certs_collection.replace_one({'user_id': user_entry['u_id']}, updated_data)
            return Response(fs.get(updated_data['{}_id'.format(file_format)]).read(), headers=headers)
    else:
        data = gen_cert_and_key(token_resp['u_id'])
        certs_collection.insert_one(data)
        return Response(fs.get(data['{}_id'.format(file_format)]).read(), headers=headers)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
