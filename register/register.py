import atexit, consulate, os, socket, configparser, requests, json
from hashlib import md5
from flask import Flask, render_template, request, make_response, redirect, Response
from pymongo import MongoClient
from register_form import RegistrationForm, ProfileForm
from bson import ObjectId
from json import dumps, loads
from flask_admin import Admin, AdminIndexView, expose
from wtforms import form, fields
from flask_admin.form import Select2Widget
from flask_admin.contrib.pymongo import ModelView, filters


def graceful_shutdown():
    consul.agent.service.deregister('register')
    if os.environ['RUN_ENV'] == 'TEST':
        db.drop_collection(users_collection)


def get_services(service_name):
    services = consul.agent.services()
    return 'http://{0}:{1}'.format(services[0][service_name]['Address'], services[0][service_name]['Port'])


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


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


class DashboardView(AdminIndexView):
    def is_visible(self):
        return False
    @expose('/')
    def index(self):
        token = request.cookies.get('token')
        if token is None:
            return Response('', status=403)
        token_resp = token_check(token)
        if not token_resp['success']:
            return Response('', status=403)
        user_entry = users_collection.find_one({'_id': ObjectId(token_resp['u_id'])})
        if user_entry['is_superuser']:
            return super(DashboardView, self).index()
        return Response('', status=403)
        
class UserForm(form.Form):
    email = fields.TextField('Email', render_kw={'disabled':''})
    first_name = fields.TextField('First name', render_kw={'disabled':''})
    last_name = fields.TextField('Last name', render_kw={'disabled':''})
    is_active = fields.BooleanField('Active account')
    

class UserView(ModelView):
    column_list = ('first_name', 'last_name', 'email', 'is_active')
    column_sortable_list = ('first_name', 'last_name','email', 'is_active')

    form = UserForm
    can_create = False
    can_delete = False

    column_filters = (filters.FilterEqual('email', 'Email'),
                      filters.BooleanEqualFilter('is_active', 'Active account'))
    
    def is_accessible(self):
        token = request.cookies.get('token')
        if token is None:
            return False
        token_resp = token_check(token)
        if not token_resp['success']:
            return False
        user_entry = users_collection.find_one({'_id': ObjectId(token_resp['u_id'])})
        return user_entry['is_superuser']
    
    def inaccessible_callback(self, name, **kwargs):
        return Response('', status=403)


LOCAL_PORT = 5000
LOCAL_IP=get_local_ip()
consul = consulate.Consul(host=os.environ['CONSUL_IP'], port=os.environ['CONSUL_PORT'])
consul.agent.service.register('register',
                              port=LOCAL_PORT,
                              tags=['register'],
                              interval='10s',
                              httpcheck='http://{0}:{1}/healthcheck'.format(LOCAL_IP, LOCAL_PORT),
                              address=LOCAL_IP)
atexit.register(graceful_shutdown)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.debug = True
app.url_map.strict_slashes = False
admin = Admin(app, index_view=DashboardView(), name='User activation')

config = configparser.ConfigParser()
config.read('settings.ini')

db = MongoClient('mongodb://{0}:{1}@{2}:27017/UsersDB'.format(
    os.environ['USERS_DB_LOGIN'],
    os.environ['USERS_DB_PASS'],
    os.environ['USERS_DB_IP']
))['UsersDB']
users_collection = db[config[os.environ['RUN_ENV']]['users_collection']]
admin.add_view(UserView(users_collection, 'Users'))

@app.route('/healthcheck')
def health_check():
    return '', 200


@app.route('/')
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        form = RegistrationForm(request.form)
        if form.validate():
            if users_collection.find_one({'email': form.email.data}) is not None:
                return 'Account already exists for this email address'
            else:
                new_user = {
                    'email': form.email.data,
                    'password': md5(form.password.data.encode()).hexdigest(),
                    'first_name': form.first_name.data,
                    'last_name': form.last_name.data,
                    'is_superuser': False,
                    'is_active': False
                }
            u_id = users_collection.insert_one(new_user)
            return make_response({'success': u_id.acknowledged, 'u_id': str(u_id.inserted_id)})
    return render_template('register.html', form=RegistrationForm())


@app.route('/logpass_check', methods=['POST'])
def logpass_check():
    req = request.get_json()
    data = {'u_id': '',
            'success': False}
    db_user = users_collection.find_one({'email': req['email']})
    if db_user is None:
        return data
    if md5(req['password'].encode()).hexdigest() == db_user['password']:
        data['u_id'] = str(db_user['_id'])
        data['success'] = True
    return data



@app.route('/profile', methods=['GET', 'POST'])
def profile():
    token = request.cookies.get('token')
    if token is None:
        return redirect('https://' + os.environ['HOST_IP'] + ':5000/login?next=profile', code=302)
    token_resp = token_check(token)
    if not token_resp['success']:
        return redirect('https://' + os.environ['HOST_IP'] + ':5000/login?next=profile', code=302)
    user_entry = users_collection.find_one({'_id': ObjectId(token_resp['u_id'])})
    if request.method == 'POST':
        form = ProfileForm(request.form)
        if form.validate():
            user_entry['first_name'] = form.first_name.data
            user_entry['last_name'] = form.last_name.data
            users_collection.replace_one({'_id': user_entry['_id']}, user_entry)
            return 'Profile updated successfully'
        return 'Invalid data'

    form = ProfileForm(first_name=user_entry['first_name'],
                        last_name=user_entry['last_name'])
    profile_is_active = (
        "Your account is inactive. Contact your administrator to activate it.", 
        "Your account has been activated successfully.")[user_entry['is_active']]
    return render_template('profile.html', form=form, is_active=profile_is_active)


@app.route('/is_active', methods=['POST'])
def is_active_profile():
    req = request.get_json()
    user_entry = users_collection.find_one({'_id': ObjectId(req['u_id'])})
    data = {'success': user_entry['is_active']}
    return data

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
