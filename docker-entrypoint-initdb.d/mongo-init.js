db = db.getSiblingDB('UsersDB');
db.createUser(
    {
        user: 'users_admin',
        pwd:  'password',
        roles: [{role: 'readWrite', db: 'UsersDB'}],
    }
);
db.createCollection('users');
db.createCollection('userstest');


db.userstest.insertOne( {
    email: 'test@test.ru',
    password: '25d55ad283aa400af464c76d713c07ad',
    first_name: 'admin',
    last_name: 'admin',
    is_superuser: true,
    is_active: true
    } );


db = db.getSiblingDB('TokensDB');
db.createUser(
    {
        user: 'tokens_admin',
        pwd:  'password',
        roles: [{role: 'readWrite', db: 'TokensDB'}],
    }
);
db.createCollection('tokens');
db.createCollection('tokenstest');

db = db.getSiblingDB('CertsDB');
db.createUser(
    {
        user: 'certs_admin',
        pwd:  'password',
        roles: [{role: 'readWrite', db: 'CertsDB'}],
    }
);
db.createCollection('certs');
db.createCollection('certstest');
