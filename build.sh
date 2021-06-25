#!/bin/bash
OQS_OPENSSL=$PWD/oqs-openssl/openssl
DAYS=3650
SIG_ALG=falcon1024

#generate nginx certs and keys
${OQS_OPENSSL} req -x509 -new -nodes -newkey rsa:4096 -days ${DAYS} -keyout nginx_ca.key -out nginx_ca.crt -config cert_exts.conf -extensions nginx_ca
${OQS_OPENSSL} req -new -newkey ${SIG_ALG} -keyout nginx_server.key -out nginx_server.csr -nodes -config cert_exts.conf -extensions nginx_server
${OQS_OPENSSL} x509 -req -in nginx_server.csr -out nginx_server.crt -CA nginx_ca.crt -CAkey nginx_ca.key -CAcreateserial -days 365 -extensions nginx_server -extfile cert_exts.conf

#generate cert_service root ca and key
${OQS_OPENSSL} genpkey -algorithm falcon1024 -out root_ca.key
${OQS_OPENSSL} req -x509 -key root_ca.key -out root_ca.crt -subj "/CN=Falcon1024 CA/name=Falcon1024 CA" -days ${DAYS} -sha512 -config $PWD/cert/cert-exts.conf -extensions root_ca
#generate openvpn server cert and key
${OQS_OPENSSL} req -new -newkey falcon1024 -keyout server.key -out server.csr -nodes -sha512 -subj "/CN=Falcon1024 VPN Server/name=Falcon1024 VPN Server" -config cert_exts.conf -extensions openvpn_server
${OQS_OPENSSL} x509 -req -in server.csr -out server.crt -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -days ${DAYS} -sha512 -extensions openvpn_server -extfile cert_exts.conf
#build docker images
cd  $PWD/login && docker build -t 'login_service' .
cd  ../register && docker build -t 'register_service' .
cd  ../cert && docker build -t 'cert_service' . --network=host
cd  ../nginx/ && docker build -t 'oqs_nginx' . --network=host
#copy root cert, server key and server cert in openvpn directory
cd ..
cp root_ca.crt server.crt server.key /usr/local/openvpn/etc/keys/
#restart openvpn service
systemctl restart pq-openvpn.service

#remove csr files
rm server.csr nginx_server.csr 
