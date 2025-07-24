#!/bin/sh
. config.env
export PKI_DNS NAMESPACE K8S_DNS_SUFFIX 

read -p "Create docker volumes www and pki for testing in Kubernetes in Docker Decktop? y or n: " CREATE_VOLUMES
if [ "${CREATE_VOLUMES}" == "y" ]; then
  docker volume create www
  docker volume create pki
fi

#create configMap for openssl.cnf
envsubst '$PKI_DNS' < etc/ssl/openssl.cnf | tee /tmp/openssl.cnf
kubectl create cm openssl-cnf --from-file=/tmp/openssl.cnf
#mount it under /etc/ssl in nginx, php-fpm, init and test deployments

#create root CA cert in both forms PEM and DER
echo "Creating Root CA cert..."
openssl req -x509 -newkey rsa:4096 -subj /CN=$ROOT_CA_CN -extensions v3_ca_root -config /tmp/openssl.cnf -days 3650 -out /tmp/root_ca.pem -keyout /tmp/root_ca.key -noenc
echo "Creating Root CA cert...done"
if [ $? == 0 ]; then
  echo "Converting Root CA cert to DER...done"
fi
openssl x509 -inform PEM -outform DER -in /tmp/root_ca.pem -out /tmp/root_ca.der
kubectl create secret tls root-ca --cert /tmp/root_ca.pem --key /tmp/root_ca.key
#mount root_ca tls.crt as /etc/ssl/root_ca.pem and tls.key as /etc/ssl/private/root_ca.key in nginx and init deployments
kubectl create cm root-ca-crt --from-file=/tmp/root_ca.der
#mount root_ca_crt as /etc/ssl/root_ca.der in php-fpm, init and test deployments and as /var/www/pki/pki/root_ca.crt in nginx and test deployments

#create signing CA subordinate cert in both forms PEM and DER
#sed 's/2048/4096/' /tmp/openssl.cnf
echo "Creating Signing CA cert..."
openssl req -CA /tmp/root_ca.pem -CAkey /tmp/root_ca.key -newkey rsa:4096 -subj /CN=$SIGNING_CA_CN -extensions v3_ca_sub -config /tmp/openssl.cnf -days 3650 -out /tmp/signing_ca.pem -keyout /tmp/signing_ca.key -noenc
if [ $? == 0 ]; then
  echo "Creating Signing CA cert...done"
fi
openssl x509 -inform PEM -outform DER -in /tmp/signing_ca.pem -out /tmp/signing_ca.der
cat /tmp/root_ca.pem >> /tmp/signing_ca.pem
kubectl create secret tls signing-ca --cert /tmp/signing_ca.pem --key /tmp/signing_ca.key
#mount signing_ca tls.crt as /etc/ssl/signing_ca.pem
kubectl create cm signing-ca-crt --from-file=/tmp/signing_ca.der
#mount signing_ca_crt as /etc/ssl/signing_ca.der in php-fpm, init and test deployments and as /var/www/pki/pki/signing_ca.crt in nginx deployment
#sed 's/4096/2048/' /tmp/openssl.cnf

#chain root and signing CAs
cat /tmp/signing_ca.pem /tmp/root_ca.pem | tee /tmp/ca_chain.pem
kubectl create cm ca-chain-pem --from-file=/tmp/ca_chain.pem
#mount ca_chain_pem under /etc/ssl in test, nginx, php-fpm deployments

#create PKI server cert in both forms
echo "Creating PKI server cert..."
openssl req -CA /tmp/signing_ca.pem -CAkey /tmp/signing_ca.key -subj /CN=$PKI_DNS -extensions usr_cert -addext "subjectAltName=DNS:$PKI_DNS" -config /tmp/openssl.cnf -days 365 -out /tmp/pki.pem -keyout /tmp/pki.key -noenc
if [ $? == 0 ]; then
  echo "Creating PKI server cert...done"
fi
cat /tmp/signing_ca.pem >> /tmp/pki.pem
openssl x509 -inform PEM -outform DER -in /tmp/pki.pem -out /tmp/pki.der
kubectl create secret tls pki --cert /tmp/pki.pem --key /tmp/pki.key
#mount pki secret tls.crt as /etc/ssl/pki.pem and tls.key as /etc/ssl/private/pki.key in nginx deployment
kubectl create cm pki-crt --from-file=/tmp/pki.der

#create FPM server cert in both forms, chain it with signing CA
echo "Creating PHP-FPM server cert..."
openssl req -CA /tmp/signing_ca.pem -CAkey /tmp/signing_ca.key -subj /CN=$FPM_DNS -extensions usr_cert -addext "subjectAltName=DNS:$FPM_DNS" -config /tmp/openssl.cnf -days 365 -out /tmp/fpm.pem -keyout /tmp/fpm.key -noenc
if [ $? == 0 ]; then
  echo "Creating PHP-FPM server cert...done"
fi
cat /tmp/signing_ca.pem >> /tmp/fpm.pem
openssl x509 -inform PEM -outform DER -in /tmp/fpm.pem -out /tmp/fpm.der
kubectl create secret tls fpm --cert /tmp/fpm.pem --key /tmp/fpm.key
#mount fpm secret tls.crt as /etc/ssl/fpm.pem and tls.key as /etc/ssl/private/fpm.key in php-fpm deployment
kubectl create cm fpm-crt --from-file=/tmp/fpm.der

#create PG server cert in both forms, chain it with signing CA
echo "Creating Postgresql server cert..."
openssl req -CA /tmp/signing_ca.pem -CAkey /tmp/signing_ca.key -subj /CN=$PG_DNS -extensions usr_cert -addext "subjectAltName=DNS:$PG_DNS" -config /tmp/openssl.cnf -days 365 -out /tmp/postgres.pem -keyout /tmp/postgres.key -noenc
if [ $? == 0 ]; then
  echo "Creating Postgresql server cert...done"
fi
cat /tmp/signing_ca.pem >> /tmp/postgres.pem
openssl x509 -inform PEM -outform DER -in /tmp/postgres.pem -out /tmp/postgres.der
kubectl create secret tls postgres --cert /tmp/postgres.pem --key /tmp/postgres.key
#mount postgres secret tls.crt as /var/pki/pg/postgres.pem and tls.key as /var/pki/pg/postgres.key in postgres deployment or stateful set
kubectl create cm postgres-crt --from-file=/tmp/postgres.der

# generate root CA CRL in DER form
echo "Generating Root CA CRL..."
touch /tmp/index.txt
echo f5f3982b441a6d0a98e26cf1af78da420892f675 > /tmp/crlnumber
openssl ca -gencrl -out /tmp/root_ca.crl -config /tmp/openssl.cnf -name root_ca -cert=/tmp/root_ca.pem -keyfile=/tmp/root_ca.key -rand_serial -crldays 3650
if [ $? == 0 ]; then
  echo "Generating Root CA CRL...done"
fi
openssl crl -inform PEM -in /tmp/root_ca.crl -outform DER -out /tmp/root_ca.crl
kubectl create cm root-ca-crl --from-file=/tmp/root_ca.crl
#mount root_ca_crl under /var/www/pki/pki/

read -p "Please enter the password for LDAP service account named in ARG LDAP_BINDING_DN in Dockerfile-init (it will be saved in ldap-secret):" -s LDAP_PASSWORD
kubectl create secret generic ldap-secret --from-literal=ldap-pass=$LDAP_PASSWORD
read -p "Please enter the password for postgres database account (it will be saved in pg-secret):" -s PG_PASSWORD
kubectl create secret generic pg-secret --from-literal=pg-pass=$PG_PASSWORD

envsubst '$NAMESPACE $K8S_DNS_SUFFIX' < core_dsn_patch.json | tee /tmp/patch.json
read -p "To allow $PKI_DNS to be resolved inside k8s, we need to add rewrite into coredns cm. Add this line - rewrite name exact $PKI_DNS nginx.$NAMESPACE.svc.$K8S_DNS_SUFFIX - as the first line before errors. Pressing enter opens vi editor"
#kubectl patch configmap coredns -n kube-system --type json --patch-file /tmp/patch.json
kubectl edit configmap coredns -n kube-system
read -p "For the changes to take effect, Core-DNS pods need to be restarted. Pressing enter restarts Core-DNS"
kubectl delete pod -l k8s-app=kube-dns -n kube-system

rm /tmp/openssl.cnf /tmp/root_ca.pem /tmp/root_ca.key /tmp/root_ca.der /tmp/signing_ca.pem /tmp/signing_ca.key /tmp/signing_ca.der /tmp/ca_chain.pem /tmp/pki.pem /tmp/pki.key /tmp/pki.der /tmp/fpm.pem /tmp/fpm.key /tmp/fpm.der /tmp/postgres.pem /tmp/postgres.key /tmp/postgres.der /tmp/index.txt /tmp/crlnumber /tmp/root_ca.crl /tmp/patch.json