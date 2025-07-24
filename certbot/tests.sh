#!/bin/ash
# install certbot and create a virtual host in nginx
USERNAME=test
PASSWORD=123
ACME_SERVER=$PKI_DNS
export CERTBOT_DOMAIN=$TEST_DNS
export REQUESTS_CA_BUNDLE=/etc/ssl/ca_chain.pem
#sudo apk add certbot
FOUND=`nslookup $CERTBOT_DOMAIN 2>&1` 
if [ "$?" != 0 ]; then
  FOUND=`grep $CERTBOT_DOMAIN /etc/hosts`
  if [ "${FOUND}" == "" ]; then
    echo "$CERTBOT_DOMAIN is not found in DNS. For testing purpose add it into /etc/hosts file"
    exit 1
  fi
fi 
FOUND=`nslookup $ACME_SERVER 2>&1`
if [ "$?" != 0 ]; then
  FOUND=`grep $ACME_SERVER /etc/hosts`
  if [ "${FOUND}" == "" ]; then
    echo "$ACME_SERVER is not found in DNS. For testing purpose add it into /etc/hosts file"
    exit 1
  fi
fi 

sed -i "s/username/$USERNAME/" certbot.conf
KEY=`php$PHP_VER ../key_request.php $USERNAME $PASSWORD`;
sed -i "s/eab-hmac-key = .*/eab-hmac-key = $KEY/" certbot.conf
sudo mkdir -p /var/www/${CERTBOT_DOMAIN}/.well-known/acme-challenge
sudo chown alpine /var/www/${CERTBOT_DOMAIN}/.well-known/acme-challenge
sudo sh -c "cat <<END>/etc/nginx/http.d/${CERTBOT_DOMAIN}.conf
server {
        listen 0.0.0.0:80;
        server_name ${CERTBOT_DOMAIN};
        location / {
                root /var/www/${CERTBOT_DOMAIN};
        }
}
END"
sudo nginx -s reload
if [ "$?" != 0 ]; then
  sudo nginx
fi
# verify certbot.conf file
# run the tests
mkdir logs
certbot -c certbot.conf register
certbot -c certbot.conf certonly --manual -d ${CERTBOT_DOMAIN} -v
certbot -c certbot.conf certificates
openssl x509 -in live/${CERTBOT_DOMAIN}/cert.pem -text -noout
certbot -c certbot.conf renew --cert-name ${CERTBOT_DOMAIN} -v --force-renewal
certbot -c certbot.conf certificates
openssl x509 -in live/${CERTBOT_DOMAIN}/cert.pem -text -noout
certbot -c certbot.conf revoke --cert-name ${CERTBOT_DOMAIN} --delete-after-revoke -n
certbot -c certbot.conf unregister -n

# cleanup
rm -rf accounts archive backups csr keys live renewal renewal-hooks logs
sudo rm -rf /etc/nginx/http.d/${CERTBOT_DOMAIN}.conf
sudo rm -rf /var/www/${CERTBOT_DOMAIN}/
sudo nginx -s reload
