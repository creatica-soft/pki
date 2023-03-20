#!/bin/ash
# install certbot and create a virtual host in nginx
export CERTBOT_DOMAIN=test.example.com
export REQUESTS_CA_BUNDLE=/etc/ssl/ca_chain.pem
sudo apk add certbot
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
sudo service nginx reload

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
sudo service nginx reload