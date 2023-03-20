#!/bin/ash
echo $CERTBOT_VALIDATION > /var/www/${CERTBOT_DOMAIN}/.well-known/acme-challenge/$CERTBOT_TOKEN
