#!/bin/ash
rm -f /var/www/${CERTBOT_DOMAIN}/.well-known/acme-challenge/$CERTBOT_TOKEN
