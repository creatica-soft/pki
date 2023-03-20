#!/bin/sh
STANDBY_SERVER_IP="192.168.1.1"
months="jan feb mar apr may jun jul aug sep oct nov dec"
month=`date -u +%m`
month=$(($month - 1))
month=`j=1; for i in $months; do if [ $((j++)) -eq $month ]; then echo $i; fi; done`
cp /home/alpine/pki.tar.gz /home/alpine/pki.tar.gz.$month
ssh ${STANDBY_SERVER_IP} cp /home/alpine/pki.tar.gz /home/alpine/pki.tar.gz.$month
