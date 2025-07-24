#!/bin/sh
. config.env
kubectl delete ingress nginx-https
kubectl delete service php-fpm nginx postgres
kubectl delete deployment init
kubectl delete deployment nginx
kubectl delete deployment php-fpm
kubectl delete deployment postgres
kubectl delete cm ca-chain-pem fpm-crt openssl-cnf pki-crt postgres-crt root-ca-crl root-ca-crt signing-ca-crt
kubectl delete secret fpm ldap-secret pg-secret pki postgres signing-ca root-ca
kubectl delete pvc www pki
kubectl delete pv www pki
read -p "Press enter to open vi editor and delete the line - rewrite name exact $PKI_DNS nginx.$NAMESPACE.svc.$K8S_DNS_SUFFIX - in coredns configmap"
kubectl edit configmap coredns -n kube-system
read -p "Press enter to restart Core-DNS pods"
kubectl delete pod -l k8s-app=kube-dns -n kube-system
docker volume rm www
docker volume rm pki
