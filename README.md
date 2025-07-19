## PKI Project

This is a PHP implementation of a server-side certificate management protocol (CMP) documented in rfc4210, 
automatic certificate management environment (ACME), rfc8555, Certificate Enrollment over Secure Transport (EST)
defined in rfc7030, online certificate status protocol (OCSP), rfc6960, Certificate Store Access via HTTP, rfc4387, MS-XCEP (https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCEP/%5bMS-XCEP%5d.pdf) and MS-WSTEP (https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-WSTEP/%5bMS-WSTEP%5d.pdf).

Fro quick tests and deployment Dockerfile is provided. You may test both sqlite and postgres db at the same time.

```
git clone https://github.com/creatica-soft/pki
cd pki
# review ARGs in Dockerfile and update as needed
export LDAP_PASSWORD=<ldap_service_account_password>
export PG_PASSWORD=<postgres_password>
docker build -t alpine-pki --rm --secret id=ldap,env=LDAP_PASSWORD --secret id=pg,env=PG_PASSWORD .
unset LDAP_PASSWORD PG_PASSWORD
docker run -it --net=host --name pki alpine-pki
# replace $PKI_DNS and $TEST_DNS with the same values as in Dockerfile
echo 127.0.0.1 $PKI_DNS $TEST_DNS | sudo tee -a /etc/hosts
cd /var/www/pki/cmp_client
php84 tests.php
cd ../est_client
php84 tests.php
cd ../certbot
./tests.sh
sed -i 's/sql_db = "postgres"/sql_db = "sqlite"/' ../lib/config.php
cd /var/www/pki/cmp_client
php84 tests.php
cd ../est_client
php84 tests.php
cd ../certbot
./tests.sh
sed -i 's/sql_db = "sqlite"/sql_db = "postgres"/' ../lib/config.php
```

For production, /var/pki folder should probably be placed in a docker persistent volume to preserve certificate database in case a new container runs. The same might be done for /var/log, etc. To preserve data in the current container if it stopped, simply start it with

```
docker contrainer start -i alpine-pki 
```

Openssl version 3 includes RFC4120-compliant CMP client, which has been tested to work with this server.
Openssl ocsp client has been tested with OCSP server.
Let's Encrypt Certbot has been tested with ACME server.
MS Certificates MMC (certmgr.msc and certlm.msc), certutil.exe and certreq.exe have been tested with MS-XCEP and MS-WSTEP.

The client certificate has a subject with a common name (CN) equaled to sAMAccountName (username) and a role equaled to 'standard'.

ACME uses external account binding to associate ACME client public key with its owner via Active Directory account binding.

Standard role in CMP allows requesting key updates and revocations only to certificates issued to the same user,
i.e. those that have owner field in their subject equaled to CN of a client certificate. 
Standard role is not allowed requesting wildcard certificates.

There exists a 'master' role in CMP, which is free from the above limitations.

In ACME clients are free from the above limitations because ACME performs domain validation (DV) and if successful, then issues
the certificate. 

MS-XCEP is anonymous and MS-WSTEP uses AD LDAP username and password authentication. Default user role is standard. Trusted users can be added to the master role via lib/config.php.

By default MS-XCEP provides three certificate templates (GenericUser, Email and GenericComputer). Additional templates may be added via msxcep/globals.php file.

### Usage examples and documentation

See index.html

### Certificate databases

Certificates are stored in sqlite3 or postgres db depending on ARG DB in Dockerfile. See init-cert.sql and init-acme.sql for sqlite3 schema and createdb.sql for postgres schema.

### Common PHP library

| File name                 | PHP Classes                                      | Notes                                           |
| ------------------------  | ------------------------------------------------ | ----------------------------------------------- |
| lib/algorithm_identifier.php  | DHBMParameter, PBMParameter, AlgorithmIdentifier | https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.3 |
| lib/atv.php                   | AttributeTypeAndValue - used by Name class       | https://datatracker.ietf.org/doc/html/rfc4519   |
| lib/base64url.php             | base64url_encode() and base64url_decode()        | https://datatracker.ietf.org/doc/html/rfc4648#section-5 |
| lib/cert_id.php               | CertHash, CertId                                 | Certificate Hash                                | 
| lib/cert_template.php         | CertTemplate                                     | https://datatracker.ietf.org/doc/html/rfc4211#section-5 |
| lib/certificate.php           | TBSCertificate, Certificate                      | https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1 |
| lib/certification_request.php | CertificationRequestInfo, CertificationRequest   | https://datatracker.ietf.org/doc/html/rfc2986 |
| lib/extension.php             | Extensions, Extension                            | https://datatracker.ietf.org/doc/html/rfc5280#section-4.2 |
| lib/general_name.php          | RDN, Name, GeneralName                           | https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.1 |
| lib/signed_data.php           | ContentInfo, SignedData, SignerInfo              | https://datatracker.ietf.org/doc/html/rfc5652 (PKCS #7) |
| lib/subject_pubkey_info.php   | RSAPublicKey, DSAPublicKey, DHPublicKey, ECPublicKey, SubjectPublicKeyInfo | https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7 |
| lib/validity.php              | Validity                                         | https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5 |

### PHP Classes for CMP

| File name                 | PHP Classes                                      | Notes                                           |
| ------------------------  | ------------------------------------------------ | ----------------------------------------------- |
| cmp/cert_confirm.php          | CertStatus, CertConfirmContent                   | https://datatracker.ietf.org/doc/html/rfc4210#section-5.3.18 |
| cmp/cert_rep_msg.php          | CertRepMessage                                   | https://datatracker.ietf.org/doc/html/rfc4210#section-5.3.4 |
| cmp/cert_req.php              | CertReq                                          | https://datatracker.ietf.org/doc/html/rfc4211#section-5 |
| cmp/cert_req_msg.php          | CertReqMessages, CertReqMessage                  | https://datatracker.ietf.org/doc/html/rfc4211#section-3 |
| cmp/cert_response.php         | CertResponse                                     | https://datatracker.ietf.org/doc/html/rfc4210#section-5.3.4 |
| cmp/certified_key_pair.php    | CertifiedKeyPair                                 | https://datatracker.ietf.org/doc/html/rfc4210#section-5.3.4 |
| cmp/controls.php              | Controls                                         | https://datatracker.ietf.org/doc/html/rfc4211#section-6 |
| cmp/error_msg.php             | ErrorMsgContent                                  | https://datatracker.ietf.org/doc/html/rfc4210#section-5.3.21 |
| cmp/extra_certs.php           | ExtraCerts                                       | https://datatracker.ietf.org/doc/html/rfc4210#section-5.1 |
| cmp/genm.php                  | InfoTypeAndValue, GenMsgContent, GeneralInfo     | https://datatracker.ietf.org/doc/html/rfc4210#section-5.3.19 |
| cmp/pki_body.php              | PKIBody                                          | https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.2 |
| cmp/pki_header.php            | PKIFreeText, PKIHeader                           | https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.1 |
| cmp/pki_message.php           | PKIMessage                                       | https://datatracker.ietf.org/doc/html/rfc4210#section-5.1 |
| cmp/pki_protection.php        | PKIProtection                                    | https://datatracker.ietf.org/doc/html/rfc4210#section-5.1 |
| cmp/pki_status_info.php       | PKIStatusInfo                                    | https://datatracker.ietf.org/doc/html/rfc4210#section-5.2.3 |
| cmp/popo_signing_key.php      | POPOPrivKey, PKMACValue, POPOSKInput, POPOSigningKey | https://datatracker.ietf.org/doc/html/rfc4210#section-5.2.8 |
| cmp/rev_rep.php               | RevRepContent, CRL, RevokedCerts, RevokedCert, TBSCRL | https://datatracker.ietf.org/doc/html/rfc4210#section-5.3.10 |
| cmp/rev_req.php               | RevReq, RevReqContent                            | https://datatracker.ietf.org/doc/html/rfc4210#section-5.3.9 |

### PHP Classes for ACME

| File name                 | PHP Classes                                      | Notes                                           |
| ------------------------  | ------------------------------------------------ | ----------------------------------------------- |
| acme/account.php               | Account class                                    | https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2 |
| acme/acme_request.php          | ACME request class                               | https://datatracker.ietf.org/doc/html/rfc8555#section-6.1 |
| acme/authorization.php         | Authorization class                              | https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4 |
| acme/challenge.php             | Challenge class                                  | https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5 |
| acme/order.php                 | Order class                                      | https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3 |
https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7 |

### PHP Classes for EST

| File name                 | PHP Classes                                      | Notes                                           |
| ------------------------  | ------------------------------------------------ | ----------------------------------------------- |


### Other files

server.php is the CMP, ACME, EST, OCSP, MS-XCEP or MS-WSTEP server, which answers the CMP, ACME, EST, OCSP, MS-XCEP or MS-WSTEP requests.

lib/asn1_types.php is ITU-T X680/X690 ASN.1 type constants

lib/asn1decode.php - ITU-T X680/X690 ASN.1 decoder, which will get the binary data (DER) and return an array, which is later mapped to CMP class properties.

lib/asn1encode.php - ITU-T X680/X690 ASN.1 encoder, which will take a class, a constructed bit, a type and a value and returns a DER string.

lib/help_functions.php - a bunch of useful functions that are consumed by any file.

lib/sql.php - SQL functions related to certs.db table operations such as select, insert, update and delete
lib/acme_sql.php - SQL functions related to acme.db table operations such as select, insert, update and delete
lib/cmp_sql.php - SQL functions related to certs.db table operations such as select, insert, update and delete

lib/config.php - this is where all common configuration settings are.
globals.php - this is where protocol-specific configuration settings are.

lib/asn1parse.php - very similar to openssl asn1parse, it takes a file in DER or PEM encoding as a first argument and 'pem' as a second if needed.

### Automatic Certificate Management Environment (ACME), RFC 8555

This is Let's Encrypt server. There are many ACME clients. A client must support external account binding. Many do not.
Recommended ACME client is Certbot from Let's Encrypt.

### Enrollment over Secure Transport

This is a simplified version of both CMP and CMC (rfc5273) protocols. Three well-known URIs are supported: cacerts, simpleenroll and simplereenroll. 
Certificate revocation, which requires full CMC, is not supported since it is optional in rfc7030. AD username and password as well as SSL client certificate authentication with standard and master roles are supported. Same as in CMP, no domain validation. EST clients do exist but are not required. Certificates can simply be requested using curl and openssl req, base64 and pkcs7 commands. Both openssl versions (1 and 3) work with EST server.


### Certificate Enrollment Protocol MS-XCEP

This protocol is used by MS Certificates MMC (certmgr.msc and certlm.msc) to get certificate templates and certificate enrollment url where to submit certification requests (CSR or CMC). This is XML-based protocol, more precisely SOAP 1.2.

### WS-Trust X.509v3 Token Enrollment Extensions MS-WSTEP

This protocol is used by the same Microsoft tools as MS-XCEP to actually request and renew certificates. In theory it should support certificate revocation because it uses full CMC but in practice there is no GUI functions in Certificates MMC to do this; hence, the server side also does not implement certificate revocation.

### Online Certificate Status Protocol (OCSP), RFCs 6960 and 5019

openssl provides ocsp client, which can be used to verify that OCSP server works fine. Also, openssl verify command may be used.

### Certificate Store Access via HTTP, RFC 4387

Well-known URLs are provided for certificates and CRLs:

```
https://pki.example.org/certificates/search.cgi?attirbute=value
https://pki.example.org/crls/search.cgi?attirbute=value
```

where all x.509 attributes are supported: certHash, uri, iHash, iAndSHash, name, cn, sHash, sKIDHash.