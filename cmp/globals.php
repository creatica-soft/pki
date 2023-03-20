<?php
require_once "config.php";
$log_level = LOG_ERR; //options are LOG_ERR, LOG_INFO and LOG_DEBUG
$pvno = 2; //CMP protocol version (1: RFC2510, 2: RFC4210)
$max_pki_requests = 1;
$confirm_wait_time_sec = 86400; // https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.1.2
$include_confirm_wait_time = true; //include it in generalInfo optional PKIMessage header field
$max_time_skew_sec = 180; //max time skew between sender and recipient; since cert notBefore and notAfter usually have 1 min precision
$cmp_path = '/cmp/';
$content_type = 'application/pkixcmp';
$client_cert_enroll_url = "$base_url/cert_request.html";
/* 
sudo sqlite3 /var/pki/certs.db \
  'create table cert_req_ids(serial TEXT PRIMARY KEY ASC, certReqId TEXT, timestamp INTEGER, nonce TEXT, transactionID TEXT);' \
  'CREATE INDEX certReqId_idx on cert_req_ids(certReqId); CREATE INDEX transactionID_idx on cert_req_ids(transactionID);'

cert_req_ids table has unconfirmed cert_req_ids; once confirmed (or denied) in CERTCONF message or unconfirmed within 
$confirm_wait_time_sec, the cert status should be updated in certs table from 2 (on-hold) to either 0 (valid) or revoked (-1) and the record 
in cert_req_ids should be deleted
*/

$root_ca_der_path = '/etc/ssl/root_ca.der';
$include_signing_ca_cert_in_extra_certs = false;
$supported_signing_algs = ['sha1WithRSAEncryption', 'sha256WithRSAEncryption', 'dsa-with-SHA1', 'dsa-with-SHA256', 'ecdsa-with-SHA1', 'ecdsa-with-SHA256', 'password based MAC'];
$supported_encrypting_algs = ['sha1WithRSAEncryption', 'sha256WithRSAEncryption'];
$supported_language_tag = '';
$preferred_symmetric_alg = 'aes-128-cbc';
$ca_protocol_enc_cert = '';
$default_pki_message_protection_alg = 'sha256WithRSAEncryption';
$include_root_ca_cert_in_capubs = false;

?>
