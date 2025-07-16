<?php
require_once "config.php";
$log_level = LOG_ERR; //options are LOG_ERR, LOG_INFO and LOG_DEBUG
$acme = 1; //ACME protocol version (1 (v2): RFC8555)
$path = '/acme';
$directory = "$path/";
$newNonce = "$path/new-nonce";
$newAccount = "$path/new-account";
$accountsUrl = "/accounts/";
$newOrder = "$path/new-order";
$ordersUrl = "/orders/";
$authorizationsUrl = "/authorizations/";
$challengesUrl = "/challenges/";
$csrUrl = "/csr"; //will be added to URL after orderId and used in finalize field of the account Order object
$certificateUrl = "/cert/"; //will be added to URL after orderId
//$newAuthz = "$path/new-authz"; //for pre-authorizations only
$meta = ['website' => "$base_url", 'externalAccountRequired' => true];
$externalAccountBindingRequired = true;
$retry_after_sec = 60; //polling interval for authorization object for acme client
$revokeCert = "$path/revoke-cert";
$keyChange = "$path/key-change";
//$supported_jwk_algs = ['ES256', 'Ed25519', 'RS256'];
$supported_jwk_algs = ['ES256', 'RS256'];
$acme_urn_error = "urn:ietf:params:acme:error:";
$account_id_length_bytes = 8;
$order_id_length_bytes = 8;
$authorization_id_length_bytes = 8;
$challenge_id_length_bytes = 8;
$token_length_bytes = 16; //Challenge class token
$order_expires_days = 7;
$nonce_expires_sec = 3600;
$curl_max_redirections = 10; //maximum redirections when validating http-01 challenge
$curl_ipresolve = CURL_IPRESOLVE_V4; // or CURL_IPRESOLVE_V6
$hmac_key_length = 64; //should be provided to a client in base64url_encoded() form
$acme_db = "$DB_DIR/acme.db"; //ACME tables are kept in a separate sqlite3 db
/* 
sudo sqlite3 $DB_DIR/acme.db \
  'create table nonces(nonce TEXT PRIMARY KEY ASC, ip TEXT, expires INTEGER);' \
  'create index ip_idx on nonces(ip);' \
  'create index expires_idx on nonces(expires);'

//uri for an account should look like /acme/accounts/<accountID>
sudo sqlite3 $DB_DIR/acme.db \
  'create table accounts(id TEXT PRIMARY KEY ASC, status INTEGER, termsOfServiceAgreed INTEGER, jwk_hash TEXT, kid TEXT, jwk BLOB, contacts BLOB, externalAccountBinding BLOB);' \
  'create index jwk_hash_idx on accounts(jwk_hash);' \
  'create index account_status_idx on accounts(status);' \
  'create index account_kid_idx on accounts(kid);'

//uri for an order should look like /acme/accounts/<accountID>/orders/<orderID>
sudo sqlite3 $DB_DIR/acme.db \
  'PRAGMA foreign_keys = ON;' \
  'create table orders(id TEXT PRIMARY KEY ASC, status INTEGER, expires INTEGER, identifiers BLOB, notBefore INTEGER, notAfter INTEGER, certSerial TEXT, account TEXT, foreign key(account) references accounts(id) ON DELETE CASCADE);' \
  'create index order_status_idx on orders(status);' \
  'create index order_expires_idx on orders(expires);' \
  'create index notBefore_idx on orders(notBefore);' \
  'create index notAfter_idx on orders(notAfter);'

//uri for authorizations should look like /acme/accounts/<accountID>/orders/<orderID>/authorizations/<authorizationID>
sudo sqlite3 $DB_DIR/acme.db \
  'PRAGMA foreign_keys = ON;' \
  'create table authorizations(id TEXT PRIMARY KEY ASC, identifier BLOB, status INTEGER, expires INTEGER, wildcard INTEGER, "order" TEXT, foreign key("order") references orders(id) ON DELETE CASCADE);' \
  'create index authorization_status_idx on authorizations(status);' \
  'create index authorization_expires_idx on authorizations(expires);'

//uri for challenges should look like /acme/accounts/<accountID>/orders/<orderID>/authorizations/<authorizationID>/challenges/<challengeID>
sudo sqlite3 $DB_DIR/acme.db \
  'PRAGMA foreign_keys = ON;' \
  'create table challenges(id TEXT PRIMARY KEY ASC, type TEXT, url TEXT, status INTEGER, token TEXT, error TEXT, validated INTEGER, authorization TEXT, foreign key(authorization) references authorizations(id) ON DELETE CASCADE);' \
  'create index type_idx on challenges(type);' \
  'create index challenge_status_idx on challenges(status);' \
  'create index token_idx on challenges(token);' \
  'create index validated_idx on challenges(validated);'

nonces table is used for ACME nonces, ip is the acme client's IP address; once the nonce is used, it's removed from the table
*/

?>
