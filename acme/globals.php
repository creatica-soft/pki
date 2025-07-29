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
$acme_db = "$DB_DIR/sqlite/acme.db"; //ACME tables are kept in a separate sqlite3 db
