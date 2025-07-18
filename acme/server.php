<?php
// can be tested with certbot client and its config file in C:\Certbot\cli.ini as
// certbot.exe certonly --manual -d alpine-3-15-4.lat.internal
// REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE envvar can be set to point to C:\Certbot\internal_ca_bundle.pem

require_once 'globals.php';
require_once 'helper_functions.php';
require_once 'base64url.php';
require_once 'sql.php';
require_once 'acme_sql.php';
require_once 'general_name.php';
require_once 'cert_template.php';
require_once 'certificate.php';
require_once 'extension.php';
require_once 'acme_request.php';
require_once 'account.php';
require_once 'order.php';
require_once 'authorization.php';
require_once 'challenge.php';

//some global declarations
$jwk = null; //json object from protected header
$jwk_hash = null; //sha1 hash in hex of the ASN.1 encoded SubjectPubkeyInfo object constructed from $jwk 
                //(see verifySignature() in helper_functions.php)
$account = null;

//see https://datatracker.ietf.org/doc/html/rfc7807
function acmeError($type, $detail, $statusCode) {
  global $acme_urn_error, $supported_jwk_algs;
  header('Cache-Control: no-store', true);
  header('Content-Type: application/problem+json', true);
  switch ($type) {
    case 'badSignatureAlgorithm':
      $encoded = json_encode(['type' => $acme_urn_error . $type, 'detail' => $detail, 'algorithms' => $supported_jwk_algs]);
    break;
    default:
      $encoded = json_encode(['type' => $acme_urn_error . $type, 'detail' => $detail]);
  }
  headerNonce();
  header('Content-Length: ' . strlen($encoded), true, $statusCode);
  echo $encoded;
  exit(1);
}

function headerNonce($code = 204) {
  do {
    $nonce = gmp_random_bits(128);
    $nonce = gmp_strval($nonce, 8);
  } while (! sqlSaveNonce($nonce, $_SERVER['REMOTE_ADDR']));
  header('Replay-Nonce: ' . base64url_encode($nonce), true, $code);
}

function headers($len = null, $code = 200) {
  global $base_url, $directory;
  http_response_code($code);
  header('Cache-Control: no-store', true, $code);
  header('Content-Type: application/json', true, $code);
  header('Link: <' . "$base_url$directory" . '>;rel="index"', false, $code);
  headerNonce($code);
  if (! is_null($len))
    header('Content-Length: ' . $len, true, $code);
}

class AcmeException extends Exception {
  protected string $type;

  function __construct(string $type, string $message = "", int $code = 0, ?Throwable $previous = null) {
    $this->type = $type;
    parent::__construct($message, $code, $previous);
  }
  
  function getType() {
    return $this->type;
  }
}

function exception_handler($e) {
  errorLog($e);
  if ($e instanceof AcmeException) {
    $type = $e->getType();
    $code = $e->getCode();
  }
  else { 
    $type = 'serverInternal';
    $code = 500;
  }
  acmeError($type, "Internal PKI ACME Server: " . $e->getMessage(), $code);
}

function getKeyAuthorization($token, $jwk) {
  //calculate thumbprint according to rfc7638
  $jwkArray = json_decode($jwk, JSON_OBJECT_AS_ARRAY);
  if (is_null($jwkArray)) {
    errorLog("getKeyAuthorization() error: json_decode($jwk, JSON_OBJECT_AS_ARRAY) returned null");
    return false;
  }
  ksort($jwkArray, SORT_STRING); //keys must be sorted lexicographically by UNICODE code points of member names
  $jwk = json_encode($jwkArray);
  if (! $jwk) {
    errorLog("getKeyAuthorization() error: json_encode(array) returned false. Array was \n" . print_r($jwkArray, true));    
    return false;
  }
  $thumbprint = hash('sha256', $jwk, $binary = true); 
  return $token . '.' . base64url_encode($thumbprint);
}

function verifyDnsChallenge($dnsRecord, $keyAuthorization) {
  global $log_level;
  $txt = dns_get_record($dnsRecord, DNS_TXT, $authoritativeNameServers);
  if (! $txt || ! is_array($txt)) {
    //if ($log_level == LOG_INFO || $log_level == LOG_DEBUG) 
      errorLog("verifyDnsChallenge() returned false: authoritativeNameServers are $authoritativeNameServers", $level = 'debug');
    return false;
  }
  if ($log_level == LOG_DEBUG) 
    errorLog("verifyDnsChallenge(): dns_get_record returned " . print_r($txt, true), 'debug');
  $b64 = base64url_encode(hash('sha256', $keyAuthorization, $binary = true));
  foreach ($txt as $record) {
    if ($log_level == LOG_DEBUG) 
      errorLog("verifyDnsChallenge():  processing dns record\n" . print_r($record, true), 'debug');
    if ($b64 == trim($record['txt']))
      return true;
    else {
    //if ($log_level == LOG_INFO || $log_level == LOG_DEBUG) 
      errorLog("verifyDnsChallenge(): " . $record['txt'] . ". base64url_encode(hash('sha256', $keyAuthorization)) = $b64", $level = 'debug');
    }
  }
  return false;
}

function verifyHttpChallenge($challengeUrl, $keyAuthorization) {
  global $curl_max_redirections, $log_level, $curl_ipresolve;
  $curl = curl_init($challengeUrl);
  if ($curl === false) {
    errorLog('verifyHttpChallenge() error: curl_init failed');
    throw new AcmeException('serverInternal', 'Internal Server Error', 500);
  }
  if (curl_setopt($curl, CURLOPT_IPRESOLVE, $curl_ipresolve) == false) {
    errorLog('verifyHttpChallenge() error: curl_setopt CURLOPT_IPRESOLVE returned false');
    throw new AcmeException('serverInternal', 'Internal Server Error', 500);    
  }
  if (curl_setopt($curl, CURLOPT_RETURNTRANSFER, true) === false) {
    errorLog('verifyHttpChallenge() error: curl_setopt CURLOPT_RETURNTRANSFER returned false');
    throw new AcmeException('serverInternal', 'Internal Server Error', 500);
  }
  if (curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true) === false) {
    errorLog('verifyHttpChallenge() error: curl_setopt CURLOPT_FOLLOWLOCATION returned false');
    throw new AcmeException('serverInternal', 'Internal Server Error', 500);
  }
  if (curl_setopt($curl, CURLOPT_MAXREDIRS, $curl_max_redirections) === false) {
    errorLog('verifyHttpChallenge() error: curl_setopt CURLOPT_MAXREDIRS returned false');
    throw new AcmeException('serverInternal', 'Internal Server Error', 500);
  }

  $response = trim(curl_exec($curl));
  $responseCode = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
  if ($log_level == LOG_INFO || $log_level == LOG_DEBUG) 
    errorLog("verifyHttpChallenge(): curlResponseCode = $responseCode, curlResponse = $response", $level = 'debug');
  curl_close($curl);
  if ($responseCode != 200) return false;
  if (strncmp($response, $keyAuthorization, strlen($keyAuthorization)) != 0) return false;
  return true;
}

function verifySignature($jwk, $data, $signature, $alg = null) {
  global $supported_jwk_algs, $jwk_hash, $account,  $keyChange;
  $pubkey = new SubjectPublicKeyInfo();
  switch ($jwk->kty) {
    case 'EC':
      $pubkey->algorithm = new AlgorithmIdentifier('ecPublicKey');
      $pubkey->algorithm->parameters = new ECPKParameters();
      if ($jwk->crv == 'P-256')
        $pubkey->algorithm->parameters->namedCurve = str2oid('prime256v1');
      else {
        errorLog("verifySignature() error: unsupported public key algorithm parameter EC curve " . $jwk->crv);
        throw new AcmeException('badPublicKey', 'unsupported public key algorithm parameter EC curve', 400);
      }
      $pubkey->subjectPublicKey = new ECPublicKey($jwk->x, $jwk->y);
    break;
    case 'RSA':
      $pubkey->algorithm = new AlgorithmIdentifier('rsaEncryption');
      $pubkey->subjectPublicKey = new RSAPublicKey($jwk->n, $jwk->e);
    break;
    case 'HS256':
      $protection = hash_hmac('sha256', $data, base64url_decode($jwk->k), $binary = true);
      $res = strcmp(base64url_encode($protection), $signature);
      if ($res != 0) {
        errorLog("verifySignature() hash_hmac returned invalid signature");
        throw new AcmeException('unauthorized', 'hmac signature verification failed', 401);                  
      }
    return;
    default:
      errorLog("verifySignature() error: unsupported public key type " . $jwk->kty);
      throw new AcmeException('badPublicKey', 'unsupported public key type', 400);
  }
  $der = $pubkey->encode();
  $pem = der2pem($der, 'PUBLIC KEY');
  while(openssl_error_string());
  $key = openssl_pkey_get_public($pem);
  if (! $key) {
    $errros = array();
    $err = openssl_error_string();
    while($err) {
      $errors[] = $err;
      $err = openssl_error_string();
    }
    errorLog("verifySignature() error: badPublicKey, openssl pkey_get_public error: " . print_r($errors, true));
    throw new AcmeException('badPublicKey', 'bad public key', 500);
  }
  if (in_array($alg, $supported_jwk_algs)) {
    while(openssl_error_string());
    $res = openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA256);
  } else {
    errorLog("verifySignature() error: unsupported signature algorithm: " . $alg);
    throw new AcmeException('badSignatureAlgorithm', 'unsupported signature algorithm', 400);
  }
  switch ($res) {
    case 0: //invalid
      errorLog("verifySignature() openssl_verify returned 0 (invalid signature)");
      throw new AcmeException('malformed', 'signature verification failed', 400);                  
    break;
    case 1: //valid
      $jwk_hash = hash('sha1', $der, $binary = false);
      if (! is_null($account) && is_object($account) && $account instanceof Account) {
        if ($keyChange != $_SERVER['REQUEST_URI']) {
          if ($account->jwkHash != $jwk_hash) {
            errorLog("verifySignature() error: account with id " . $account->id . " has public key hash " . $account->jwkHash . " that does not match the hash of one from the protected header $jwk_hash");
            throw new AcmeException('accountDoesNotExist', 'account does not exist', 400);
          }
        } else {
          //update account jwk but first check that no other accounts exist with this new key
          $acc = sqlGetAccount(null, $jwk_hash);
          if ($acc) {
            errorLog("verifySignature() error: account with id " . $acc['id'] . " has the same public key hash $jwk_hash as the new key in keyChange request");
            header("Location: $base_url$path$accountsUrl" . $acc['id'] , true);
            throw new AcmeException('Conflict', 'account exists', 409);
          }
          $account->jwk = $jwk;
          sqlSaveAccount($account->id, $account->status, $account->termsOfServiceAgreed, $account->jwkHash, $account->kid, json_encode($account->jwk), json_encode($account->contacts), json_encode($account->externalAccountBinding));
        }
      }
    break;
    case -1: //error
      $error = '';
      while ($err = openssl_error_string()) $error .= $err;
      errorLog("verifySignature() openssl_verify error: $error");
      throw new AcmeException('serverInternal', 'openssl_verify error', 500);        
    break;
  }
}

set_exception_handler('exception_handler');

if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) {
  if (key_exists('USER_AGENT', $_SERVER))  
    errorLog("acme-server receiving " . $_SERVER['REQUEST_METHOD'] . " request for " . $_SERVER['REQUEST_URI'] . " URI from " . $_SERVER['REMOTE_ADDR'] . " user-agent: " . $_SERVER['USER_AGENT'], 'info');
  else 
    errorLog("acme-server receiving " . $_SERVER['REQUEST_METHOD'] . " request for " . $_SERVER['REQUEST_URI'] . " URI from " . $_SERVER['REMOTE_ADDR'], 'info');
}

$uri = explode('/', $_SERVER['REQUEST_URI']);
if (key_exists(1, $uri) && $uri[1] == str_replace('/', '', $path))
  $requestUri = $path;
if (key_exists(2, $uri) && $uri[2] == str_replace('/', '', $accountsUrl))
  $requestUri .= $accountsUrl;
if (key_exists(3, $uri)) {
  $accountID = $uri[3];
  $requestUri .= $accountID;
  $acc = sqlGetAccount($accountID);
  if (! $acc) {
    errorLog("acme-server default error: account with id $accountID does not exist");
    throw new AcmeException('accountDoesNotExist', 'account does not exist', 400);        
  }
}
if (key_exists(4, $uri) && $uri[4] == str_replace('/', '', $ordersUrl))
  $requestUri .= $ordersUrl;
if (key_exists(5, $uri)) {
  $orderID = $uri[5];
  $requestUri .= $orderID;
  $order = sqlGetOrder($orderID);
  if (! $order) {
    errorLog("acme-server order error: orderID $orderID is not found in db");
    throw new AcmeException('malformed', 'orderID is not found', 400);
  }
}
if (key_exists(6, $uri) && $uri[6] == str_replace('/', '', $authorizationsUrl))
  $requestUri .= $authorizationsUrl;
elseif (key_exists(6, $uri) && $uri[6] == str_replace('/', '', $csrUrl)) 
  $requestUri .= $csrUrl;
elseif (key_exists(6, $uri) && $uri[6] == str_replace('/', '', $certificateUrl))
  $requestUri .= $certificateUrl;
if (key_exists(7, $uri))
  $requestUri .= $uri[7];
if (key_exists(8, $uri) && $uri[8] == str_replace('/', '', $challengesUrl))
  $requestUri .= $challengesUrl;
if (key_exists(9, $uri)) { //client is ready for challenge verification
  $requestUri .= $uri[9];
  $challengeID = $uri[9];
  $challenge = sqlGetChallenge($challengeID);
  if (! $challenge) {
    errorLog("acme-server newOrder error: challengeID $challengeID is not found in db");
    throw new AcmeException('malformed', 'challengeID is not found', 400);
  }
}
$path_reg = str_replace('/', '\/', $path);
$accounts_reg = str_replace('/', '\/', $accountsUrl);
$orders_reg = str_replace('/', '\/', $ordersUrl);
$auth_reg = str_replace('/', '\/', $authorizationsUrl);
$chall_reg = str_replace('/', '\/', $challengesUrl);
$csr_reg = str_replace('/', '\/', $csrUrl);
$cert_reg = str_replace('/', '\/', $certificateUrl);

$n = gmp_pow(2, $account_id_length_bytes * 8);
$n = gmp_strval($n);
$acc_len_max = strlen($n);
$acc_len_min = 1;
$n = gmp_pow(2, $order_id_length_bytes * 8);
$n = gmp_strval($n);
$ord_len_max = strlen($n);
$ord_len_min = 1;
$n = gmp_pow(2, $authorization_id_length_bytes * 8);
$n = gmp_strval($n);
$auth_len_max = strlen($n);
$auth_len_min = 1;
$n = gmp_pow(2, $challenge_id_length_bytes * 8);
$n = gmp_strval($n);
$chall_len_max = strlen($n);
$chall_len_min = 1;
$n = gmp_pow(2, $cert_serial_bytes * 8);
$n = gmp_strval($n);
$sn_len_max = strlen($n);
$sn_len_min = 1;
$patternAcc = $path_reg . $accounts_reg . '[0-9]{' . $acc_len_min . ',' . $acc_len_max . '}';
if (preg_match('/^' . $patternAcc . '$/', $requestUri))
  $accountUrl = $requestUri;
else $accountUrl = null;
$patternOrd = $patternAcc . $orders_reg . '[0-9]{' . $ord_len_min . ',' . $ord_len_max . '}';
if (preg_match('/^' . $patternOrd . '$/', $requestUri))
  $orderUrl = $requestUri;
else $orderUrl = null;
$patternAuth = $patternOrd . $auth_reg . '[0-9]{' . $auth_len_min . ',' . $auth_len_max . '}';
if (preg_match('/^' . $patternAuth . '$/', $requestUri))
  $authorizationUrl = $requestUri;
else $authorizationUrl = null;
$patternChall = $patternAuth . $chall_reg . '[0-9]{' . $chall_len_min . ',' . $chall_len_max . '}';
if (preg_match('/^' . $patternChall . '$/', $requestUri))
  $challengeUrl = $requestUri;
else $challengeUrl = null;
$patternCsr = $patternOrd . $csr_reg;
if (preg_match('/^' . $patternCsr . '$/', $requestUri))
  $csrReqUrl = $requestUri;
else $csrReqUrl = null;
$patternCert = $patternOrd . $cert_reg . '[0-9]{' . $sn_len_min . ',' . $sn_len_max . '}';
if (preg_match('/^' . $patternCert . '$/', $requestUri))
  $certUrl = $requestUri;
else $certUrl = null;
 
switch($_SERVER['REQUEST_METHOD']) {
  case 'GET':
    if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
      errorLog("acme-server: processing GET request...");
    if ($log_level == LOG_DEBUG)
      errorLog("acme-server GET request URI: " . $_SERVER['REQUEST_URI'], $level = 'debug');
    switch($_SERVER['REQUEST_URI']) {
      case $directory:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server: processing directory GET request...", $level = 'info');
        $response = array("newNonce" => "$base_url$newNonce", "newAccount" => "$base_url$newAccount", "newOrder" => "$base_url$newOrder", "revokeCert" => "$base_url$revokeCert", "keyChange" => "$base_url$keyChange"); 
        $json = json_encode($response);
        headers(strlen($json));
        echo $json;
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server directory reply: " . print_r(headers_list()) . "\n\n$json", $level = 'debug');
        exit(0);
      case $newNonce:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server: processing newNonce GET request...", $level = 'info');
        headers();
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server newNonce reply: " . print_r(headers_list()) . "\n\n", $level = 'debug');
        exit(0);
      default:
        errorLog("acme-server.php error: unrecognized http request uri using GET " . $_SERVER['REQUEST_URI']);
        throw new AcmeException('malformed', 'method not allowed', 405); 
    }
  break;
  case 'POST':
    if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
      errorLog("acme-server: processing POST request...", $level = 'info');
    if ($_SERVER['CONTENT_TYPE'] != 'application/jose+json') {
      errorLog("acme-server.php error(): wrong content-type - expected application/jose+json, received " . $_SERVER['CONTENT_TYPE']);
      throw new AcmeException('malformed','wrong content type', 415);
    }
    $acmeRequest = file_get_contents('php://input');
    if ($log_level == LOG_DEBUG)
      errorLog("acme-server POST request: $acmeRequest", $level = 'debug');
    $len = strlen($acmeRequest);
    if ($_SERVER['CONTENT_LENGTH'] != $len) {
      errorLog("acme-server.php error(): wrong content-length, calculated $len, received " . $_SERVER['CONTENT_LENGTH']);
      throw new AcmeException('malformed','wrong content length', 400);
    }

    if ($_SERVER['REQUEST_URI'] != $directory && $_SERVER['REQUEST_URI'] != $newNonce) {
      //do some cleanup, precisely delete expired orders and old nonces
      sqlDeleteNonces(); //delete nonces older than $nonce_expires_sec
      $orders = sqlGetExpiredOrders();
      if ($orders) {
        foreach($orders as $order)
          sqlDeleteOrder($order['id']);
      }
      $acmeRequest = new AcmeRequest($acmeRequest); //this will validate the request
    }

    switch($_SERVER['REQUEST_URI']) {
      case $directory:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server directory: processing directory POST request...", $level = 'info');
        headers();
        $response = array("newNonce" => "$base_url$newNonce", "newAccount" => "$base_url$newAccount", "newOrder" => "$base_url$newOrder", "revokeCert" => "$base_url$revokeCert", "keyChange" => "$base_url$keyChange", "meta" => $meta); 
        $json = json_encode($response, JSON_UNESCAPED_SLASHES);
        echo $json;
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server directory reply: " . print_r(headers_list()) . "\n\n$json", $level = 'debug');
        exit(0);
      case $newNonce:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server newNonce: processing newNonce POST request...", $level = 'info');
        headers();
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server newNonce reply: " . print_r(headers_list()) . "\n\n", $level = 'debug');
        exit(0);
      case $newAccount: //jwk property in protected header must exist, 
                        //meaning that account object won't be automatically created in AcmeRequest::validate()
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server newAccount: processing newAccount POST request...", $level = 'info');
        $payload = base64url_decode($acmeRequest->payload);
        $acct = json_decode($payload);
        if (is_null($acct)) {
          errorLog('acme-server newAccount error: unable to decode a payload');
          throw new AcmeException('malformed', 'unable to decode a payload', 400);
        }
        $account = sqlGetAccount(null, $jwk_hash);
        if (property_exists($acct, 'onlyReturnExisting') && $acct->onlyReturnExisting) {
          if (! $account) {
            errorLog("acme-server newAccount error: account does not exist but onlyReturnExisting is true");
            throw new AcmeException('accountDoesNotExist', 'account does not exist', 400);        
          }
        }
        $statusCode = null;
        if ($account) {
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server newAccount: account with id " . $account['id'] . " exists in $acme_db", $level = 'info');
          $statusCode = 201; //rfc8555 says to return status code 200 AND include Location header, which does not make sense with 200
                             //php will actually send 302 (redirect) instead and breaks the acme client, which will follow the redirect
                             //by sending GET request to account url, which is not allowed
          $account = new Account($account['id']);
        } else {
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server newAccount: creating new account...", $level = 'info');
          $statusCode = 201;
          $account = new Account();
          $account->set($acct);
        }
        $json = json_encode($account);
        if (! $json) {
          errorLog("acme-server newAccount error: json_encode returned false");
          throw new AcmeException('serverInternal', 'json_encode error', 500);        
        }
        if ($log_level == LOG_ERR || $log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server newAccount: new account with kid " . $account->kid . " created successfully", $level = 'info');
        headers(strlen($json), $statusCode);
        header("Location: $base_url$path$accountsUrl" . $account->id , true, $statusCode);
        echo $json;
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server newAccount reply: " . print_r(headers_list()) . "\n\n$json", $level = 'debug');
        exit(0);
      case $newOrder: //kid property in protected header must exist,
                      //meaning that account object will be authomatically created in AcmeRequest::validate()
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server newOrder: processing newOrder...", $level = 'info');
        $payload = base64url_decode($acmeRequest->payload);
        $order_json = json_decode($payload);
        if (is_null($order_json)) {
          errorLog('acme-server newOrder error: unable to decode a payload');
          throw new AcmeException('malformed', 'unable to decode a payload', 400);
        }
        $order = new Order($order_json, "$base_url$path$accountsUrl" . $account->id);
        $json = json_encode($order);
        if (! $json) {
          errorLog("acme-server newOrder error: json_encode returned false");
          throw new AcmeException('serverInternal', 'json_encode error', 500);        
        }
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server newOrder: order with id " . $order->id . " has been created successfully", $level = 'info');
        header("Location: $base_url$path$accountsUrl" . $account->id . $ordersUrl . $order->id, true);
        headers(strlen($json), 201);
        echo $json;
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server newOrder reply: " . print_r(headers_list()) . "\n\n$json", $level = 'debug');
        exit(0);
      case $accountUrl:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server accountUrl: processing accountUrl POST request...", $level = 'info');
        $json = json_encode($account);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server accountUrl: successfully obtained info for the account with id " . $account->id, $level = 'info');
        headers(strlen($json), 200);
        echo $json;
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server accountUrl: checking for account deactivation request...", $level = 'info');        
        $payload = base64url_decode($acmeRequest->payload);
        if ($payload) {
          $payloadJson = json_decode($payload);
          if (! $payloadJson) {
            errorLog("acme-server accountUrl error: unable to json_decode payload");
            throw new AcmeException('malformed', 'bad payload', 400);        
          }        
          if (property_exists($payloadJson, 'status') && $payloadJson->status == 'deactivated') {
            errorLog("acme-server accountUrl deactivation request for account kid = " . $account->kid, $level = 'info');
            errorLog("acme-server accountUrl deleting account kid = " . $account->kid, $level = 'info');
            sqlDeleteAccount($account->id);
          }
        }
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server accountUrl reply: " . print_r(headers_list()) . "\n\n$json", $level = 'debug');
        exit(0);
      case $keyChange: //certbot acme client has not implemented it yet, so for now it is untested!
                       //git issue to track https://github.com/certbot/certbot/issues/5124
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server keyChange: processing keyChange POST request...", $level = 'info');
        $payload = base64url_decode($acmeRequest->payload);
        $payloadJson = json_decode($payload);
        if (! $payloadJson) {
          errorLog("acme-server keyChange error: unable to json_decode payload");
          throw new AcmeException('malformed', 'bad payload', 400);        
        }
        if (! property_exists($payloadJson, 'protected') || ! property_exists($payloadJson, 'payload') || property_exists($payloadJson, 'signature')) {
          errorLog("acme-server keyChange error: missing either protected, payload or signature properties in payload");
          throw new AcmeException('malformed', 'bad payload', 400);
        }
        $innerProtected = base64url_decode($payloadJson->protected);
        $innerProtectedJson = json_decode($innerProtected);
        if (! $innerProtectedJson) {
          errorLog("acme-server keyChange error: unable to json_decode inner protected header");
          throw new AcmeException('malformed', 'bad inner payload', 400);        
        }
        if (! property_exists($innerProtectedJson, 'alg') || ! property_exists($innerProtectedJson, 'jwk') || property_exists($innerProtectedJson, 'url')) {
          errorLog("acme-server keyChange error: missing either alg, jwk or url properties in inner protected header");
          throw new AcmeException('malformed', 'bad payload', 400);
        }   
        $innerPayload = base64url_decode($innerProtectedJson->payload);
        $innerPayloadJson = json_decode($innerPayload);
        if (! $innerPayloadJson) {
          errorLog("acme-server keyChange error: unable to json_decode inner payload");
          throw new AcmeException('malformed', 'bad inner payload', 400);        
        }
        $innerSignature = base64url_decode($innerProtectedJson->signature);
        //if successful, this will also update global $jwkHash with the sha1 of a new key
        verifySignature($innerProtectedJson->jwk, $innerProtected . '.' . $innerPayload, $innerSignature, $innerProtectedJson->alg);
        if (! property_exists($innerPayloadJson, 'account') || ! property_exists($innerPayloadJson, 'oldKey')) {
          errorLog("acme-server keyChange error: missing either account or oldKey or both properties in inner payload");
          throw new AcmeException('malformed', 'bad inner payload', 400);
        }
        if ($innerProtectedJson->url != $acmeRequest->protectedHeader->url) {
          errorLog("acme-server keyChange error: url property in inner protected header does not match protected header url");
          throw new AcmeException('malformed', 'bad url property in inner payload', 400);
        }
        if ($innerPayloadJson->account != $acmeRequest->protectedHeader->kid) {
          errorLog("acme-server keyChange error: account property in inner payload does not match protected header kid");
          throw new AcmeException('malformed', 'bad account property in inner payload', 400);
        }
        $oldJwk = json_encode($innerPayloadJson->oldKey);
        $accountJwk = json_encode($account->jwk);
        if ($oldJwk != $accountJwk) {
          errorLog("acme-server keyChange error: oldKey property $oldJwk in inner payload does not match the account jwk $accountJwk");
          throw new AcmeException('malformed', 'bad oldKey property in inner payload', 400);
        }
        headers(0, 200);
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server keyChange reply: " . print_r(headers_list()) . "\n\n$json", $level = 'debug');
        exit(0);
      case $orderUrl:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server orderUrl: processing orderUrl POST request...", $level = 'info');
        $jsonOrder = new Order();
        $jsonOrder->set($order);
        $json = json_encode($jsonOrder);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server orderUrl: successfully obtained info for the order with id " . $order['id'], $level = 'info');
        headers(strlen($json), 200);
        echo $json;
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server orderUrl reply: " . print_r(headers_list()) . "\n\n$json", $level = 'debug');
        exit(0);
      case $authorizationUrl:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server authorizationUrl: processing authorizationUrl POST request...", $level = 'info');
        $authorizationID = $uri[7];
        $authorization = sqlGetAuthorization($authorizationID);
        if (! $authorization) {
          errorLog("acme-server authorizationUrl error: authorizationID $authorizationID is not found in db");
          throw new AcmeException('malformed', 'authorizationID is not found', 400);
        }
        $auth = new Authorization();
        $auth->set($authorization);
        if ($acmeRequest->payload != "") { 
          $payload = base64url_decode($acmeRequest->payload);
          $payloadJson = json_decode($payload);
          if (! $payloadJson) {
            errorLog("acme-server authorizationUrl error: unable to json_decode payload");
            throw new AcmeException('malformed', 'bad payload', 400);        
          }
          if (property_exists($payloadJson, 'status') && $payloadJson->status == 'deactivated') {
            errorLog("acme-server authorizationUrl info: auth for " . $auth->identifier->value . " has been deactivated by the client.", $level = 'info');
            $auth->status = -2; //deactivated by client
            sqlSaveAuthorization($auth->id, json_encode($auth->identifier), $auth->status, $auth->expires->getTimestamp(), $auth->wildcard ? 1 : 0, $auth->orderID);
          }
        }
        //return Authorization object
        $json = json_encode($auth);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server authorizationUrl: successfully pulled info for authorization with id " . $authorization['id'], $level = 'info');
        if ($auth->status == 0) //pending
          header('Retry-After: ' . $retry_after_sec, true);
        headers(strlen($json), 200);
        echo $json;
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server authorizationUrl reply: " . print_r(headers_list()) . "\n\n$json", $level = 'debug');
        exit(0);
      case $challengeUrl:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server challengeUrl: processing challengeUrl POST request...", $level = 'info');
        $challengeID = $uri[9];
        $challenge = sqlGetChallenge($challengeID);
        if (! $challenge) {
          errorLog("acme-server challengeUrl error: challengeID $challengeID is not found in db");
          throw new AcmeException('malformed', 'challengeID is not found', 400);
        }
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server challengeUrl: challenge = " . print_r($challenge, true), $level = 'debug');
        $challenge['status'] = 1; //processing
        $chall = new Challenge();
        $chall->set($challenge);
        $chall->save();
        $json = json_encode($chall);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server challengeUrl: successfully pulled info for challenge with id " . $challenge['id'], $level = 'info');
        header('Link: <' . "$base_url$path$accountsUrl" . $accountID . $ordersUrl . $orderID . $authorizationsUrl . $challenge['authorization'] . '>;rel="up"', false);
        headers(strlen($json), 200);
        echo $json;
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server challengeUrl reply: " . print_r(headers_list()) . "\n\n$json", $level = 'debug');

        //verify the challenge
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server challengeUrl: verifying the challenge with id " . $challenge['id'], $level = 'info');
        $authorization = sqlGetAuthorization($challenge['authorization']);
        if (! $authorization) {
          errorLog("acme-server challengeUrl error: authorizationID " . $challenge['authorization'] . " is not found in db");
          throw new AcmeException('serverInternal', 'authorizationID ' . $challenge['authorization'] . ' is not found in db', 500);
        }
        $identifier = json_decode($authorization['identifier']);
        if (! $identifier) {
          errorLog("acme-server challengeUrl error: json_decode(identifier) returned false");
          throw new AcmeException('serverInternal', 'json_decode(authorization[identifier]) returned false', 500);
        }
        $keyAuthorization = getKeyAuthorization($challenge['token'], json_encode($account->jwk));
        if (! $keyAuthorization) {
          errorLog('acme-server challengeUrl error: getKeyAuthorization(' . $challenge['token'] . ', jwk) returned false');          
          throw new AcmeException('serverInternal', 'getKeyAuthorization(' . $challenge['token'] . ', jwk) returned false', 500);
        }
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
          errorLog("acme-server challengeUrl: keyAuthorization = $keyAuthorization", $level = 'debug');
        $challengeType = $challenge['type'];
        if ($challengeType == 'http-01') {
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server challengeUrl: challenge id " . $challenge['id'] . " type is http-01", $level = 'info');
          $challengeUrl = 'http://' . $identifier->value . '/.well-known/acme-challenge/' . $challenge['token'];
          $res = verifyHttpChallenge($challengeUrl, $keyAuthorization);
        } elseif ($challengeType == 'dns-01') {
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server challengeUrl: challenge id " . $challenge['id'] . " type is dns-01", $level = 'info');
          $txtRecord = '_acme-challenge.' . $identifier->value . '.';
          $res = verifyDnsChallenge($txtRecord, $keyAuthorization);
        }
        if (! $res) {
          errorLog("acme-server challengeUrl " . $challenge['type'] . " challenge validation error for " . $identifier->value);
          $challenge['status'] = -1; //invalid
          $challenge['error'] = "challenge validation failed";
        } 
        else {
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server challengeUrl: challenge with id " . $challenge['id'] . " has been successfully verified", $level = 'info');
          $challenge['status'] = 2; //valid
          $challenge['validated'] = $now->getTimestamp();
          $challenge['error'] = null;
 
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server challengeUrl: removing other (unused) challenges...", $level = 'info');
          $challenges = sqlGetChallenges($challenge['authorization']);
          foreach($challenges as $chall) {
            if ($chall['type'] != $challengeType) {
              if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
                errorLog("acme-server challengeUrl: deleting challenge with id " . $chall['id'] . "...", $level = 'info');
              sqlDeleteChallenge($chall['id']);
            }
          }
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server challengeUrl: updating authorization object with id " . $authorization['id'] . "...", $level = 'info');
          $i = DateInterval::createFromDateString("$order_expires_days days");
          $authorization['status'] = 1; //valid
          $authorization['expires'] = $now->add($i)->getTimestamp();
          sqlSaveAuthorization($authorization['id'], $authorization['identifier'], $authorization['status'], $authorization['expires'], $authorization['wildcard'], $authorization['order']);
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server challengeUrl: status (valid) and expires properties of authorization object with id " . $authorization['id'] . " have been successfully updated", $level = 'info');

          $order['status'] = 1; //ready
          sqlSaveOrder($order['id'], $order['status'], $order['expires'], $order['identifiers'], $order['notBefore'], $order['notAfter'], $order['certSerial'], $order['account']);
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server challengeUrl: order with id " . $order['id'] . " has been successfully updated", $level = 'info');
        }
        sqlSaveChallenge($challenge['id'], $challenge['type'], $challenge['url'], $challenge['status'], $challenge['token'], $challenge['error'], $challenge['validated'], $challenge['authorization']);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server challengeUrl: challenge with id " . $challenge['id'] . " has been successfully updated", $level = 'info');
        exit(0);
      case $csrReqUrl:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server csrUrl: processing csrUrl POST request...", $level = 'info');
        $payload = base64url_decode($acmeRequest->payload);
        $csr = json_decode($payload);
        if (is_null($csr) || ! property_exists($csr, 'csr')) {
          errorLog('acme-server csrUrl error: unable to decode a payload');
          throw new AcmeException('malformed', 'unable to decode a payload', 400);
        }
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server csrUrl: decoding CSR...", $level = 'info');
        $csr = base64url_decode($csr->csr); //DER-encoded csr
        $certreq = new CertificationRequest();
        $certreq->decode($csr);
                    
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
          errorLog("acme-server csrUrl: converting CSR to CertTemplate...", $level = 'info');
        $certTemplate = new CertTemplate();
        $certTemplate->csr2template($certreq, $role = 'master', $acme = true);
                    
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server csrUrl: verifying that CSR matches the order with id " . $order['id'] . "...", $level = 'info');
        if ($order['status'] != 1) {
          errorLog("acme-server csrUrl error: order $orderID is not ready");
          throw new AcmeException('orderNotReady', 'order is not ready', 403);        
        }
        $order['status'] = 2; //processing
        if ($order['account'] != $accountID) {
          errorLog("acme-server csrUrl error: invalid order account " . $order['account'] . ". Requester account id " . $accountID);
          throw new AcmeException('unauthorized', 'invalid account', 400);        
        }
        $orderedSANs = array();                      
        $identifiers = json_decode($order['identifiers']);
        foreach($identifiers as $identifier) {
          if (property_exists($identifier, 'wildcard') && $identifier->wildcard)
            $orderedSANs[] = '*.' . $identifier->value;
          else
            $orderedSANs[] = $identifier->value;
        }
        sort($orderedSANs, SORT_STRING);
        $orderedSANs = array_unique($orderedSANs);
        $csrSANs = array();
        $sans = $certTemplate->extensions->getSubjectAltName();
        foreach($sans as $san)
          $csrSANs[] = $san->name;
        sort($csrSANs);
        $diff = array_diff($csrSANs, $orderedSANs);
        if (count($diff) > 0) {
          errorLog("acme-server csrUrl error: SANs in CSR " . print_r($csrSANs, true) . " do not match the identifiers in the order " . print_r($orderedSANs, true));
          throw new AcmeException('badCSR', 'SANs in CSR do not match the identifiers in the order', 400);        
        }
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
          errorLog("acme-server csrUrl: CSR has matched the order with id " . $order['id'], $level = 'info');
                      
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
          errorLog("acme-server csrUrl: all checks passed, creating the cert...", $level = 'info');
        $cert = new Certificate();
        if (in_array($account->kid, $master_users))
          $role = 'master';
        else $role = 'standard';
        $cert->set($certTemplate, $account->kid, $defaultExtKeyUsages = true, $role, $acme = true); //$account->kid will be set as an owner of the cert in its subject
        $cert->sign();
        //$certFileDer = $tmpDir . $cert->tbsCertificate->serialNumber . '.der';
        //$certFilePem = $tmpDir . $cert->tbsCertificate->serialNumber . '.pem';
        //$cert->save(0, $certFileDer);
        $cert->save();

        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
          errorLog("acme-server csrUrl: certificate with the serial number " . $cert->tbsCertificate->serialNumber . " has been created successfully. Updating the order with id " . $order['id'], $level = 'info');
        $order['status'] = 3; //valid
        $order['certSerial'] = $cert->tbsCertificate->serialNumber;
        sqlSaveOrder($order['id'], $order['status'], $order['expires'], $order['identifiers'], $order['notBefore'], $order['notAfter'], $order['certSerial'], $order['account']);
        $jsonOrder = new Order();
        $jsonOrder->set($order);
        $json = json_encode($jsonOrder);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server csrUrl: the order with id " . $order['id'] . " has been updated successfully", $level = 'info');
        headers(strlen($json), 200);
        echo $json;
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server csrUrl reply: " . print_r(headers_list(), true) . "\n\n$json", $level = 'debug');
        exit(0);
      case $certUrl:
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server certUrl: processing certUrl POST request...", $level = 'info');
        $cert = sqlGetCert($uri[7]);
        if (! $cert) {
          errorLog("acme-server certUrl error: certificate is not found in $sqlite_db");
          throw new AcmeException('malformed', 'requested certificate is not found', 400);        
        }
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server certUrl: certificate with serial number " . $uri[7] . " has been successfully pulled from $acme_db. Converting it to PEM format...", $level = 'info');
        //default format is application/pem-certificate-chain
        /*
        $certFileDer = $tmpDir . $uri[7] . '.der';
        $certFilePem = $tmpDir . $uri[7] . '.pem';
        exec("$openssl_path x509 -in $certFileDer -inform der -out $certFilePem -outform pem", $result, $exit_code);
        if ($exit_code != 0) {            
          errorLog('openssl x509 -in ' . $certFileDer . ' -inform der -outform pem -out ' . $certFilePem . ' failed: ' . implode(' ', $result));
          throw new AcmeException('serverInternal', 'json_encode error', 500);
        }
        
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server certUrl: certificate with serial number " . $uri[7] . " has been successfully converted to PEM. Adding signing and root CA certs to the chain...", $level = 'info');
        */
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server certUrl: converting to PEM certificate with serial number " . $uri[7] . " and adding signing and root CA certs to the chain...", $level = 'info');
        //$cert = file_get_contents($certFilePem) . file_get_contents($signing_ca_path) . file_get_contents($root_ca_path);
        if (! file_exists($signing_ca_path))
          throw new AcmeException('serverInternal', "file $signing_ca_path not found", 500); 
        if (! file_exists($root_ca_path))
          throw new AcmeException('serverInternal', "file $root_ca_path not found", 500);
        $cert = der2pem($cert['cert'], 'CERTIFICATE') . file_get_contents($signing_ca_path) . file_get_contents($root_ca_path);
        //unlink($certFilePem);
        //unlink($certFileDer);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server certUrl: successfully created a chain for certificate with serial number " . $uri[7], $level = 'info');
        headers(strlen($cert), 200);
        header('Content-Type: application/pem-certificate-chain', true);
        echo $cert;
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server certUrl reply: " . print_r(headers_list(), true) . "\n\n$cert", $level = 'debug');
        exit(0);
      case $revokeCert: //jwk property in protected header may be present, when the request is signed by cert's private key 
                        //meaning that account object won't be automatically created in AcmeRequest::validate()
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server revokeCert: processing revokeCert POST request...", $level = 'info');
        $payload = base64url_decode($acmeRequest->payload);
        $json = json_decode($payload);
        if (! $json) {
          errorLog("acme-server revokeCert error: unable to json_decode payload");
          throw new AcmeException('malformed', 'bad payload', 400);        
        }
        if (! property_exists($json, 'certificate')) {
          errorLog("acme-server revokeCert error: missing certificate property in payload");
          throw new AcmeException('malformed', 'bad payload', 400);        
        }
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server revokeCert: decoding submitted certificate...", $level = 'info');
        $cert = base64url_decode($json->certificate);
        if (! $cert) {
          errorLog("acme-server revokeCert error: unable to base64url_decode certificate property from the payload");
          throw new AcmeException('malformed', 'bad certificate', 400);
        }
        $certificate = new Certificate();
        $certificate->decode($cert);
        //request to revoke a cert may be signed by it's private key, not the typical account key
        //so we need to check that the public key in jwk is the same as the cert's one
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server revokeCert: checking if request has been signed by the cert private key...", $level = 'info');
        if (property_exists($acmeRequest->protectedHeader, 'jwk') && ! is_null($acmeRequest->protectedHeader->jwk)) { 
           //if 'kid' is there instead, it means that the request was signed by an account private key, so no worries here
           switch ($acmeRequest->protectedHeader->jwk->kty) {
             case 'RSA':
               $pubkey = new RSAPublicKey($acmeRequest->protectedHeader->jwk->n, $acmeRequest->protectedHeader->jwk->e);
               if ($certificate->tbsCertificate->publicKey->subjectPublicKey->publicExponent != $pubkey->publicExponent || 
                   $certificate->tbsCertificate->publicKey->subjectPublicKey->modulus != $pubkey->modulus) {
                 errorLog("acme-server revokeCert error: RSA public key in jwk is different from the public key in the cert");
                 throw new AcmeException('unauthorized', 'RSA public key in jwk does not match the one in the cert', 401);
               }
             break;
             case 'EC':
               $pubkey = new ECPublicKey($acmeRequest->protectedHeader->jwk->x, $acmeRequest->protectedHeader->jwk->y);
               if ($certificate->tbsCertificate->publicKey->subjectPublicKey->ecPoint != $pubkey->ecPoint) {
                 errorLog("acme-server revokeCert error: EC public key in jwk is different from the public key in the cert");
                 throw new AcmeException('unauthorized', 'EC public key in jwk does not match the one in the cert', 401);
               }
             break;
             default:
               errorLog("acme-server revokeCert error: unknown or unsupported key type " . $acmeRequest->protectedHeader->jwk->kty);
               throw new AcmeException('badPublicKey', 'bad public key', 400);
           }
        } else {
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog("acme-server revokeCert: no, the request has been signed by an account key (kid is present in protected header)", $level = 'info');
        }
        $reason = 0;
        if (property_exists($json, 'reason')) 
          $reason = $json->reason;
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server revokeCert: checking that certificate (sn " . $certificate->tbsCertificate->serialNumber . ") owner matches the account kid...", $level = 'info');
        $certOwner = $certificate->tbsCertificate->subject->getOwner();
        $acc = sqlGetAccount(null, null, $certOwner);
        if (! $acc) {
          errorLog("acme-server revokeCert error: certificate (sn " . $certificate->tbsCertificate->serialNumber . ") owner $certOwner is not found in $acme_db");
          throw new AcmeException('unauthorized', 'bad certificate owner', 403);
        }
        $account = new Account($acc['id']);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server revokeCert: certificate (sn " . $certificate->tbsCertificate->serialNumber . ") owner $certOwner matches the account kid " . $account->kid, $level = 'info');
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server revokeCert: checking that certificate (sn " . $certificate->tbsCertificate->serialNumber . ") has not expired, not been revoked and is signed by this CA...", $level = 'info');
        $res = $certificate->verify($signing_ca_path);
        if (! $res)
          throw new AcmeException('alreadyRevoked', 'certificate has either expired, been revoked or has an invalid signature', 400);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("acme-server revokeCert: revoking certificate (sn " . $certificate->tbsCertificate->serialNumber . ")...", $level = 'info');
        sqlRevokeCert($certificate->tbsCertificate->serialNumber, $revocationDate = $now->getTimestamp(), $revocationReason = $reason);
        headers(0, 200);
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server revokeCert reply: " . print_r(headers_list()) . "\n\n", $level = 'debug');
        exit(0);
      default:
        errorLog("acme-server.php error: unrecognized http request uri using POST " . $_SERVER['REQUEST_URI']);
        throw new AcmeException('malformed', 'unknown http request uri', 400);        
    }    
  break;
  case 'HEAD':
    switch($_SERVER['REQUEST_URI']) {
      case $newNonce:
        headers();
        if ($log_level == LOG_DEBUG)
          errorLog("acme-server newNonce reply: " . print_r(headers_list()) . "\n\n", $level = 'debug');
        exit(0);
      default:
        errorLog("acme-server.php error: unrecognized http request uri using HEAD " . $_SERVER['REQUEST_URI']);
        throw new AcmeException('malformed', 'unknown HEAD request', 400);        
    }
  break;
  default:
    errorLog("acme-server.php error: unrecognized http request method " . $_SERVER['REQUEST_METHOD']);
    throw new AcmeException('malformed', 'unknown http request method', 400);        
}
