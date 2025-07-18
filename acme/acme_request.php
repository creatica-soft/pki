<?php

/*
json encoded objects might need to be preserved as is for comparisson because $json = json_decode($json) following json_encode($json)
may return a different string representation.
alternatively, one may pass the encoded string to json_encode(json_decode($json)) for both obejcts before comparisson but this
will not work for signature verification
*/

class ProtectedHeader { //all properties are mandatory except union of $jwk and $kid - only one must be present
  public $alg; //either ES256 (must support) or Ed25519 (should support), also RS256 (supported)
  public $jwk; // ES256 or Ed25519 public key for newAccount or revokeCert only
               // see https://datatracker.ietf.org/doc/html/rfc7518#section-3.4 for ES256 or
               // https://datatracker.ietf.org/doc/html/rfc8037 for Ed25519
  public $kid; //for all other request, mutually exclusive with $jwk and must be an account URL
  public $nonce; //all POST requests must carry nonce
  public $base_url; //it must match $base_url$_SERVER['REQUEST_URI']

  function __construct($encoded) {
    global $supported_jwk_algs, $base_url, $log_level;
    $decoded = base64url_decode($encoded);
    $protected = json_decode($decoded);
    if ($log_level == LOG_DEBUG) 
      errorLog('ProtectedHeader::__construct(): protected = ' . print_r($protected, true));
    if (property_exists($protected, 'alg')) {
      if (! in_array($protected->alg, $supported_jwk_algs)) {
        errorLog("ProtectedHeader::__construct() error: badSignatureAlgorithm " . $protected->alg);
        throw new AcmeException('badSignatureAlgorithm', 'unsupported algorithm: ' . $protected->alg, 400);
      }
      $this->alg = $protected->alg;
    }
    if (property_exists($protected, 'jwk')) {
      if (property_exists($protected, 'kid')) {
        errorLog("AcmeRequest::__construct() error: jwk and kid are mutually exclusive");
        throw new AcmeException('malformed', 'jwk and kid are mutually exclusive', 400);
      }
      $this->jwk = $protected->jwk; 
      $this->kid = null;
    }
    elseif (property_exists($protected, 'kid')) {
      $this->kid = $protected->kid; 
      $this->jwk = null;
    } else {
      errorLog("ProtectedHeader::__construct() error: either jwk or kid must exist in the protected header");
      throw new AcmeException('unauthorized', 'missing jwk or kid in protected header', 401);
    }
    $this->nonce = null;
    if (property_exists($protected, 'nonce')) {
      $nonce = base64url_decode($protected->nonce);
      if (! $nonce) {
        errorLog("ProtectedHeader::__construct() error: bad nonce - base64url_decode() returned false");
        throw new AcmeException('badNonce', 'bad nonce', 400);       
      }
      //need to compare it to the issued nonce in newNonce request
      $nonces = sqlGetNonces($_SERVER['REMOTE_ADDR']);
      if (! $nonces) {
        errorLog("ProtectedHeader::__construct() error: nonce for the sender IP " . $_SERVER['REMOTE_ADDR'] . " is not found in db");
        throw new AcmeException('badNonce', 'unknown nonce', 400);       
      }
      foreach ($nonces as $n) {
        if ($n['nonce'] == $nonce) {
          sqlDeleteNonce($nonce);
          $this->nonce = $nonce;
          break;
        }
      }
      if (is_null($this->nonce)) {
        errorLog("ProtectedHeader::__construct() error: unrecognized nonce in POST request");
        throw new AcmeException('badNonce', 'unrecognized nonce in POST request', 400); 
      }
    } else {
      if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        errorLog("ProtectedHeader::__construct() error: missing nonce in POST request");
        throw new AcmeException('badNonce', 'missing nonce in POST request', 400); 
      }
    }
    if (property_exists($protected, 'url')) {
      if ($protected->url != $base_url . $_SERVER['REQUEST_URI']) {
        errorLog("ProtectedHeader::__construct() error: url in protected json header " . $protected->url . " does not match request uri " . $base_url . $_SERVER['REQUEST_URI']);
        throw new AcmeException('unauthorized', 'url in protected json header does not match request url', 401);
      }
      $this->url = $protected->url;
    }
  }
}

class AcmeRequest {
  public $protectedHeader; //Protected class
  public $protected; //base64url-encoded header for signature verification
  public $payload; //payload string (base64url-encoded)
  public $signature; //base64url-decoded binary string

  private function validate() {
    global $jwk, $jwk_hash, $account, $revokeCert;
    if (! is_null($this->protectedHeader->jwk)) {
      $jwk = $this->protectedHeader->jwk;
    }
    else {
      if (is_null($this->protectedHeader->kid)) {
        errorLog("AcmeRequest::validate() error: protectedHeader->kid is null");
        throw new AcmeException('malformed', 'neither jwk nor kid exists in protected header', 400);
      }
      $kid = explode('/', $this->protectedHeader->kid);
      $id = array_pop($kid);
      $account = new Account($id);
      $jwk = $account->jwk;
    }
    verifySignature($jwk, $this->protected . '.' . $this->payload, $this->signature, $this->protectedHeader->alg);
  }

  function __construct($encoded) {
    $acmeRequest = json_decode($encoded);
    if (! property_exists($acmeRequest, 'protected')) {
      errorLog("AcmeRequest::__construct() error: missing protected header");
      throw new AcmeException('malformed', 'missing protected header', 400);
    }
    $this->protected = $acmeRequest->protected;
    $this->protectedHeader = new ProtectedHeader($acmeRequest->protected);
    if (! property_exists($acmeRequest, 'payload')) {
      errorLog("AcmeRequest::__construct() error: missing payload");
      throw new AcmeException('malformed', 'missing payload', 400);
    }
    $this->payload = $acmeRequest->payload;
    if (! property_exists($acmeRequest, 'signature')) {
      errorLog("AcmeRequest::__construct() error: missing signature");
      throw new AcmeException('malformed', 'missing signature', 400);
    }
    $this->signature = base64url_decode($acmeRequest->signature);
    $this->validate();
  }
}
