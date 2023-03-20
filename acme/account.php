<?php

//uri for an account should look like /acme/accounts/<id>
class Account implements JsonSerializable {
  public $id; //accountID
  public $jwk; //public key conveyed in ProtectedHeader
  public $jwkHash; //sha1 hash of DER-encoded public key in $jwk
  public $status; //required; "valid" (0) => "deactivated" (1) by a client or "revoked" (-1) by a server
  public $contacts; //optional, array of URL strings, usually "mailto:account@example.com"
                   // if mailto is unsupported, then error with unsupportedContact
                   // if email is not valid, then error with invalidContact
  public $kid; //sAMAccountName from AD - used in externalAccountBinding object
  public $termsOfServiceAgreed; //optional, boolean
  public $externalAccountBinding; //optional, object
  public $onlyReturnExisting; //optional, boolean; do not create new account if it's present and true
                              // if account does not exist (no jwk in accounts table), then return 400 accountDoesNotExist
  public $orders; //required; url such as https://pki.techcorpapps.com/acme/accounts/<id>/orders, 
                  //which should return an array of order URLs in orders list
                  //see https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2.1

  private function accountStatus2str($status) {
    switch ($status) {
      case 0: return "valid";
      case 1: return "deactivated";
      case -1: return "revoked";
      default: return "unknown";
    }
  }

  function jsonSerialize() {
    $account = array('status' => $this->accountStatus2str($this->status));
    if (! is_null($this->contacts))
      $account['contact'] = $this->contacts;
    if (! is_null($this->termsOfServiceAgreed))
      $account['termsOfServiceAgreed'] = $this->termsOfServiceAgreed;
    if (! is_null($this->externalAccountBinding))
      $account['externalAccountBinding'] = $this->externalAccountBinding;
    if (! is_null($this->orders))
      $account['orders'] = $this->orders;    
    return $account;
  }

  function set($account) { //$account is a json object here
    global $externalAccountBindingRequired, $jwk, $newAccount, $mackeys_file, $base_url, $log_level, $acme_db;
    //need to validate contacts: if url schema is not mailto:, then return 'unsupportedContact'
    //if email is invalid, then return 'invalidContact'
    if (property_exists($account, 'contact')) {
      foreach($account->contact as $contact) {
        if (! str_starts_with($contact, "mailto:")) {
          errorLog("Account::set() error: unsupported contact schema: $contact");
          throw new AcmeException('unsupportedContact', 'unsupported schema in contact url', 400);
        }
        $c = explode(':', $contact)[1];
        if (! preg_match("/^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,})$/i", $c)) {
          errorLog("Account::set() error: invalid email address: $");
          throw new AcmeException('invalidContact', 'invalid email address', 400);
        }
      }
      $this->contacts = $account->contact;
    }
    if (property_exists($account, 'termsOfServiceAgreed'))
      $this->termsOfServiceAgreed = $account->termsOfServiceAgreed;
    if (property_exists($account, 'onlyReturnExisting')) {
      $this->onlyReturnExisting = $account->onlyReturnExisting;
    }
    if (property_exists($account, 'externalAccountBinding')) {
      $this->externalAccountBinding = $account->externalAccountBinding;
      //verify the binding
      if (property_exists($account->externalAccountBinding, 'protected') && property_exists($account->externalAccountBinding, 'payload') && property_exists($account->externalAccountBinding, 'signature')) {
        $protected = base64url_decode($account->externalAccountBinding->protected);
        if (! $protected) {
          errorLog("Account::set() unable to base64 decode protected property in externalAccountBinding");
          throw new AcmeException('malformed', 'bad protected property in externalAccountBinding', 400);                  
        }
        $protectedJson = json_decode($protected);
        if (! $protectedJson) {
          errorLog("Account::set() unable to json_decode protected property in externalAccountBinding");
          throw new AcmeException('malformed', 'bad protected property in externalAccountBinding', 400);                  
        }
        if (property_exists($protectedJson, 'alg') && property_exists($protectedJson, 'kid') && property_exists($protectedJson, 'url')) {
          $this->kid = $protectedJson->kid;
          $key = sqlGetKey($this->kid);
          if (! $key) {
            errorLog("Account::set() mac key for $kid is not found in $acme_db");
            throw new AcmeException('externalAccountRequired', "mac key for $kid is not found", 400);                  
          }
          $hmacKey = json_encode(array('kty' => 'HS256', 'k' => $key));
          verifySignature(json_decode($hmacKey), $account->externalAccountBinding->protected . '.' . $account->externalAccountBinding->payload, $account->externalAccountBinding->signature);

          $jwk2 = base64url_decode($account->externalAccountBinding->payload);
          if (! $jwk2) {
            errorLog("Account::set() error: unable to base64url_decode jwk in externalAccountBinding->payload");
            throw new AcmeException('externalAccountRequired', 'bad externalAccountBinding payload', 400);                  
          }
          $jwk2 = json_decode($jwk2);
          if (! $jwk2) {
            errorLog("Account::set() error: unable to json_decode jwk in externalAccountBinding->payload");
            throw new AcmeException('externalAccountRequired', 'bad externalAccountBinding payload', 400);                  
          }
          $json = json_encode($jwk);
          $jwk2 = json_encode($jwk2);
          if ($log_level == LOG_DEBUG) { 
            errorLog("jwk = $json");
            errorLog("jwk2 = $jwk2");
          }
          $hash1 = hash('sha1', $json, $binary = false);
          $hash2 = hash('sha1', $jwk2, $binary = false);
          if ($hash1 != $hash2) {
            errorLog("Account::set() jwk in externalAccountBinding payload $jwk2 is different from jwk in protected header $json");
            throw new AcmeException('externalAccountRequired', 'jwk in externalAccountBinding payload is different from jwk in protected header', 400);                  
          }
          if ($protectedJson->url != "$base_url$newAccount") {
            errorLog("Account::set() url in externalAccountBinding protected property " . $protectedJson->url . " is different from from newAccount url $base_url$newAccount");
            throw new AcmeException('externalAccountRequired', 'url in externalAccountBinding protected property ' . $protectedJson->url . " is different from from newAccount url $base_url$newAccount", 400);                  
          }
        } else {
          errorLog("Account::set() missing one or more of the following properties in externalAccountBinding->protected: alg, kid or url");
          throw new AcmeException('externalAccountRequired', 'missing one or more of the following properties in externalAccountBinding->protected: alg, kid or url', 400);                  
        }        
      } else {
        errorLog("Account::set() missing one or more of the following properties in externalAccountBinding: protected, payload or signature");
        throw new AcmeException('externalAccountRequired', 'missing one or more of the following properties in externalAccountBinding: protected, payload or signature', 400);                  
      }
    } else {
      if ($externalAccountBindingRequired) {
        errorLog("Account::set() missing external account binding");
        throw new AcmeException('externalAccountRequired', 'missing external account binding', 400);                  
      }
    }
    sqlSaveAccount($this->id, $this->status, $this->termsOfServiceAgreed, $this->jwkHash, $this->kid, json_encode($this->jwk), json_encode($this->contacts), json_encode($this->externalAccountBinding));
  }

  //this private function just fills the properties of Account instance from the database
  private function setAccount($account) { //here $account is an array, returned from acme.db
    $this->id = $account['id'];
    //$this->jwk = $account['jwk'];
    $this->jwk = json_decode($account['jwk']);
    $this->jwkHash = $account['jwk_hash'];
    if (! is_null($account['kid']))
      $this->kid = $account['kid'];
    if ($account['status'] != 0) {
      $status = $this->accountStatus2str($account['status']);
      sqlDeleteAccount($this->id);
      errorLog("Account::setAccount() error: unauthorized - account kid " . $account->kid . " status is $status");
      throw new AcmeException('unauthorized', "account status is $status", 401);
    }
    $this->status = 0;
    if (! is_null($account['contacts']))
      $this->contacts = json_decode($account['contacts']);
    if (! is_null($account['termsOfServiceAgreed']))
      $this->termsOfServiceAgreed  = $account['termsOfServiceAgreed'] ? true : false;
    if (! is_null($account['externalAccountBinding']))
      $this->externalAccountBinding = json_decode($account['externalAccountBinding']);
  }

  function __construct($id = null) {
    global $jwk, $jwk_hash, $acme_db, $account_id_length_bytes, $base_url, $accountsUrl, $ordersUrl;
    if (is_null($id)) {
      if (is_null($jwk_hash)) {
        errorLog('Account::__construct() error: both id and jwk_hash are null');
        throw new AcmeException('accountDoesNotExist', 'account does not exist', 400);
      }
      $account = sqlGetAccount(null, $jwk_hash);
    }
    else {
      $account = sqlGetAccount($id);
      if (! $account) {
        errorLog("Account::__construct() error: account with id $id does not exist in $acme_db");
        throw new AcmeException('accountDoesNotExist', 'account does not exist', 400);
      }
    }
    if ($account) {
      $this->setAccount($account);
    } else { //account do not exists (sqlGetAccount(null, $jwk_hash) returns false) - create a new one
      do {
        $id = gmp_random_bits($account_id_length_bytes * 8);
        $id = gmp_strval($id, 10);
      } while(sqlGetAccount($id));
      $this->id = $id;
      $this->jwk = $jwk;
      $this->jwkHash = $jwk_hash;
      $this->contacts = null;
      $this->kid = null;
      $this->termsOfServiceAgreed = null;
      $this->externalAccountBinding = null;
    }
    $this->orders = $base_url . $accountsUrl . $this->id . $ordersUrl;
  }
}

?>