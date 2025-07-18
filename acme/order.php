<?php

//uri for an order should look like /acme/accounts/<id>/orders/<id>
//finalize for csr should look like /acme/accounts/<id>/orders/<id>/finalize
//certificate for an order should look like /acme/accounts/<id>/orders/<id>/certificate
class Order implements JsonSerializable {
  public $id;
  public $status; //"pending" (0) => "ready" (1) (after validation) => "processing" (2) (after csr) => "valid" (3) or "invalid" (-1)
  public $expires; //optional, string in rfc3339 format; for example, 2022-12-31T23:59:60Z - required for "pending" and "valid" status
  public $identifiers; //array of Identifier objects 
  public $notBefore; //in rfc3339 format
  public $notAfter; //in rfc3339 format
  public $error; //object, rfc7808, optional order processing error, I think mandatory for "invalid" status
                 //I think it can be just set to error $detail and submitted to throw new AcmeException($type, $detail, $statusCode) function
                 //alternatively, it can be an object with $type, $detail and $statusCode properties
  public $authorizations; //required, array of url strings for POST-AS-GET requests, one per identifier; 
                          //each will return Authorization object
  public $finalize; //required, url string where CSR should be posted once all authorizations are complete
  public $certificate; //optional but required for "valid" status; url for issued certificate
                       //we just save certSerial and build url on the fly
  private $accountID;

  private function orderStatus2str($status) {
    switch ($status) {
      case 0: return "pending";
      case 1: return "ready";
      case 2: return "processing";
      case 3: return "valid";
      case -1: return "invalid";
      default: return "unknown";
    }
  }

  function jsonSerialize() {
    global $base_url, $path, $accountsUrl, $ordersUrl, $certificateUrl;
    $order = array('status' => $this->orderStatus2str($this->status));
    if (($this->status == 0 || $this->status == 3) && ! is_null($this->expires))
      $order['expires'] = $this->expires->format(DATE_ATOM);
    $order['identifiers'] = $this->identifiers;
    $order['notBefore'] = $this->notBefore->format(DATE_ATOM);
    $order['notAfter'] = $this->notAfter->format(DATE_ATOM);    
    if (! is_null($this->error))
      $order['error'] = $this->error;    
    $order['authorizations'] = $this->authorizations;    
    $order['finalize'] = $this->finalize;    
    if (! is_null($this->certificate))
      $order['certificate'] = "$base_url$path$accountsUrl" . $this->accountID . $ordersUrl . $this->id . $certificateUrl . $this->certificate;    
    return $order;
  }

  private function checkQuotas($subject = null) {
    global $account, $max_certs_per_cn, $max_certs_standard, $max_certs_master, $master_users;
    $certNumberOverall = sqlGetOwnCertsCount($account->kid);
    if (in_array($account->kid, $master_users))
      $role = 'master';
    else $role = 'standard';
    switch ($role){
      case 'standard':
        if ($certNumberOverall >= $max_certs_standard) {
          errorLog("Order::checkQuotas() error: overall certificates number $certNumberOverall is greater than the limit $max_certs_standard");
          throw new AcmeException('rateLimited', "overall certificates number $certNumberOverall is greater than the limit $max_certs_standard", 400);
        }
      break;
      case 'master':
        if ($certNumberOverall >= $max_certs_master) {
          errorLog("Order::checkQuotas() error: overall certificates number $certNumberOverall is greater than the limit $max_certs_master");
          throw new AcmeException('rateLimited', "overall certificates number $certNumberOverall is greater than the limit $max_certs_master", 400);
        }
      break;
    }
    if (! is_null($subject)) {
      $certNumberPerCN = sqlGetOwnCertsCount($account->kid, $subject);
      if ($certNumberPerCN >= $max_certs_per_cn) {
        errorLog("Order::checkQuotas() error: certificates number per domain $certNumberPerCN is greater than the limit $max_certs_per_cn");
        throw new AcmeException('rateLimited', "certificates number per domain $certNumberPerCN is greater than the limit $max_certs_per_cn", 400);
      }
    }
  }

  function set($order) {
    global $base_url, $path, $accountsUrl, $ordersUrl, $authorizationsUrl, $csrUrl, $certificateUrl, $now;
    if (is_null($order)) {
      errorLog('Order::set() error: an argument is null');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    if (! is_array($order)) {
      errorLog('Order::set() error: an argument is not an array');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $this->id = $order['id'];
    if (key_exists('error', $order))
      $this->error = json_decode($order['error']);
    else $this->error = null;
    if ($order['expires'] < $now->getTimestamp()) { //expired
      $this->status = -1; //invalid
      $this->error = 'expired';
    } else       
      $this->status = $order['status'];
    $this->expires = DateTime::createFromFormat('U', $order['expires']);
    $this->identifiers = json_decode($order['identifiers']);
    $this->notBefore = DateTime::createFromFormat('U', $order['notBefore']);
    $this->notAfter = DateTime::createFromFormat('U', $order['notAfter']);
    $authorizations = sqlGetAuthorizations($this->id);
    if ($authorizations) {
      foreach($authorizations as $authorization)
        $this->authorizations[] = "$base_url$path$accountsUrl" . $order['account'] . $ordersUrl . $this->id . $authorizationsUrl . $authorization['id'];
    }
    $this->finalize = "$base_url$path$accountsUrl" . $order['account'] . $ordersUrl . $this->id . $authorizationsUrl . $authorization['id'] . $csrUrl;
    if ($this->status == 3 && key_exists('certSerial', $order)) {
      $this->certificate = $order['certSerial'];
    } else $this->certificate = null;
    $this->accountID = $order['account'];
    if ($order['status'] == -1) { //invalid
      sqlDeleteOrder($this->id);
      errorLog("Order::set() error: order id " . $order['id'] . " is invalid: " . $order['error']);
      throw new AcmeException('orderNotReady', "invalid order: " . $order['error'], 400);
    }
  }

  function save() {
    sqlSaveOrder($this->id, $this->status, $this->expires->getTimestamp(), json_encode($this->identifiers), $this->notBefore->getTimestamp(), $this->notAfter->getTimestamp(), $this->certificate, $this->accountID);
  }

  function __construct($order = null, $accountUrl = null) {
    global $account, $order_id_length_bytes, $jwk, $order_expires_days, $cert_validity_days, $now, $ordersUrl, $authorizationsUrl, $csrUrl;
    //first need to check if an account exists using hash of jwk public key
    if (! is_null($order) && ! is_null($accountUrl)) {
      if (property_exists($order, 'identifiers'))
        $this->identifiers = $order->identifiers;
      if (property_exists($order, 'notBefore'))
        $this->notBefore = $order->notBefore;
      else $this->notBefore = $now;
      if (property_exists($order, 'notAfter'))
        $this->notAfter = $order->notAfter;
      else {
        $i = DateInterval::createFromDateString("$cert_validity_days days");
        $this->notAfter = $now->add($i);    
      }
      $validity = $this->notBefore->diff($this->notAfter);
      if ($validity->format('%a') > $cert_validity_days) {
        errorLog("Order::__construct() error: validity interval exceeds $cert_validity_days days");
        throw new AcmeException('rejectedIdentifier', "validity interval exceeds $cert_validity_days days", 400);
      }
      //$accountUrl = explode('/', $accountUrl);
      //$this->accountID = array_pop($accountUrl);
      $this->accountID = $account->id;
      $id = null;
      do {
        $id = gmp_random_bits($order_id_length_bytes * 8);
        $id = gmp_strval($id, 10);
      } while(sqlGetOrder($id));
      $this->id = $id;
      $this->status = 0; //pending
      $i = DateInterval::createFromDateString("$order_expires_days days");
      $this->expires = $now->add($i);
      $auths = array();
      foreach($this->identifiers as $identifier) {
        if (property_exists($identifier, 'type') && $identifier->type == "dns") {
          if (property_exists($identifier, 'value')) {
            $this->checkQuotas($identifier->value);
            //create new Authorization
            $this->authorizations = array();
            $auth = new Authorization($identifier, "$accountUrl$ordersUrl$id");
            $auths[] = $auth;
            $this->authorizations[] = "$accountUrl$ordersUrl$id$authorizationsUrl" . $auth->id;
          }
        }
      }
      $this->finalize = "$accountUrl$ordersUrl$id$csrUrl";
      $this->certificate = null;
      $this->save();
      foreach($auths as $auth)
        $auth->save();
    }
  }
}
