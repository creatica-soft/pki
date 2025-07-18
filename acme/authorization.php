<?php

class Identifier {
  public $type; //string "dns"
  public $value; //string dns domain name exactly as it will appear in a certificate cn and san
  public $wildcard; //optional, boolean;
                    //for wildcard requests, "value" should omit "*." and include optional "wildcard" = "true" field
}

//uri for an authorization should look like /acme/accounts/<id>/orders/<id>/authorizations/<id>
class Authorization implements JsonSerializable {
  public $id;
  public $identifier; //required, object
  public $status; //required, string, "pending" (0) => "valid" (1) or "invalid" (-1), "deactivated" (-2) by client, "expired" (2), 
                  //or "revoked" (-3) by server
  public $expires; //optional, string; required for "valid" status
  public $challenges; //required, array of Challenge objects
  public $wildcard; //required for wildcard domains and must be absent for non-wildcard
  private $orderID;

  private function authorizationStatus2str($status) {
    switch ($status) {
      case 0: return "pending";
      case 1: return "valid";
      case 2: return "expired";
      case -1: return "invalid";
      case -2: return "deactivated";
      case -3: return "revoked";
      default: return "unknown";
    }
  }

  function jsonSerialize() {
    $authorization = array('status' => $this->authorizationStatus2str($this->status));
    $authorization['identifier'] = $this->identifier;
    if (! is_null($this->expires))
      $authorization['expires'] = $this->expires->format(DATE_ATOM);
    $authorization['challenges'] = $this->challenges;    
    if (! is_null($this->wildcard))
      $authorization['wildcard'] = $this->wildcard;    
    return $authorization;
  }

  function set($authorization) {
    if (is_null($authorization)) {
      errorLog('Authorization::set() error: an argument is null');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    if (! is_array($authorization)) {
      errorLog('Authorization::set() error: an argument is not an array');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $this->id = $authorization['id'];
    $this->identifier = json_decode($authorization['identifier']);
    $this->status = $authorization['status'];
    if (! is_null($authorization['expires']))
      $this->expires = DateTime::createFromFormat('U', $authorization['expires']);
    else $this->expires = null;
    $challenges = sqlGetChallenges($this->id);
    if (! $challenges) {
      errorLog('Authorization::set() error: sqlGetChallenges() return false');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    foreach($challenges as $challenge) {
      $chall = new Challenge();
      $chall->set($challenge);
      $this->challenges[] = $chall;
    }
    $this->wildcard = $authorization['wildcard'] == 1 ? true : false;
    $this->orderID = $authorization['order'];
  }

  function save() {
    sqlSaveAuthorization($this->id, json_encode($this->identifier), $this->status, $this->expires->getTimestamp(), $this->wildcard ? 1 : 0, $this->orderID);
    foreach($this->challenges as $challenge)
      $challenge->save();
  }

  function __construct($identifier = null, $orderUrl = null) {
    global $authorization_id_length_bytes, $order_expires_days, $now, $authorizationsUrl;
    $this->challenges = array();
    if (! is_null($identifier) && ! is_null($orderUrl)) {
      $id = null;
      do {
        $id = gmp_random_bits($authorization_id_length_bytes * 8);
        $id = gmp_strval($id, 10);
      } while(sqlGetAuthorization($id));
      $this->id = $id;
      $this->status = 0; //pending
      $i = DateInterval::createFromDateString("$order_expires_days days");
      $this->expires = $now->add($i);
      $this->challenges[] = new Challenge('http-01', "$orderUrl$authorizationsUrl$id");
      $this->challenges[] = new Challenge('dns-01', "$orderUrl$authorizationsUrl$id");
      if (property_exists ($identifier, 'wildcard') && $identifier->wildcard)
        $this->wildcard = true;
      elseif (property_exists($identifier, 'value') && str_starts_with($identifier->value, '*.')) {
        $this->wildcard = true;
        $identifier->value = str_replace('*.', '', $identifier->value);
        $identifier->wildcard = true;
      } else $this->wildcard = null;
      $this->identifier = $identifier;
      $orderUrl = explode('/', $orderUrl);
      $this->orderID = array_pop($orderUrl);
    }
  }
}
