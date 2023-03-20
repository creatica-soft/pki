<?php

//url for a challenge should look like /acme/accounts/<id>/orders/<id>/authorizations/<id>/challenges/<id>
class Challenge implements JsonSerializable {
  public $id;
  public $type; //required, string "http-01" or "dns-01"
  public $base_url; //required, string - this is where client sends POST-AS-GET empty request when it's ready for challenge validation
  public $status; //required, string "pending" (0), "processing" (1), "valid" (2) or "invalid" (-1); 
                  //when "invalid", it should include error field
  public $token; //required for http-01 and dns-01 challenges, must be at least 128-bit base64url encoded; 
                 // the challenge is placed at /.well-known/acme-challenge/$token for http-01 challenge or
                 // dns TXT record _acme-challenge.<domain>. for dns-01 challenge
  public $validated; //optional, rfc3339 date but required if status is "valid"
  public $error; //optional, json problem object with subproblems field in case of multiple errors; 
                 //when present, status must be "invalid"
  private $authorizationID;
  
  private function challengeStatus2str($status) {
    switch ($status) {
      case 0: return "pending";
      case 1: return "processing";
      case 2: return "valid";
      case -1: return "invalid";
      default: return "unknown";
    }
  }
  
  function jsonSerialize() {
    $challenge = array('status' => $this->challengeStatus2str($this->status));
    $challenge['type'] = $this->type;
    $challenge['url'] = $this->url;
    $challenge['token'] = $this->token;    
    if ($this->status == 2 && ! is_null($this->validated))
      $challenge['validated'] = $this->validated->format(DATE_ATOM);    
    if ($this->status == -1 && ! is_null($this->error))
      $challenge['error'] = $this->error;    
    return $challenge;
  }
  
  function set($challenge) {
    if (is_null($challenge)) {
      errorLog('Challenge::set() error: an argument is null');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    if (! is_array($challenge)) {
      errorLog('Challenge::set() error: an argument is not an array');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $this->id = $challenge['id'];
    $this->type = $challenge['type'];
    $this->url = $challenge['url'];
    $this->status = $challenge['status'];
    $this->token = $challenge['token'];
    $this->error = $challenge['error'];
    if (! is_null($challenge['validated']))
      $this->validated = DateTime::createFromFormat("U", $challenge['validated']);
    else $this->validated = null;
    $this->authorizationID = $challenge['authorization'];
  }

  function save() {
    sqlSaveChallenge($this->id, $this->type, $this->url, $this->status, $this->token, $this->error, $this->validated?->getTimestamp(), $this->authorizationID);
  }

  function __construct($type = null, $authorizationUrl = null) {
    global $challenge_id_length_bytes, $token_length_bytes, $challengesUrl;
    if (! is_null($type) && ! is_null($authorizationUrl)) {
      $id = null;
      do {
        $id = gmp_random_bits($challenge_id_length_bytes * 8);
        $id = gmp_strval($id, 10);
      } while(sqlGetChallenge($id));
      $this->id = $id;
      $this->type = $type;
      $this->url = "$authorizationUrl$challengesUrl$id";
      $this->status = 0; //pending
      $this->token = base64url_encode(gmp_strval(gmp_random_bits($token_length_bytes * 8), 10));
      $authorizationUrl = explode('/', $authorizationUrl);
      $this->authorizationID = array_pop($authorizationUrl);
    }
    $this->validated = null;
    $this->error = null;
  }
}

?>