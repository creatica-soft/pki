<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'general_name.php';
require_once 'algorithm_identifier.php';
require_once 'genm.php';
require_once 'globals.php';
require_once 'pki_status_info.php';
require_once 'helper_functions.php';
require_once 'sql.php';

/*
PKIHeader ::= SEQUENCE {
         pvno                INTEGER     { cmp1999(1), cmp2000(2) },
         sender              GeneralName,
         recipient           GeneralName,
         messageTime     [0] GeneralizedTime         OPTIONAL,
         protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
         senderKID       [2] KeyIdentifier           OPTIONAL,
         recipKID        [3] KeyIdentifier           OPTIONAL,
         transactionID   [4] OCTET STRING            OPTIONAL,
         senderNonce     [5] OCTET STRING            OPTIONAL,
         recipNonce      [6] OCTET STRING            OPTIONAL,
         freeText        [7] PKIFreeText             OPTIONAL,
         generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                             InfoTypeAndValue     OPTIONAL
     }

KeyIdentifier ::= OCTET STRING

PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
*/

class PKIFreeText {
  public $freeText;

  function encode() {
    if (! is_null($this->freeText))
      $encoded = '';
      foreach($this->freeText as $text)
        $encoded .= asn1encode($class = 0, $constructed = false, $type = UTF8_STRING, $value = $text); 
      return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($freeText) {
    $decoded = asn1decode($freeText);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $freeText = $decoded['value'];
    else
      throw new Exception("PKIFreeText::decode() error: bad message check: expected an ASN.1 SEQUENCE for freeText, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($freeText) > 2) {
      $decoded = asn1decode($freeText);
      if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == UTF8_STRING) {
        $this->freeText[] = $decoded['value'];
        $freeText = substr($freeText, $decoded['length'] + $decoded['hl']);
      } else
        throw new Exception("PKIFreeText::decode() error: bad message check: expected an ASN.1 UTF8_STRING, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    }
    return $offset;
  }

  function __construct($freeText = null) {
    if (! is_null($freeText)) {
      if (is_array($freeText))
        $this->freeText = $freeText;
      elseif (is_string($freeText)) {
       $this->freeText = array();
       $this->freeText[] = $freeText;
      } else
        throw new Exception('PKIFreeText::_construct() error: an argument is neither a string nor an array', SYSTEM_FAILURE);
    } else
      $this->freeText = array();
  }
}

class PKIHeader {
  public $pvno;
  public $sender;
  public $recipient;
  public $messageTime;
  public $protectionAlg;
  public $senderKID;
  public $recipientKID;
  public $transactionID;
  public $senderNonce;
  public $recipientNonce;
  public $freeText;
  public $generalInfo;

  function checkVersion() {
    global $pvno;
    if ($this->pvno != $pvno)
      throw new Exception('Unsupported CMP protocol version ' . $this->pvno . '. Server version is ' . $pvno, UNSUPPORTED_VERSION);
  }

  function checkSender() {
    $error = '';
    if (is_null($this->sender))
      $error = 'sender is null';
    elseif (! is_object($this->sender))
      $error = 'sender is not an object';
    elseif (! $this->sender instanceof GeneralName)
      $error = 'sender is not an instance of GeneralName class';
    elseif (! $this->sender->getCN())
      $error = 'sender does not have a CN attribute';
    //elseif (! $this->sender->getRole())
      //$error = 'sender does not have a role attribute';
    if (! empty($error))
      throw new Exception($error, BAD_REQUEST);
  }

  function checkRecipient() {
    global $signing_ca_path;
    $error = '';
    $errorType = BAD_REQUEST;
    if (is_null($this->recipient))
      $error = 'recipient is null';
    elseif (! is_object($this->recipient))
      $error = 'recipient is not an object';
    elseif (! $this->recipient instanceof GeneralName)
      $error = 'recipient is not an instance of GeneralName class';
    elseif (! $this->recipient->getCN())
      $error = 'recipient does not have a CN attribute';
    else {
      $dn = getCertSubjectName($signing_ca_path);
      $recipient = $this->recipient->__toString();
      if (strcasecmp($dn, $recipient) != 0) {
        $error = "Wrong authority: the recipient GeneralName ($recipient) is different from the CA GeneralName ($dn)";
        $errorType = WRONG_AUTHORITY;
      }
    }
    if (! empty($error))
      throw new Exception($error, $errorType);
  }

  function checkMessageTime() {
    global $max_time_skew_sec, $now;
    $errorType = BAD_TIME;
    $error = '';

    $msgTime = $this->messageTime2DateTime();
    if ($msgTime) {
      if (abs($msgTime->getTimestamp() - $now->getTimestamp()) > $max_time_skew_sec)
        $error = 'Time skew is too big: server time: ' . $now->format("YmdHis") . 'Z, client time: ' . $this->messageTime;
    } else
      $error = 'messageTime is null';
    if (! empty($error))
      throw new Exception($error, $errorType);
  }

  function checkProtectionAlg() {
    global $supported_signing_algs;
    if (is_null($this->protectionAlg))
      throw new Exception("PKI message protection is required. Please sign the message with your client certificate or a shared secret using HMAC.", BAD_REQUEST);
    if (! in_array(oid2str($this->protectionAlg->algorithm), $supported_signing_algs)) {
      $algs = '';
      $size = count($supported_signing_algs) - 1;
      for ($i = 0; $i < $size; $i++) {
        $algs .= $supported_signing_algs[$i] . ', ';
      }
      $algs .= $supported_signing_algs[$size];
      throw new Exception("Unsupported signature algorithm " . $this->protectionAlg->algorithm . ". Please use one of $algs", BAD_ALG);
    }
  }  

  function checkTransactionID() {
    global $request, $implicitConfirm, $confirm_wait_time_sec, $now;

    if (is_null($this->transactionID)) {
      if ($request->body->type != CERTCONF) return;
      else
        throw new Exception('Request header is missing the TransactionID', BAD_REQUEST);
    }
    //check if transactionID is in use
    $certReqIds = sqlGetCertReqIds($this->transactionID);
    if ($certReqIds) { //in-use but $confirm_wait_time_sec may have expired for cert requests
      $ts = date_create('@' . $certReqIds[0]['timestamp']);
      $confirmWaitTimeInterval = DateInterval::createFromDateString("$confirm_wait_time_sec seconds");
      $expTime = date_add($ts, $confirmWaitTimeInterval);
      $diff = date_diff($now, $expTime);
      if ($diff->format('%R')  == '-') { //confirm_wait_time expired, revoke requested cert if any
        foreach($certReqIds as $id)
          sqlRevokeCert($id['serial'], $revocationDate = $now->getTimestamp(), $revocationReason = 6);
        sqlDeleteCertReqIds($this->transactionID);
      } else { //confirm_wait_time has not expired yet, if it is not CertConfirm message, then error out with "transaction in use"
        if ($request->body->type != CERTCONF)
          throw new Exception('TransactionID is in use: ' . (string)$this->transactionID, TRANSACTION_ID_IN_USE);
      }  
    }
  }

  function checkSenderKID() {

  }

  function checkSenderNonce() {

  }

  function checkRecipientNonce() {
    global $request, $metadata;
    if ($request->body->type == CERTCONF) {
      $certReqIds = sqlGetCertReqIds($this->transactionID);
      if (! $certReqIds)
        throw new Exception("transactionID " . $this->transactionID . " is not found", BAD_RECIPIENT_NONCE);
      if (strcmp($certReqIds[0]['nonce'], $this->recipientNonce) != 0)
        throw new Exception("Bad recipient nonce " . $this->recipientNonce, BAD_RECIPIENT_NONCE);
    }
  }

  function checkGeneralInfo() {
    global $implicitConfirm;
    //check if implicitConfirm is indicated, which means that the CMP client won't send certConf message
    if (is_null($this->generalInfo) || ! is_object($this->generalInfo) || ! $this->generalInfo instanceof GeneralInfo) 
      return false;
    foreach($this->generalInfo->generalInfo as $genInfo) {
      if (strcmp($genInfo->infoType, '1.3.6.1.5.5.7.4.13') == 0) {
        $implicitConfirm = true;
        break;
      }
    }
  }

  function setSender() {
    global $signing_ca_der_path;

    $cert = new Certificate($signing_ca_der_path);
    $this->sender = new GeneralName($cert->tbsCertificate->subject->__toString());
    //alternative way of setting a sender:
    //$sender = getCertSubjectName($signing_ca_path);
    //$this->sender = new GeneralName($sender);
  }

  function setRecipient() {
    global $sender;
    if (! is_null($sender) && is_object($sender) && $sender instanceof GeneralName)
      $this->recipient = clone $sender;
    else error_log("sender is either null or not an object or not an instance of GeneralName class\n");
  }

  function setMessageTime() {
    $this->messageTime = gmdate("YmdHis") . 'Z'; //YYYYMMDDhhmmssZ
  }

  function setProtectionAlg() {
    global $default_pki_message_protection_alg;
    $this->protectionAlg = new AlgorithmIdentifier($default_pki_message_protection_alg); 
  }

  function setTransactionID() {
    global $requestContentType, $transactionID, $implicitConfirm;
    if (! empty($transactionID)) 
      $this->transactionID = $transactionID;
    else {
      $this->transactionID = bin2hex(openssl_random_pseudo_bytes(16));
      while(sqlGetCertReqIds($this->transactionID))
        $this->transactionID = bin2hex(openssl_random_pseudo_bytes(16));
    }
  }

  function setSenderKID() {
    global $signing_ca_der_path;
    $cert = new Certificate();
    if (! file_exists($signing_ca_der_path))
      throw new Exception("PKIHeader::setSenderKID() error: file $signing_ca_der_path is not found", SYSTEM_FAILURE);
    $cert->decode(file_get_contents($signing_ca_der_path));
    $kid = $cert->tbsCertificate->extensions->getSubjectKeyIdentifier();
    if (! $kid)
      throw new Exception("PKIHeader::setSenderKID() error: getSubjectKeyIdentifier() returned false", SYSTEM_FAILURE);
    $this->senderKID = $kid;
  }    

  function setSenderNonce() {
    $this->senderNonce = bin2hex(openssl_random_pseudo_bytes(16));
  }  

  function setRecipientNonce() {
    global $senderNonce;
    if (! empty($senderNonce))
      $this->recipientNonce = $senderNonce;
    else errorLog("senderNonce is empty\n", 'error');
  }

  function setFreeText($freeText) {
    $this->freeText = $freeText;  
  }

/* From RFC4210:
   If the CA grants the request to the EE, it MUST put the same
   extension in the PKIHeader of the response.  If the EE does not find
   the extension in the response, it MUST send the certificate
   confirmation.
*/

  function setGeneralInfo() {
    global $request, $implicitConfirm, $include_confirm_wait_time, $confirm_wait_time_sec, $now;

    $certReqsTypes = [0, 2, 4, 7, 9, 13];
    if ($implicitConfirm) {
      $this->generalInfo = new GeneralInfo();
      $this->generalInfo->set('implicitConfirm', '', NULL_VALUE);
    } else {
      if ($include_confirm_wait_time && in_array($request?->body?->type, $certReqsTypes)) {
        $this->generalInfo = new GeneralInfo();
        $confirmWaitTimeInterval = DateInterval::createFromDateString("$confirm_wait_time_sec seconds");
        $expTime = date_add($now, $confirmWaitTimeInterval);
        $this->generalInfo->set('confirmWaitTime', $expTime->format("YmdHis") . 'Z', GENERALIZED_TIME);
      } else $this->generalInfo = null;
    } 
  }
 
  function messageTime2DateTime() {
    if (is_null($this->messageTime)) return false;
    $str = rtrim($this->messageTime, 'Z');
    $str = explode('.', $str)[0];
    list($century, $year, $month, $day, $hour, $min, $sec) = str_split($str, 2);
    return date_create("$century$year$month$day" . 'T' . "$hour$min$sec", new DateTimeZone("+0000"));
  }

  function encode() {
    $header = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->pvno);
    $header .= $this->sender->encode();
    if (! is_null($this->recipient))
      $header .= $this->recipient->encode();
    else $header .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = '');
    if (! is_null($this->messageTime)) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = GENERALIZED_TIME, $value = $this->messageTime);
      $header .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $encoded);
    }
    if (! is_null($this->protectionAlg)) {
      $encoded = $this->protectionAlg->encode();
      $header .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $encoded);
    }
    if (! is_null($this->senderKID)) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->senderKID);
      $header .= asn1encode($class = 2, $constructed = true, $type = 2, $value = $encoded);
    }
    if (! is_null($this->recipientKID)) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->recipientKID);
      $header .= asn1encode($class = 2, $constructed = true, $type = 3, $value = $encoded);
    }
    if (! is_null($this->transactionID)) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->transactionID);
      $header .= asn1encode($class = 2, $constructed = true, $type = 4, $value = $encoded);
    }
    if (! is_null($this->senderNonce)) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->senderNonce);
      $header .= asn1encode($class = 2, $constructed = true, $type = 5, $value = $encoded);
    }
    if (! is_null($this->recipientNonce)) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->recipientNonce);
      $header .= asn1encode($class = 2, $constructed = true, $type = 6, $value = $encoded);
    }
    if (! is_null($this->freeText)) {
      $encoded = $this->freeText->encode();
      $header .= asn1encode($class = 2, $constructed = true, $type = 7, $value = $encoded);
    }
    if (! is_null($this->generalInfo)) {
      $encoded = $this->generalInfo->encode();
      $header .= asn1encode($class = 2, $constructed = true, $type = 8, $value = $encoded); 
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $header);
  }

  function decode($pkiHeader) {
    global $sender, $senderNonce, $transactionID;
    $iter = 0;
    $decoded = asn1decode($pkiHeader);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $pkiHeader = $decoded['value'];
    else
      throw new Exception("PKIHeader::decode() error: bad message check: expected an ASN.1 SEQUENCE for PKIHeader, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($pkiHeader) > 2) {
      switch($iter) {
        case 0: //pvno
          $decoded = asn1decode($pkiHeader);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->pvno = $decoded['value'];
          }
          else
            throw new Exception("PKIHeader::decode() error: bad message check: expected an ASN.1 INTEGER type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 1: //sender
            $this->sender = new GeneralName();
            $next = $this->sender->decode($pkiHeader);
            $this->sender->name = $this->sender->__toString();
            $sender = clone $this->sender;
        break;
        case 2: //recipient
            $this->recipient = new GeneralName();
            $next = $this->recipient->decode($pkiHeader);
            $this->recipient->name = $this->recipient->__toString();
        break;
        default: 
          $decoded = asn1decode($pkiHeader);
          $next = $decoded['length'] + $decoded['hl'];
          if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed']) {
            switch($decoded['type']) {
              case 0: //messageTime
                $decoded2 = asn1decode($decoded['value']);
                if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && $decoded2['type'] == GENERALIZED_TIME)
                  $this->messageTime = $decoded2['value'];
                else
                  throw new Exception("PKIHeader::decode() error: bad message check: expected an ASN.1 GENERALIZED_TIME type, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type']), BAD_MESSAGE_CHECK);
              break;
              case 1: //protectionAlg
                $this->protectionAlg = new AlgorithmIdentifier();
                $this->protectionAlg->decode($decoded['value']);
              break;
              case 2: //senderKID
                $decoded2 = asn1decode($decoded['value']);
                if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && $decoded2['type'] == OCTET_STRING)
                  $this->senderKID = $decoded2['value'];
                else
                  throw new Exception("PKIHeader::decode() error: bad message check: expected an ASN.1 OCTET_STRING type, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type']), BAD_MESSAGE_CHECK);
              break;
              case 3: //recipientKID
                $decoded2 = asn1decode($decoded['value']);
                if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && $decoded2['type'] == OCTET_STRING)
                  $this->recipientKID = $decoded2['value'];
                else
                  throw new Exception("PKIHeader::decode() error: bad message check: expected an ASN.1 OCTET_STRING type, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type']), BAD_MESSAGE_CHECK);
              break;
              case 4: //transactionID
                $decoded2 = asn1decode($decoded['value']);
                if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && $decoded2['type'] == OCTET_STRING) {
                  $this->transactionID = $decoded2['value'];
                  $transactionID = $this->transactionID;
                } else
                  throw new Exception("PKIHeader::decode() error: bad message check: expected an ASN.1 OCTET_STRING type, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type']), BAD_MESSAGE_CHECK);
              break;
              case 5: //senderNonce
                $decoded2 = asn1decode($decoded['value']);
                if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && $decoded2['type'] == OCTET_STRING) {
                  $this->senderNonce = $decoded2['value'];
                  $senderNonce = $this->senderNonce;
                } else
                  throw new Exception("PKIHeader::decode() error: bad message check: expected an ASN.1 OCTET_STRING type, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type']), BAD_MESSAGE_CHECK);
              break;
              case 6: //recipientNone
                $decoded2 = asn1decode($decoded['value']);
                if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && $decoded2['type'] == OCTET_STRING)
                  $this->recipientNonce = $decoded2['value'];
                else
                  throw new Exception("PKIHeader::decode() error: bad message check: expected an ASN.1 OCTET_STRING type, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type']), BAD_MESSAGE_CHECK);
              break;
              case 7: //freeText
                  $this->freeText = new PKIFreeText();
                  $this->freeText->decode($decoded['value']);
              break;
              case 8: //generalInfo
                  $this->generalInfo = new GeneralInfo();
                  $this->generalInfo->decode($decoded['value']);
              break;
              default:
                throw new Exception("PKIHeader::decode() error: bad message check: string is too long", BAD_MESSAGE_CHECK);
            }
          } else
            throw new Exception("PKIHeader::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed type with a value between 0 and 8, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
        break;
      }
      $pkiHeader = substr($pkiHeader, $next);
      $iter++;
    }
    return $offset;
  }

  function __construct() {
    $this->pvno = 2;
    $this->messageTime = null;
    $this->protectionAlg = null;
    $this->senderKID = null;
    $this->recipientKID = null;
    $this->transactionID = null;
    $this->senderNonce = null;
    $this->recipientNonce = null;
    $this->freeText = null;
    $this->generalInfo = null;
  }
}

?>