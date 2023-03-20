<?php
require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'pki_header.php';
require_once 'sql.php';

/*
GenMsgContent ::= SEQUENCE OF InfoTypeAndValue

generalInfo     [8] SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue     OPTIONAL

InfoTypeAndValue ::= SEQUENCE {
    infoType               OBJECT IDENTIFIER,
    infoValue              ANY DEFINED BY infoType  OPTIONAL
}

-- extension ImplicitConfirm
implicitConfirm OBJECT IDENTIFIER ::= {id-it 13}
ImplicitConfirmValue ::= NULL

-- extension ConfirmWaitTime
confirmWaitTime OBJECT IDENTIFIER ::= {id-it 14}
ConfirmWaitTimeValue ::= GeneralizedTime

     -- where {id-it} = {id-pkix 4} = {1 3 6 1 5 5 7 4}
*/

class InfoTypeAndValue {
  public $infoType;
  public $infoValue;
  public $infoValueType;

  function encode() {
      $encoded = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->infoType);
      switch($this->infoType) {
        case '1.3.6.1.5.5.7.4.1': //CA Protocol Encryption Certificate (Req: <absent>, Rep: Certificate)
          if (! is_null($this->infoValue))          
            $encoded .= $this->infoValue->encode();
        break;
        case '1.3.6.1.5.5.7.4.2': //Signing Key Pair Types (Req: <absent>, Rep: SEQUENCE SIZE (1..MAX) OF AlgorithmIdentifier)
          if (! is_null($this->infoValue)) {
            $enc = '';
            foreach($this->infoValue as $val)
              $enc .= $val->encode();
            $encoded .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $enc);
          }
        break;
        case '1.3.6.1.5.5.7.4.3': //Encryption/Key Agreement Key Pair Types (Req: <absent>, Rep: SEQUENCE SIZE (1..MAX) OF AlgorithmIdentifier)
          if (! is_null($this->infoValue)) {
            $enc = '';
            foreach($this->infoValue as $val)
              $enc .= $val->encode();
            $encoded .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $enc);
          }
        break;
        case '1.3.6.1.5.5.7.4.4': //Preferred Symmetric Algorithm (Req: <absent>, Rep: AlgorithmIdentifier)
          if (! is_null($this->infoValue))
            $encoded .= $this->infoValue->encode();
        break;
        case '1.3.6.1.5.5.7.4.5': //Updated CA Key Pair (Rep: CAKeyUpdAnnContent)
          if (! is_null($this->infoValue))          
            $encoded .= $this->infoValue->encode();
        break;
        case '1.3.6.1.5.5.7.4.6': //CRL (Req: < absent >, Rep: CertificateList)
          if (! is_null($this->infoValue))          
            $encoded .= $this->infoValue->encode();
        break;
        case '1.3.6.1.5.5.7.4.7': //Rep: Unsupported Object Identifiers (SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER)
          if (! is_null($this->infoValue)) {
            $oid = '';
            foreach($this->infoValue as $val)
              $oid .= asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->infoValue);
            $encoded .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $oid);
          }
        break;
        case '1.3.6.1.5.5.7.4.10': //Req: Algorithm OID, for example, for DH/DSA or eliptic curves
          if (! is_null($this->infoValue))          
            $encoded .= asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->infoValue);
        break;
        case '1.3.6.1.5.5.7.4.11': //Rep: Key Pair Parameters, for example, for DH/DSA or eliptic curves (AlgorithmIdentifier | < absent > - meaning not supported)
          if (! is_null($this->infoValue))
            $this->infoValue->encode();
        break;
        case '1.3.6.1.5.5.7.4.12': //Revocation Passphrase (Req: EncryptedValue, Rep: < absent >)
          if (! is_null($this->infoValue))
            $encoded .= $this->infoValue->encode();
        break;
        case '1.3.6.1.5.5.7.4.13': //known extension ImplicitConfirm used by EE to inform CA
          $encoded .= asn1encode($class = 0, $constructed = false, $type = NULL_VALUE, $value = '');
        break;
        case '1.3.6.1.5.5.7.4.14': //known extension ConfirmWaitTime used by CA to inform EE
          if (! is_null($this->infoValue))          
            $encoded .= asn1encode($class = 0, $constructed = false, $type = GENERALIZED_TIME, $value = $this->infoValue);
        break;
        case '1.3.6.1.5.5.7.4.15': //Original PKIMessage
          if (! is_null($this->infoValue))          
            $encoded .= $this->infoValue->encode();
        break;
        case '1.3.6.1.5.5.7.4.16': //Supported Language Tags (Req: SEQUENCE SIZE (1..MAX) OF UTF8String, Rep: SEQUENCE SIZE (1) OF UTF8String)
          if (! is_null($this->infoValue)) {
            $langTag = '';
            foreach($this->infoValue as $val)            
              $langTag .= asn1encode($class = 0, $constructed = false, $type = UTF8_STRING, $value = $val);
            $encoded .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $langTag);
          }
        break;
        default: //other possible extensions
          if (! is_null($this->infoValue))          
            $encoded .= asn1encode($class = 0, $constructed = false, $type = $this->infoValueType, $value = $this->infoValue);
        break;
      }
      return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($infoTypeAndValue) {
    $iter = 0;
    $decoded = asn1decode($infoTypeAndValue);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $infoTypeAndValue = $decoded['value'];
    else
      throw new Exception("InfoTypeAndValue::decode() error: bad message check: expected an ASN.1 SEQUENCE for InfoTypeAndValue, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($infoTypeAndValue) > 2) {
      switch($iter) {
        case 0:
          $decoded = asn1decode($infoTypeAndValue);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER) {
            $this->infoType = $decoded['value'];
          } else
            throw new Exception("InfoTypeAndValue::decode() error: bad message check: expected an ASN.1 OBJECT_IDENTIFIER type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 1:
          switch($this->infoType) {
            case '1.3.6.1.5.5.7.4.1': //CA Protocol Encryption Certificate (Req: <absent>, Rep: Certificate)
            break;
            case '1.3.6.1.5.5.7.4.2': //Signing Key Pair Types (Req: <absent>, Rep: SEQUENCE SIZE (1..MAX) OF AlgorithmIdentifier)
            break;
            case '1.3.6.1.5.5.7.4.3': //Encryption/Key Agreement Key Pair Types (Req: <absent>, Rep: SEQUENCE SIZE (1..MAX) OF AlgorithmIdentifier)
            break;
            case '1.3.6.1.5.5.7.4.4': //Preferred Symmetric Algorithm (Req: <absent>, Rep: AlgorithmIdentifier)
            break;
            case '1.3.6.1.5.5.7.4.5': //Updated CA Key Pair (Rep: CAKeyUpdAnnContent)
            break;
            case '1.3.6.1.5.5.7.4.6': //CRL (Req: < absent >, Rep: CertificateList)
            break;
            case '1.3.6.1.5.5.7.4.7': //Rep: Unsupported Object Identifiers (SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER)
            break;
            case '1.3.6.1.5.5.7.4.10': //Req: Algorithm OID, for example, for DH/DSA or eliptic curves
              $decoded = asn1decode($infoTypeAndValue);
              if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER) {
                $this->infoValue = $decoded['value'];
              } else
                throw new Exception("InfoTypeAndValue::decode() error: bad message check: expected an ASN.1 OBJECT_IDENTIFIER type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
              $next = $decoded['length'] + $decoded['hl'];
            break;
            case '1.3.6.1.5.5.7.4.11': //Rep: Key Pair Parameters, for example, for DH/DSA or eliptic curves (AlgorithmIdentifier | < absent > - meaning not supported)
            break;
            case '1.3.6.1.5.5.7.4.12': //Revocation Passphrase (Req: EncryptedValue, Rep: < absent >)
              //unsupported
            break;
            case '1.3.6.1.5.5.7.4.13': //known extension ImplicitConfirm used by EE to inform CA
            break;
            case '1.3.6.1.5.5.7.4.14': //known extension ConfirmWaitTime used by CA to inform EE
            break;
            case '1.3.6.1.5.5.7.4.15': //Original PKIMessage
            break;
            case '1.3.6.1.5.5.7.4.16': //Supported Language Tags (Req: SEQUENCE SIZE (1..MAX) OF UTF8String, Rep: SEQUENCE SIZE (1) OF UTF8String)
              $this->infoValue = new PKIFreeText();
              $next = $this->infoValue->decode($infoTypeAndValue);
            break;
            default: //other possible extensions
            break;
          }
        break;
        default:
          throw new Exception("InfoTypeAndValue::decode() error: bad message check: string is too long", BAD_MESSAGE_CHECK);
      }
      $infoTypeAndValue= substr($infoTypeAndValue, $next);
      $iter++;
    }
    return $offset;
  }
  
  function __construct($info = null) {
    $this->infoValue = null;
    $this->infoValueType = null;
    if (! is_null($info)) {
      if (is_string($info))
        $this->infoType = $info;
      else
        throw new Exception("InfoTypeAndValue::__construct() error: an argument is not a string", SYSTEM_FAILURE);
    }
  }
}

class GenMsgContent {
  public $genMsgs;

  function set() {
    global $now, $request, $supported_signing_algs, $supported_encrypting_algs, $preferred_symmetric_alg, $ca_protocol_enc_cert, $crl_der_file, $confirm_wait_time_sec, $supported_language_tag;
    if (count($request->body->content->genMsgs) == 0) {
      $genMsgTypes = ['1.3.6.1.5.5.7.4.1', '1.3.6.1.5.5.7.4.2', '1.3.6.1.5.5.7.4.3', '1.3.6.1.5.5.7.4.4', '1.3.6.1.5.5.7.4.6'];
      foreach($genMsgTypes as $type)
        $request->body->content->genMsgs[] = new InfoTypeAndValue($type);
    }
    $msgNumber = 0;
    foreach($request->body->content->genMsgs as $msg) {
      $this->genMsgs[$msgNumber] = new InfoTypeAndValue($msg->infoType);
      switch($msg->infoType) {
        case '1.3.6.1.5.5.7.4.1': //CA Protocol Encryption Certificate (Req: <absent>, Rep: Certificate | < absent >)
          if (! empty($ca_protocol_enc_cert))
            $this->genMsgs[$msgNumber]->infoValue = new Certificate($ca_protocol_enc_cert);
        break;
        case '1.3.6.1.5.5.7.4.2': //Signing Key Pair Types (Req: <absent>, Rep: SEQUENCE SIZE (1..MAX) OF AlgorithmIdentifier)
          $this->genMsgs[$msgNumber]->infoValue = array();
          foreach($supported_signing_algs as $alg)
            $this->genMsgs[$msgNumber]->infoValue[] = new AlgorithmIdentifier($alg);
        break;
        case '1.3.6.1.5.5.7.4.3': //Encryption/Key Agreement Key Pair Types (Req: <absent>, Rep: SEQUENCE SIZE (1..MAX) OF AlgorithmIdentifier)
          $this->genMsgs[$msgNumber]->infoValue = array();
          foreach($supported_encrypting_algs as $alg)
            $this->genMsgs[$msgNumber]->infoValue[] = new AlgorithmIdentifier($alg);
        break;
        case '1.3.6.1.5.5.7.4.4': //Preferred Symmetric Algorithm (Req: <absent>, Rep: AlgorithmIdentifier)
            $this->genMsgs[$msgNumber]->infoValue = new AlgorithmIdentifier($preferred_symmetric_alg);
        break;
        case '1.3.6.1.5.5.7.4.5': //Updated CA Key Pair (Rep: CAKeyUpdAnnContent)
        break;
        case '1.3.6.1.5.5.7.4.6': //CRL (Req: < absent >, Rep: CertificateList)
          $this->genMsgs[$msgNumber]->infoValue = new CRL();
        break;
        case '1.3.6.1.5.5.7.4.7': //Rep: Unsupported Object Identifiers (SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER)
          $this->genMsgs[$msgNumber]->infoValue = array();
          foreach($supported_encrypting_algs as $alg)
            $this->genMsgs[$msgNumber]->infoValue[] = new AlgorithmIdentifier($alg);
        break;
        case '1.3.6.1.5.5.7.4.10': //Req: Algorithm OID, for example, for DH/DSA or eliptic curves
        break;
        case '1.3.6.1.5.5.7.4.11': //Rep: Key Pair Parameters, for example, for DH/DSA or eliptic curves (AlgorithmIdentifier | < absent > - meaning not supported)
        break;
        case '1.3.6.1.5.5.7.4.12': //Revocation Passphrase (Req: EncryptedValue, Rep: < absent >)
        break;
        case '1.3.6.1.5.5.7.4.13': //known extension ImplicitConfirm used by EE to inform CA
        break;
        case '1.3.6.1.5.5.7.4.14': //known extension ConfirmWaitTime used by CA to inform EE
          $confirmWaitTimeInterval = DateInverval::createFromDateString("$confirm_wait_time_sec seconds");
          $expTime = date_add($now, $confirmWaitTimeInterval);
          $this->genMsgs[$msgNumber]->infoValue = $expTime->format("YmdHis") . 'Z';
        break;
        case '1.3.6.1.5.5.7.4.15': //Original PKIMessage
        break;
        case '1.3.6.1.5.5.7.4.16': //Supported Language Tags (Req: SEQUENCE SIZE (1..MAX) OF UTF8String, Rep: SEQUENCE SIZE (1) OF UTF8String)
          if (! empty($supported_language_tag)) {
            $this->genMsgs[$msgNumber]->infoValue = array();
            $this->genMsgs[$msgNumber]->infoValue[] = $supported_language_tag;
          }
        break;
        default: //other possible extensions
        break;
      }
      $msgNumber++;
    }
  }

  function encode() {
    $encoded = '';
    foreach($this->genMsgs as $msg) {
      $encoded .= $msg->encode();
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($genMsgs) {
    $decoded = asn1decode($genMsgs);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $genMsgs = $decoded['value'];
    else
      throw new Exception("GenMsgContent::decode() error: bad message check: expected an ASN.1 SEQUENCE for GenMsgContent, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($genMsgs) > 2) {
      $genMsg = new InfoTypeAndValue();
      $next = $genMsg->decode($genMsgs);
      $this->genMsgs[] = $genMsg;
      $genMsgs = substr($genMsgs, $next);
    }
    return $offset;
  }

  function __construct() {
    $this->genMsgs = array();
  }
}

class GeneralInfo {
  public $generalInfo;

  function set($type, $value, $valueType) {
    $generalInfo = new InfoTypeAndValue();
    $generalInfo->infoType = str2oid($type);
    $generalInfo->infoValue = $value;
    $generalInfo->infoValueType = $valueType;
    $this->generalInfo[] = $generalInfo;
  }

  function encode() {
    $encoded = '';
    foreach($this->generalInfo as $info) {
      $encoded .= $info->encode();
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($genInfo) {
    $decoded = asn1decode($genInfo);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $genInfo = $decoded['value'];
    else
      throw new Exception("GeneralInfo::decode() error: bad message check: expected an ASN.1 SEQUENCE for GeneralInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($genInfo) > 2) {
      $gInfo = new InfoTypeAndValue();
      $next = $gInfo->decode($genInfo);
      $this->generalInfo[] = $gInfo;
      $genInfo = substr($genInfo, $decoded['length'] + $decoded['hl']);
    }
    return $offset;
  }

  function __construct() {
    $this->generalInfo = array();
  }
}

?>