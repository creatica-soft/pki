<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'algorithm_identifier.php';
require_once 'popo_signing_key.php';
require_once 'cert_req.php';

/*
CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg

CertReqMsg ::= SEQUENCE {
 certReq CertRequest,
 popo ProofOfPossession OPTIONAL,
 -- content depends upon key type
 regInfo SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL
}

ProofOfPossession ::= CHOICE {
 raVerified [0] NULL,
 -- used if the RA has already verified that the requester is in
 -- possession of the private key
 signature [1] POPOSigningKey,
 keyEncipherment [2] POPOPrivKey,
 keyAgreement [3] POPOPrivKey }

POPOSigningKey ::= SEQUENCE {
 poposkInput [0] POPOSigningKeyInput OPTIONAL,
 algorithmIdentifier AlgorithmIdentifier,
 signature BIT STRING }
 -- The signature (using "algorithmIdentifier") is on the
 -- DER-encoded value of poposkInput. NOTE: If the CertReqMsg
 -- certReq CertTemplate contains the subject and publicKey values,
 -- then poposkInput MUST be omitted and the signature MUST be
 -- computed over the DER-encoded value of CertReqMsg certReq. If
 -- the CertReqMsg certReq CertTemplate does not contain both the
 -- public key and subject values (i.e., if it contains only one
 -- of these, or neither), then poposkInput MUST be present and
 -- MUST be signed.

POPOSigningKeyInput ::= SEQUENCE {
 authInfo CHOICE {
 sender [0] GeneralName,
 -- used only if an authenticated identity has been
 -- established for the sender (e.g., a DN from a
 -- previously-issued and currently-valid certificate)
 publicKeyMAC PKMACValue },
 -- used if no authenticated GeneralName currently exists for
 -- the sender; publicKeyMAC contains a password-based MAC
 -- on the DER-encoded value of publicKey
 publicKey SubjectPublicKeyInfo } -- from CertTemplate

PKMACValue ::= SEQUENCE {
algId AlgorithmIdentifier,
-- algorithm value shall be PasswordBasedMac {1 2 840 113533 7 66 13}
-- parameter value is PBMParameter
value BIT STRING }

PBMParameter ::= SEQUENCE {
 salt OCTET STRING,
 owf AlgorithmIdentifier,
 -- AlgId for a One-Way Function (SHA-1 recommended)
 iterationCount INTEGER,
 -- number of times the OWF is applied
 mac AlgorithmIdentifier
 -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
} -- or HMAC [HMAC, RFC2202])

POPOPrivKey ::= CHOICE {
 thisMessage [0] BIT STRING, -- Deprecated
 -- possession is proven in this message (which contains the private
 -- key itself (encrypted for the CA))
 subsequentMessage [1] SubsequentMessage,
 -- possession will be proven in a subsequent message
 dhMAC [2] BIT STRING, -- Deprecated
 agreeMAC [3] PKMACValue,
 encryptedKey [4] EnvelopedData }
 -- for keyAgreement (only), possession is proven in this message
 -- (which contains a MAC (over the DER-encoded value of the
 -- certReq parameter in CertReqMsg, which MUST include both subject
 -- and publicKey) based on a key derived from the end entity's
 -- private DH key and the CA's public DH key);

id-regInfo-utf8Pairs    OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.2.1 }
id-regInfo-certReq       OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.2.2 }
*/

class CertReqMessages {
  public $certReqMessages;

  function encode() {
    $encoded = '';
    foreach($this->certReqMessages as $msg)
      $encoded .= $msg->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($certReqMessages) {
    $decoded = asn1decode($certReqMessages);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $certReqMessages = $decoded['value'];
    else
      throw new Exception("CertReqMessages::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertReqMessages, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($certReqMessages) > 2) {
      $certReqMsg = new CertReqMessage();
      $next = $certReqMsg->decode($certReqMessages);
      $certReqMsg->validate();
      $this->certReqMessages[] = $certReqMsg;
      $certReqMessages = substr($certReqMessages, $next);
    }
    return $offset;
  }

  function __construct() {
    $this->certReqMessages = array();
  }
}

class CertReqMessage {
  public $certReq;
  public $popo;
  public $popoType;
  public $regInfo;

  function encode() {
    $certReqMsg = $this->certReq->encode();

    if (! is_null($this->popo)) {
      if ($this->popoType == 0)
        $popo = asn1encode($class = 0, $constructed = false, $type = NULL_VALUE, $value = '');
      elseif ($this->popoType > 0 && $this->popoType < 4)
        $popo = $this->popo->encode();
      else
        throw new Exception("unknown Proof-Of-Possession (POP): $option", SYSTEM_FAILURE);
      $popo = asn1encode($class = 2, $constructed = true, $type = $this->popoType, $value = $popo);      
      $certReqMsg .= $popo;
    }
    if (! is_null($this->regInfo)) {
      $regInfo = '';
      foreach($this->regInfo as $val)
        $regInfo .= $val->encode();
      $certReqMsg .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $regInfo);
    }
    $certReqMsg = asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $certReqMsg);
    
    return $certReqMsg;
  }

  function decode($req) {
    $iter = 0;
    $decoded = asn1decode($req);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $req = $decoded['value'];
    else
      throw new Exception("CertReqMessage::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertReqMessage, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($req) > 2) {
      switch($iter) {
        case 0: //certReq
          $this->certReq = new CertReq();
          $next = $this->certReq->decode($req);
        break;
        default: //popo and regInfo
          $decoded = asn1decode($req);
          $next = $decoded['length'] + $decoded['hl'];
          if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed'] && $decoded['type'] >= 0 && $decoded['type'] <= 3) {
            switch($decoded['type']) {
              case 0:
                throw new Exception("Proof-Of-Possession (POP) RA verified (" . $decoded['type'] . ") is not supported", BAD_REQUEST);
              break;
              case 1:
                $this->popo = new POPOSigningKey();
                $this->popo->decode($decoded['value'], $implicit = true);
                $this->popoType = 1;
              break;
              case 2:
                throw new Exception("Proof-Of-Possession (POP) using a private key (" . $decoded['type'] . ") is not supported", BAD_REQUEST);
              break;
              case 3:
                throw new Exception("Proof-Of-Possession (POP) using a private key (" . $decoded['type'] . ") is not supported", BAD_REQUEST);
              break;
              default:
                throw new Exception("unknown Proof-Of-Possession (POP): " . $this->popoType, SYSTEM_FAILURE);
            }
          } elseif ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE) { //regInfo
            $this->regInfo = new AtributeTypeAndValues();
            $this->regInfo->decode($req);
          } else
            throw new Exception("CertReqMessage::decode() error: bad message check: expected an ASN.1 SEQUENCE or CONTEXT_SPECIFIC constructed class and value between 0 and 3, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
      }
      $req = substr($req, $next);
      $iter++;
    }
    return $offset;
  }

  function validate() {
    if (! is_null($this->popo)) {
      switch($this->popoType) {
        case 0: //raVerified
        break;
        case 1: //signature, pubkey
          $res = $this->popo->validate($this->certReq);
        break;
        case 2: //keyEncipherment, privKey
          throw new Exception("keyEncipherment privKey is not supported for Proof-Of-Possession (POP)", SYSTEM_FAILURE);
        break;
        case 3: //keyAgreement, privKey
          throw new Exception("keyAgreement privKey is not supported for Proof-Of-Possession (POP)", SYSTEM_FAILURE);
        break;
        default:
          throw new Exception("unknown Proof-Of-Possession (POP): $option", SYSTEM_FAILURE);
      }
      if (! $res)
        throw new Exception("Proof of possession of a private key (POP) is invalid", BAD_POP);
    } else
        throw new Exception("Proof of possession of a private key (POP) is absent", BAD_REQUEST);
  }  

  function __construct() {
    $this->popo = null;
    $this->regInfo = null;
  }
}
