<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'general_name.php';
require_once 'algorithm_identifier.php';
require_once 'subject_pubkey_info.php';
require_once 'pki_status_info.php';

/*
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
-- The value is computed over the DER-encoded public key of the certificate subject

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
 encryptedKey [4] EnvelopedData } -- see rfc3852 for details
 -- for keyAgreement (only), possession is proven in this message
 -- (which contains a MAC (over the DER-encoded value of the
 -- certReq parameter in CertReqMsg, which MUST include both subject
 -- and publicKey) based on a key derived from the end entity's
 -- private DH key and the CA's public DH key);

SubsequentMessage ::= INTEGER {
 encrCert (0),
 -- requests that resulting certificate be encrypted for the
 -- end entity (following which, POP will be proven in a
 -- confirmation message)
 challengeResp (1) }
 -- requests that CA engage in challenge-response exchange with
 -- end entity in order to prove private key possession
*/

class POPOSigningKey {
  public $algorithmId;
  public $signature;

  // $certReq is CertReq object
  function validate($certReq) {
    while (openssl_error_string());
    if (is_null($certReq->certTemplate->publicKey))
      throw new Exception("POP cannot be verified: public key is absent in certificate template " . print_r($certReq, true), BAD_POP);
    if (is_null($certReq->certTemplate->subject))
      throw new Exception("POP cannot be verified: subject is missing in a certificate template " . print_r($certReq, true), BAD_POP);
    $pubkey = der2pem(asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $certReq->certTemplate->publicKey->encode($implicit = true)), 'PUBLIC KEY');
    $cert_req = $certReq->encode();
    $digestAlg = OPENSSL_ALGO_SHA1; //default for openssl_verify()
    switch ($this->algorithmId->algorithm) {
      case '1.2.840.113549.1.1.11': //sha256WithRSAEncryption
      case '2.16.840.1.101.3.4.3.2': //dsa-with-sha256
        $digestAlg = OPENSSL_ALGO_SHA256;
      break;
    }
    $res = openssl_verify($cert_req, hex2bin($this->signature), $pubkey, $digestAlg);

    switch($res) {
      case 0: return false;
      case 1: return true;
      default:
        $error = "POPOSigningKey::validate() openssl verify error: ";
        while ($err = openssl_error_string()) $error .= $err;
        throw new Exception($error, SYSTEM_FAILURE);
    }
  }

  function encode($implicit = true) {
    $encoded = '';
    $encoded .= $this->algorithmId->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = '00' . $this->signature);
    if ($implicit) return $encoded;
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($popo, $implicit = false) {
    $iter = 0;
    if (! $implicit) {
      $decoded = asn1decode($popo);
      if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
        $popo = $decoded['value'];
      else
        throw new Exception("POPOSigningKey::decode() error: bad message check: expected an ASN.1 SEQUENCE for POPOSigningKey, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
      $offset = $decoded['length'] + $decoded['hl'];
    } else $offset = strlen($popo);
    while(strlen($popo) > 2) {
      $decoded = asn1decode($popo);
      switch($iter) {
        case 0: //popoSKInput - not supported
          if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed'] && $decoded['type'] == 0)
            throw new Exception("POPOSigningKey::decode() error: POPO Signing Key Input is not supported", BAD_REQUEST);
          $this->algorithmId = new AlgorithmIdentifier();
          $this->algorithmId->decode($popo);
        break;
        case 1: //signature 
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING) {
            $this->signature = $decoded['value'];
          } else
            throw new Exception("POPOSigningKey::decode() error: bad message check: expected an ASN.1 BIT_STRING, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
        break;
        default:
          throw new Exception("POPOSigningKey::decode() error: bad message check: string is too long", BAD_MESSAGE_CHECK);
      }
      $popo = substr($popo, $decoded['length'] + $decoded['hl']);
      $iter++;
    }
    return $offset;
  }
  
  function __construct() {
    $this->popoSKInput = null;
  }
}
