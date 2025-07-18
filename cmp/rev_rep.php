<?php
require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'globals.php';
require_once 'pki_status_info.php';
require_once 'certificate.php';
require_once 'extension.php';
require_once 'helper_functions.php';
require_once 'sql.php';
require_once 'cert_rev_list.php';

/*
RevRepContent ::= SEQUENCE {
         status        SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
         revCerts  [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
         crls      [1] SEQUENCE SIZE (1..MAX) OF CertificateList
                       OPTIONAL
     }

CertId ::= SEQUENCE {
 issuer GeneralName,
 serialNumber INTEGER }

CertificateList ::= CRL

CRL ::= SEQUENCE {
 tbsCRL TBSCRL,
 signatureAlgorithm AlgorithmIdentifier,
 signature BIT STRING }

TBSCRL ::= SEQUENCE {
 version Version OPTIONAL,
 -- if present, MUST be v2
 signature AlgorithmIdentifier,
 issuer Name,
 thisUpdate Time,
 nextUpdate Time OPTIONAL,
 revokedCertificates SEQUENCE OF SEQUENCE {
   userCertificate CertificateSerialNumber,
   revocationDate Time,
   crlEntryExtensions Extensions OPTIONAL
   -- if present, MUST be v2
 } OPTIONAL,
 
crlEntryExtensions [0] Extensions OPTIONAL }
 -- if present, MUST be v2

-- Version, Time, CertificateSerialNumber, and Extensions were
-- defined earlier for use in the certificate structure

crlEntryExtensions:

id-ce-cRLReasons OBJECT IDENTIFIER ::= { id-ce 21 }

   -- reasonCode ::= { CRLReason }

   CRLReason ::= ENUMERATED {
        unspecified             (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
             -- value 7 is not used
        removeFromCRL           (8),
        privilegeWithdrawn      (9),
        aACompromise           (10) }

id-ce-invalidityDate OBJECT IDENTIFIER ::= { id-ce 24 }

   InvalidityDate ::=  GeneralizedTime

id-ce-certificateIssuer   OBJECT IDENTIFIER ::= { id-ce 29 }

   CertificateIssuer ::=     GeneralNames
*/

class RevRepContent {
  public $statusSeq;
  public $revCertIds;
  public $crls;

  function set() {
    global $now, $request, $max_pki_requests, $default_signing_alg, $signing_ca_der_path, $signing_ca_privkey_path, $signing_ca_path, $clr_next_update_in_days, $cert_serial_bytes;
    
    $reqNumber = 0;
    foreach($request->body->content->revReqs as $req) {
      if ($reqNumber >= $max_pki_requests)
        throw new Exception("Max number of PKI requests ($max_pki_requests) in a single message is reached", BAD_REQUEST);
      if (is_null($req->certTemplate->serialNumber))
        throw new Exception("bad certificate template - missing serialNumber", BAD_CERT_TEMPLATE);
      if (is_null($req->certTemplate->issuer))
        throw new Exception("bad certificate template - missing issuer", BAD_CERT_TEMPLATE);
      $dn = getCertSubjectName($signing_ca_path);
      if (strcasecmp($dn, $req->certTemplate->issuer) != 0)
        throw new Exception("bad certificate template -  wrong authority: the issuer (" . $req->certTemplate->issuer . ") of the certificate template is different from the CA subject ($dn)", BAD_CERT_TEMPLATE);
      $cert = sqlGetCert($req->certTemplate->serialNumber);
      if (is_null($cert))
        throw new Exception("Certificate with the serialNumber (" . $req->certTemplate->serialNumber . ") is not found in the certs database", BAD_REQUEST);
      if ($cert['status'] == -1)
        throw new Exception("Certificate with the serialNumber (" . $req->certTemplate->serialNumber . ") has already been revoked", CERT_REVOKED);
      if ($cert['status'] == 1)
        throw new Exception("Certificate with the serialNumber (" . $req->certTemplate->serialNumber . ") has expired", BAD_REQUEST);
      $owner = getOwner($cert['subject']);
      if ($owner) { //owner field is not present in SSL client certificates, those that are used for authentication in CMP
                    //but we should be able to revoke SSL client certs anyway
        $cn = $request->header->sender->getCN();
        $role = $request->header->sender->getRole();
        if (strncasecmp($owner, $cn, strlen($owner)) != 0 && strncasecmp($role, 'master', 6) != 0)
          throw new Exception("Owner in the subject of a cert $owner is not equal to the sender CN $cn and CN role is $role", BAD_REQUEST);
      }

      $revReason = 0;
      if (! is_null($req->crlExtensions)) {
        foreach($req->crlExtensions->extensions as $ext) {
          switch($ext->extnID) {
            case '2.5.29.21': //crlReason
              $revReason = $ext->extnValue;
            break;
            case '2.5.29.24': //invalidityDate
            break;
            case '2.5.29.29': //certIssuer
            break;
            default: break;
          }
        }
      }
      $revocationDate = $now->getTimestamp();
      sqlRevokeCert($req->certTemplate->serialNumber, $revocationDate, $revReason);

      $status = new PKIStatusInfo();
      $status->status = ACCEPTED; //OR GRANTED_WITH_MODS
      $this->statusSeq[] = $status;
      $reqNumber++;
    }
    //generate new CRL
    $crl = new CRL();
  }

  function encode() {
    $encoded = '';
    foreach($this->statusSeq as $status)
      $encoded .= $status->encode();
    $encoded = asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
    if (! is_null($this->revCertIds)) {
      $certIds = '';
      foreach($this->revCertIds as $id)
        $certIds .= $id->encode();
      $certIds = asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $certIds);
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $certIds);
    }
    if (! is_null($this->crls)) {
      $crls = '';
      foreach($this->crls as $crl)
        $crls .= $crl->encode();
      $crls = asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $crls);
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $crls);
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function __construct() {
    $this->statusSeq = array();
    $this->revCertIds = null;
    $this->crls = null;
  }
}
