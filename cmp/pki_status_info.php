<?php
require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'pki_header.php';

function unusedBits($namedBitString) {
  $res = strlen(strrchr(decbin(hexdec($namedBitString)), '1')) - 1;
  $unused_bits = $res ? dechex($res) : '00';
  if (strlen($unused_bits) % 2 != 0) $unused_bits = '0' . $unused_bits;
  return $unused_bits;
}

/*
PKIStatusInfo ::= SEQUENCE {
    status        PKIStatus,
    statusString  PKIFreeText     OPTIONAL,
    failInfo      PKIFailureInfo  OPTIONAL
}

PKIStatus ::= INTEGER {
         accepted                (0),
         -- you got exactly what you asked for
         grantedWithMods        (1),
         -- you got something like what you asked for; the
         -- requester is responsible for ascertaining the differences
         rejection              (2),
         -- you don't get it, more information elsewhere in the message
         waiting                (3),
         -- the request body part has not yet been processed; expect to
         -- hear more later (note: proper handling of this status
         -- response MAY use the polling req/rep PKIMessages specified
         -- in Section 5.3.22; alternatively, polling in the underlying
         -- transport layer MAY have some utility in this regard)
         revocationWarning      (4),
         -- this message contains a warning that a revocation is
         -- imminent
         revocationNotification (5),
         -- notification that a revocation has occurred
         keyUpdateWarning       (6)
         -- update already done for the oldCertId specified in
         -- CertReqMsg
     }
*/

const ACCEPTED = 0;
const GRANTED_WITH_MODS = 1;
const REJECTION = 2;
const WAITING = 3;
const REVOCATION_WARNING = 4;
const REVOCATION_NOTIFICATION = 5;
const KEY_UPDATE_WARNING = 6;

/*
     PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
         -- text encoded as UTF-8 String [RFC3629] (note: each
         -- UTF8String MAY include an [RFC3066] language tag
         -- to indicate the language of the contained text
         -- see [RFC2482] for details)

     PKIFailureInfo ::= BIT STRING { -- this is named bitstring, so trailing zeros must be omitted; 
                                     -- another words, in an octet all 0 bits from the right (little-endian) should be counted as unused
     -- since we can fail in more than one way!
     -- More codes may be added in the future if/when required.
         badAlg              (0), - most significant bit (MSB)
         -- unrecognized or unsupported Algorithm Identifier
         badMessageCheck     (1),
         -- integrity check failed (e.g., signature did not verify)
         badRequest          (2),
         -- transaction not permitted or supported
         badTime             (3),
         -- messageTime was not sufficiently close to the system time,
         -- as defined by local policy
         badCertId           (4),
         -- no certificate could be found matching the provided criteria
         badDataFormat       (5),
         -- the data submitted has the wrong format
         wrongAuthority      (6),
         -- the authority indicated in the request is different from the
         -- one creating the response token
         incorrectData       (7),
         -- the requester's data is incorrect (for notary services)
         missingTimeStamp    (8),
         -- when the timestamp is missing but should be there
         -- (by policy)
         badPOP              (9),
         -- the proof-of-possession failed
         certRevoked         (10),
            -- the certificate has already been revoked
         certConfirmed       (11),
            -- the certificate has already been confirmed
         wrongIntegrity      (12),
            -- invalid integrity, password based instead of signature or
            -- vice versa
         badRecipientNonce   (13),
            -- invalid recipient nonce, either missing or wrong value
         timeNotAvailable    (14),
            -- the TSA's time source is not available
         unacceptedPolicy    (15),
            -- the requested TSA policy is not supported by the TSA.
         unacceptedExtension (16),
            -- the requested extension is not supported by the TSA.
         addInfoNotAvailable (17),
            -- the additional information requested could not be
            -- understood or is not available
         badSenderNonce      (18),
            -- invalid sender nonce, either missing or wrong size
         badCertTemplate     (19),
            -- invalid cert. template or missing mandatory information
         signerNotTrusted    (20),
            -- signer of the message unknown or not trusted
         transactionIdInUse  (21),
            -- the transaction identifier is already in use
         unsupportedVersion  (22),
            -- the version of the message is not supported
         notAuthorized       (23),
            -- the sender was not authorized to make the preceding
            -- request or perform the preceding action
         systemUnavail       (24),
         -- the request cannot be handled due to system unavailability
         systemFailure       (25),
         -- the request cannot be handled due to system failure
         duplicateCertReq    (26) - least significant bit LSB
         -- certificate cannot be issued because a duplicate
         -- certificate already exists
     }
*/
//Exception integers, which are indexes of pkiFailInfo array of octets
const SYSTEM_FAILURE = 0;
const BAD_MESSAGE_CHECK = 1;
const BAD_REQUEST = 2;
const BAD_TIME = 3;
const BAD_CERT_ID = 4;
const BAD_DATA_FORMAT = 5;
const WRONG_AUTHORITY = 6;
const INCORRECT_DATA = 7;
const MISSING_TIME_STAMP = 8;
const BAD_POP = 9;
const CERT_REVOKED = 10;
const CERT_CONFIRMED = 11;
const WRONG_INTEGRITY = 12;
const BAD_RECIPIENT_NONCE = 13;
const TIME_NOT_AVAILABLE = 14;
const UNACCEPTED_POLICY = 15;
const UNACCEPTED_EXTENSION = 16;
const ADD_INFO_NOT_AVAILABLE = 17;
const BAD_SENDER_NONCE = 18;
const BAD_CERT_TEMPLATE = 19;
const SIGNER_NOT_TRUSTED = 20;
const TRANSACTION_ID_IN_USE = 21;
const UNSUPPORTED_VERSION = 22;
const NOT_AUTHORIZED = 23;
const SYSTEM_UNAVAIL = 24;
const BAD_ALG = 25;
const DUPLICATE_CERT_REQ = 26;

$pkiFailInfo = [
  '00000040', //0b00000000000000000000000001000000 - SYSTEM_FAILURE
  '40', //0b01000000 - 6 unused bits
  '20', //0b00100000 - 5 used bits
  '10', //0b00010000
  '08', //0b00001000
  '04', //0b00000100
  '02', //0b00000010
  '01', //0b00000001 - 0 unused bits
  '0080', //0b0000000010000000
  '0040', //0b0000000001000000 - 7 unused bits
  '0020', //0b0000000000100000
  '0010', //0b0000000000010000
  '0008', //0b0000000000001000
  '0004', //0b0000000000000100
  '0002', //0b0000000000000010
  '0001', //0b0000000000000001 - 0 ununsed bits
  '000080', //0b000000000000000010000000
  '000040', //0b000000000000000001000000
  '000020', //0b000000000000000000100000
  '000010', //0b000000000000000000010000
  '000008', //0b000000000000000000001000
  '000004', //0b000000000000000000000100
  '000002', //0b000000000000000000000010
  '000001', //0b000000000000000000000001
  '00000080', //0b00000000000000000000000010000000
  '80', //0b10000000 - 7 unused bits - BAD_ALGORITHM
  '00000020' //0b00000000000000000000000000100000
];

class PKIStatusInfo {
  public $status;
  public $statusString;
  public $failInfo;

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->status);
    if (! is_null($this->statusString)) {
      if (is_array($this->statusString)) {
        $s = '';
        foreach($this->statusString as $str)
          $s .= asn1encode($class = 0, $constructed = false, $type = UTF8_STRING, $value = $str);
        $encoded .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $s);
      } elseif (is_object($this->statusString) && $this->statusString instanceof PKIFreeText)
        $encoded .= $this->statusString->encode();
    }
    if (! is_null($this->failInfo))
      $encoded .= asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = unusedBits($this->failInfo) . $this->failInfo);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($pkiStatusInfo) {
    $iter = 0;
    $decoded = asn1decode($pkiStatusInfo);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $pkiStatusInfo = $decoded['value'];
    else
      throw new Exception("PKIStatusInfo::decode() error: bad message check: expected an ASN.1 SEQUENCE for PKIStatusInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($pkiStatusInfo) > 2) {
      switch($iter) {
        case 0: //status 
          $decoded = asn1decode($pkiStatusInfo);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->status = $decoded['value'];
          } else
            throw new Exception("PKIStatusInfo::decode() error: bad message check: expected an ASN.1 INTEGER, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 1: //statusString
          $this->statusString = new PKIFreeText();
          $next = $this->statusString->decode($pkiStatusInfo);
        break;
        case 2: //failInfo
          $decoded = asn1decode($pkiStatusInfo);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING) {
            $this->failInfo = $decoded['value'];
          } else
            throw new Exception("PKIStatusInfo::decode() error: bad message check: expected an ASN.1 BIT_STRING, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        default:
          throw new Exception("PKIStatusInfo::decode() error: bad message check: string is too long", BAD_MESSAGE_CHECK);
      }
      $pkiStatusInfo = substr($pkiStatusInfo, $next);
      $iter++;
    }
    return $offset;
  }

  function __construct($pkiStatusInfo = null) {
    if (! is_null($pkiStatusInfo)) {
      if (! is_array($pkiStatusInfo))
        throw new Exception("PKIStatusInfo::__construct() error: an argument is not an array: " . print_r($pkiStatusInfo, true), SYSTEM_FAILURE);
      $this->status = $pkiStatusInfo[0]['value'];
      if (key_exists(1, $pkiStatusInfo)) {
        if (! is_array($pkiStatusInfo[1]))
          throw new Exception("PKIStatusInfo::__construct() error: statusString is not an array: " . print_r($pkiStatusInfo[1], true), SYSTEM_FAILURE);
        $this->statusString = array();
        foreach($pkiStatusInfo[1] as $str) {
          if (! is_array($str)) continue;
          $this->statusString[] = $str['value'];
        }
      }
      if (key_exists(2, $pkiStatusInfo))
        $this->failInfo = $pkiStatusInfo[2]['value'];
    } else {
      $this->statusString = null;
      $this->failInfo = null;
    }
  }
}
