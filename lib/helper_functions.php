<?php

function class2str($class) {
  switch($class) {
    case UNIVERSAL_CLASS: return "UNIVERSAL";
    case APPLICATION_CLASS: return "APPLICATION";
    case CONTEXT_SPECIFIC_CLASS: return "CONTEXT_SPECIFIC";
    case PRIVATE_CLASS: return "PRIVATE";
    default: throw new Exception('class2str() error: unknown class: ' . $class);
  }
}

//returns asn.1 universal type as a string
function type2str($type, $class = UNIVERSAL_CLASS) {
  if ($class != UNIVERSAL_CLASS) return $type;
  switch($type) {
    case BOOLEAN: return "BOOLEAN";
    case INTEGER: return "INTEGER";
    case BIT_STRING: return "BIT_STRING";
    case OCTET_STRING: return "OCTET_STRING";
    case NULL_VALUE: return "NULL";
    case OBJECT_IDENTIFIER: return "OBJECT_IDENTIFIER";
    case OBJECT_DESCRIPTOR: return "OBJECT_DESCRIPTOR";
    case EXTERNAL: return "EXTERNAL";
    case REAL: return "REAL";
    case ENUMERATED: return "ENUMERATED";
    case EMBEDDED_PDV: return "EMBEDDED_PDV";
    case UTF8_STRING: return "UTF8_STRING";
    case RELATIVE_OID: return "RELATIVE_OID";
    case TIME_STRING: return "TIME_STRING";
    case RESERVED: return "RESERVED";
    case SEQUENCE: return "SEQUENCE";
    case SET: return "SET";
    case NUMERIC_STRING: return "NUMERIC_STRING";
    case PRINTABLE_STRING: return "PRINTABLE_STRING";
    case T61_STRING: return "T61_STRING";
    case VIDEOTEXT_STRING: return "VIDEOTEXT_STRING";
    case IA5_STRING: return "IA5_STRING";
    case UTC_TIME: return "UTC_TIME";
    case GENERALIZED_TIME: return "GENERALIZED_TIME";
    case GRAPHIC_STRING: return "GRAPHIC_STRING";
    case VISIBLE_STRING: return "VISIBLE_STRING";
    case GENERAL_STRING: return "GENERAL_STRING";
    case UNIVERSAL_STRING: return "UNIVERSAL_STRING";
    case CHARACTER_STRING: return "CHARACTER_STRING";
    case BMP_STRING: return "BMP_STRING";
    case DATE: return "DATE";
    case TIME_OF_DAY: return "TIME_OF_DAY";
    case DATE_TIME: return "DATE_TIME";
    case DURATION: return "DURATION";
    case OID_IRI: return "OID_IRI";
    case RELATIVE_OID_IRI: return "RELATIVE_OID_IRI";
    default: return $type;
  }
}

//returns oid as a string (its description)
//it's possible to use curl to get oid descriptions from http://oid-info.com/get/<oid>
function oid2str($oid) {
  switch($oid) {
    case '1.2.643.2.2.3': return 'gostR3411-94-with-GostR3410-2001';
    case '1.2.643.2.2.4': return 'gostR3411-94-with-GostR3410-94';
    case '1.2.643.2.2.19': return 'gostR3410-2001';
    case '1.2.643.2.2.20': return 'gostR3410-94';
    case '1.2.840.10040.4.1': return 'DSA';
    case '1.2.840.10040.4.3': return 'dsaWithSHA';
    case '1.2.840.10045.2.1': return 'ecPublicKey';
    case '1.2.840.10045.3.1.7': return 'prime256v1';
    case '1.2.840.10045.4.1': return 'ecdsa-with-SHA1';
    case '1.2.840.10045.4.3.2': return 'ecdsa-with-SHA256';
    case '1.2.840.113533.7.66.13': return 'password based MAC';
    case '1.2.840.113549.1.1.1': return 'rsaEncryption';
    case '1.2.840.113549.1.1.2': return 'md2WithRSAEncryption';
    case '1.2.840.113549.1.1.4': return 'md5WithRSAEncryption';
    case '1.2.840.113549.1.1.5': return 'sha1WithRSAEncryption';
    case '1.2.840.113549.1.1.10': return 'rsaSSA-PSS';
    case '1.2.840.113549.1.1.11': return 'sha256WithRSAEncryption';
    case '1.2.840.113549.1.9.1': return 'emailAddress';
    case '1.2.840.113549.1.9.7': return 'challengePassword';
    case '1.2.840.113549.1.9.14': return 'extensionRequest';
    case '1.2.840.113549.2.9': return 'hmac-sha256';
    case '1.2.840.113533.7.66.30': return 'DHBasedMac';
    case '1.3.6.1.4.1.1466.115.121.1.8': return 'Certificate';
    case '1.3.6.1.4.1.1466.115.121.1.9': return 'CertificateList';
    case '1.3.6.1.5.5.7.1.1': return 'Authority Information Access';
    case '1.3.6.1.5.5.7.3.1': return 'TLS Web Server Authentication';
    case '1.3.6.1.5.5.7.3.2': return 'TLS Web Client Authentication';
    case '1.3.6.1.5.5.7.3.3': return 'Code Signing';
    case '1.3.6.1.5.5.7.3.4': return 'E-mail Protection';
    case '1.3.6.1.5.5.7.3.8': return 'Time Stamping';
    case '1.3.6.1.5.5.7.3.9': return 'OCSP Signing';
    case '1.3.6.1.5.5.7.4.1': return 'CA Protocol Encryption Certificate';
    case '1.3.6.1.5.5.7.4.2': return 'Signing Key Pair Types';
    case '1.3.6.1.5.5.7.4.3': return 'Encryption/Key Agreement Key Pair Types';
    case '1.3.6.1.5.5.7.4.4': return 'Preferred Symmetric Algorithm';
    case '1.3.6.1.5.5.7.4.5': return 'Updated CA Key Pair';
    case '1.3.6.1.5.5.7.4.6': return 'CRL';
    case '1.3.6.1.5.5.7.4.7': return 'Unsupported Object Identifiers';
    case '1.3.6.1.5.5.7.4.10': return 'Key Pair Parameters Request'; //OID
    case '1.3.6.1.5.5.7.4.11': return 'Key Pair Parameters Response'; //AlgorithmIdentifier | absent
    case '1.3.6.1.5.5.7.4.12': return 'Revocation Passphrase';
    case '1.3.6.1.5.5.7.4.13': return 'implicitConfirm';
    case '1.3.6.1.5.5.7.4.14': return 'confirmWaitTime';
    case '1.3.6.1.5.5.7.4.15': return 'Original PKIMessage';
    case '1.3.6.1.5.5.7.4.16': return 'Supported Language Tags';
    case '1.3.6.1.5.5.7.5.1.5': return 'oldCertId';
    case '1.3.6.1.5.5.7.48.1': return 'OCSP';
    case '1.3.6.1.5.5.7.48.1.1': return 'OCSP Basic';
    case '1.3.6.1.5.5.7.48.1.2': return 'OCSP Nonce';
    case '1.3.6.1.5.5.7.48.1.3': return 'OCSP CRL';
    case '1.3.6.1.5.5.7.48.1.4': return 'OCSP Response';
    case '1.3.6.1.5.5.7.48.1.9': return 'OCSP Extended Revoke';
    case '1.3.6.1.5.5.7.48.2': return 'CA Issuers';
    case '1.3.6.1.5.5.8.1.2': return 'hmac-sha1'; //was sha1
    case '1.3.14.3.2.26': return 'sha1';
    case '1.3.132.0.34': return 'secp384r1';
    case '0.9.2342.19200300.100.1.25': return 'dc';
    case '2.5.4.3': return 'cn';
    case '2.5.4.4': return 'sn';
    case '2.5.4.5': return 'serialNumber';
    case '2.5.4.6': return 'c'; //a two-letter ISO 3166 country code
    case '2.5.4.7': return 'l';
    case '2.5.4.8': return 'st';
    case '2.5.4.9': return 'street';
    case '2.5.4.10': return 'o';
    case '2.5.4.11': return 'ou';
    case '2.5.4.12': return 'title';
    case '2.5.4.13': return 'description';
    case '2.5.4.32': return 'owner';
    case '2.5.4.36': return 'userCertificate';
    case '2.5.4.37': return 'cACertificate';
    case '2.5.4.38': return 'authorityRevocationList';
    case '2.5.4.39': return 'certificateRevocationList';
    case '2.5.4.40': return 'crossCertificatePair';
    case '2.5.4.42': return 'givenName';
    case '2.5.4.43': return 'initials';
    case '2.5.4.53': return 'deltaRevocationList';
    case '2.5.4.72': return 'role';
    case '2.5.6.16': return 'certificationAuthority';
    case '2.5.6.16.2': return 'certificationAuthority-V2';
    case '2.5.6.19': return 'cRLDistributionPoint';
    case '2.5.29.14': return 'X509v3 Subject Key Identifier';
    case '2.5.29.15': return 'X509v3 Key Usage';
    case '2.5.29.17': return 'X509v3 Subject Alternative Name';
    case '2.5.29.19': return 'X509v3 Basic Constraints';
    case '2.5.29.20': return 'X509v3 CRL Number';
    case '2.5.29.21': return 'X509v3 CRL Reason';
    case '2.5.29.24': return 'X509v3 CRL Invalidity Date';
    case '2.5.29.29': return 'X509v3 CRL Certificate Issuer';
    case '2.5.29.31': return 'X509v3 CRL Distribution Points';
    case '2.5.29.35': return 'X509v3 Authority Key Identifier';
    case '2.5.29.37': return 'X509v3 Extended Key Usage';
    case '2.5.29.37.0': return 'anyExtendedKeyUsage';
    case '2.16.840.1.101.3.4.1.2': return 'aes-128-cbc';
    case '2.16.840.1.101.3.4.2.1': return 'sha256';
    case '2.16.840.1.101.3.4.3.2': return 'dsa-with-SHA256';
    case '2.16.840.1.113730.1.13': return 'Netscape Comment';
    default: return $oid;
  }
}

function str2oid($str) {
  switch($str) {
    case 'gostR3411-94-with-GostR3410-2001': return '1.2.643.2.2.3';
    case 'gostR3411-94-with-GostR3410-94': return '1.2.643.2.2.4';
    case 'gostR3410-2001': return '1.2.643.2.2.19';
    case 'gostR3410-94': return '1.2.643.2.2.20';
    case 'ecPublicKey': return '1.2.840.10045.2.1';
    case 'DSA': return '1.2.840.10040.4.1';
    case 'dsa-with-SHA1': return '1.2.840.10040.4.3';
    case 'dsaWithSHA1': return '1.2.840.10040.4.3';
    case 'prime256v1': return '1.2.840.10045.3.1.7';
    case 'ecdsa-with-SHA1': return '1.2.840.10045.4.1';
    case 'ecdsa-with-SHA256': return '1.2.840.10045.4.3.2';
    case 'password based MAC': return '1.2.840.113533.7.66.13';
    case 'rsaEncryption': return '1.2.840.113549.1.1.1';
    case 'md2WithRSAEncryption': return '1.2.840.113549.1.1.2';
    case 'md5WithRSAEncryption': return '1.2.840.113549.1.1.4';
    case 'sha1WithRSAEncryption': return '1.2.840.113549.1.1.5';
    case 'rsaSSA-PSS': return '1.2.840.113549.1.1.10';
    case 'sha256WithRSAEncryption': return '1.2.840.113549.1.1.11';
    case 'emailAddress': return '1.2.840.113549.1.9.1';
    case 'challengePassword': return '1.2.840.113549.1.9.7';
    case 'extensionRequest': return '1.2.840.113549.1.9.14';
    case 'hmac-sha256': return '1.2.840.113549.2.9';
    case 'DHBasedMac': return '1.2.840.113533.7.66.30';
    case 'Certificate': return '1.3.6.1.4.1.1466.115.121.1.8';
    case 'CertificateList': return '1.3.6.1.4.1.1466.115.121.1.9';
    case 'Authority Information Access': return '1.3.6.1.5.5.7.1.1';
    case 'TLS Web Server Authentication': return '1.3.6.1.5.5.7.3.1';
    case 'TLS Web Client Authentication': return '1.3.6.1.5.5.7.3.2';
    case 'Code Signing': return '1.3.6.1.5.5.7.3.3';
    case 'E-mail Protection': return '1.3.6.1.5.5.7.3.4';
    case 'Time Stamping': return '1.3.6.1.5.5.7.3.8';
    case 'OCSP Signing': return '1.3.6.1.5.5.7.3.9';
    case 'CA Protocol Encryption Certificate': return '1.3.6.1.5.5.7.4.1';
    case 'Signing Key Pair Types': return '1.3.6.1.5.5.7.4.2';
    case 'Encryption/Key Agreement Key Pair Types': return '1.3.6.1.5.5.7.4.3';
    case 'Preferred Symmetric Algorithm': return '1.3.6.1.5.5.7.4.4';
    case 'Updated CA Key Pair': return '1.3.6.1.5.5.7.4.5';
    case 'CRL': return '1.3.6.1.5.5.7.4.6';
    case 'Unsupported Object Identifiers': return '1.3.6.1.5.5.7.4.7';
    case 'Key Pair Parameters Request': return '1.3.6.1.5.5.7.4.10'; //OID
    case 'Key Pair Parameters Response': return '1.3.6.1.5.5.7.4.11'; //AlgorithmIdentifier | absent
    case 'Revocation Passphrase': return '1.3.6.1.5.5.7.4.12';
    case 'implicitConfirm': return '1.3.6.1.5.5.7.4.13';
    case 'confirmWaitTime': return '1.3.6.1.5.5.7.4.14';
    case 'Original PKIMessage': return '1.3.6.1.5.5.7.4.15';
    case 'Supported Language Tags': return '1.3.6.1.5.5.7.4.16';
    case 'oldCertId': return '1.3.6.1.5.5.7.5.1.5';
    case 'OCSP': return '1.3.6.1.5.5.7.48.1';
    case 'OCSP Basic': return '1.3.6.1.5.5.7.48.1.1';
    case 'OCSP Nonce': return '1.3.6.1.5.5.7.48.1.2';
    case 'OCSP CRL': return '1.3.6.1.5.5.7.48.1.3';
    case 'OCSP Response': return '1.3.6.1.5.5.7.48.1.4';
    case 'OCSP Extended Revoke': return '1.3.6.1.5.5.7.48.1.9';
    case 'CA Issuers': return '1.3.6.1.5.5.7.48.2';
    case 'hmac-sha1': return '1.3.6.1.5.5.8.1.2';
    case 'sha1': return '1.3.14.3.2.26';
    case 'secp384r1': return '1.3.132.0.34';
    case 'dc': return '0.9.2342.19200300.100.1.25';
    case 'cn': return '2.5.4.3';
    case 'sn': return '2.5.4.4';
    case 'serialNumber': return '2.5.4.5';
    case 'c': return '2.5.4.6'; //a two-letter ISO 3166 country code
    case 'l': return '2.5.4.7';
    case 'st': return '2.5.4.8';
    case 'street': return '2.5.4.9';
    case 'o': return '2.5.4.10';
    case 'ou': return '2.5.4.11';
    case 'title': return '2.5.4.12';
    case 'description': return '2.5.4.13';
    case 'owner': return '2.5.4.32';
    case 'userCertificate': return '2.5.4.36';
    case 'cACertificate': return '2.5.4.37';
    case 'authorityRevocationList': return '2.5.4.38';
    case 'certificateRevocationList': return '2.5.4.39';
    case 'crossCertificatePair': return '2.5.4.40';
    case 'givenName': return '2.5.4.42';
    case 'initials': return '2.5.4.43';
    case 'deltaRevocationList': return '2.5.4.53';
    case 'role': return '2.5.4.72';
    case 'certificationAuthority': return '2.5.6.16';
    case 'certificationAuthority-V2': return '2.5.6.16.2';
    case 'cRLDistributionPoint': return '2.5.6.19';
    case 'X509v3 Subject Key Identifier': return '2.5.29.14';
    case 'X509v3 Key Usage': return '2.5.29.15';
    case 'X509v3 Subject Alternative Name': return '2.5.29.17';
    case 'X509v3 Basic Constraints': return '2.5.29.19';
    case 'X509v3 CRL Number': return '2.5.29.20';
    case 'X509v3 CRL Reason': return '2.5.29.21';
    case 'X509v3 CRL Invalidity Date': return '2.5.29.24';
    case 'X509v3 CRL Certificate Issuer': return '2.5.29.29';
    case 'X509v3 CRL Distribution Points': return '2.5.29.31';
    case 'X509v3 CRL Distribution Points': return '2.5.29.31';
    case 'X509v3 Authority Key Identifier': return '2.5.29.35';
    case 'X509v3 Extended Key Usage': return '2.5.29.37';
    case 'anyExtendedKeyUsage': return '2.5.29.37.0';
    case 'aes-128-cbc': return '2.16.840.1.101.3.4.1.2';
    case 'sha256': return '2.16.840.1.101.3.4.2.1';
    case 'dsa-with-SHA256': return '2.16.840.1.101.3.4.3.2';
    case 'Netscape Comment': return '2.16.840.1.113730.1.13';
    default: return $str;
  }
}

function der2pem($der, $label) { //label according to rfc7468 (see 4. Guide)
  $pre = "-----BEGIN $label-----\r\n";
  $post = "-----END $label-----\r\n";
  return $pre . chunk_split(base64_encode($der), 64) . $post;
}

function pem2der($pem, $label = '') {
  if (! empty($label)) $label .= '-----';
  $pem = str_replace("\r", '', $pem);
  $arr = explode("\n", $pem);
  $der = '';
  foreach($arr as $str) {
    if (str_starts_with($str, "-----BEGIN $label")) {
      $der = '';
      continue;
    }
    if (str_starts_with($str, "-----END $label")) break;
    $der .= trim($str, " ");
  }
  $der = base64_decode($der, true);
  if (! $der) throw new Exception('base64_decode() returned false probably due to a char from outside of the base64 alphabet');
  return $der;
}

/* return all certificate fields as an array
 $certFile must be PEM-encoded certificate
    [name] => DN in a form /CN=<cn>/...
    [subject] => array of attr key value pairs (RDNs), for example CN => owner
    [hash] => ? hash of what?
    [issuer] => array of attr key value pairs (RDNs), for example CN => issuer
    [version] => integer 
    [serialNumber] => interger
    [serialNumberHex] => hex
    [validFrom] => UTC_TIME //YYMMDDhhmmssZ
    [validTo] => UTC_TIME //YYMMDDhhmmssZ
    [validFrom_time_t] => unix timestamp
    [validTo_time_t] => unix timestamp
    [signatureTypeSN] => short name of signing alg
    [signatureTypeLN] => long name of signing alg
    [signatureTypeNID] => national? algId
    [purposes] => array of arrays of three keys, the outer array is 1-based?
    [extensions] => array of extensions (attr key-value pairs)
            [subjectKeyIdentifier] => 91:D0:C0:31:02:B1:5A:E1:F8:11:77:1E:17:AC:1D:5A:A8:EE:89:3D
            [authorityKeyIdentifier] => keyid:40:24:C4:A9:52:A8:AB:55:BD:BB:15:7F:DE:B3:66:A4:CD:86:28:DA

            [authorityInfoAccess] => CA Issuers - URI:http://pki.example.com/root.aia

            [basicConstraints] => CA:TRUE
            [keyUsage] => Certificate Sign, CRL Sign
            [crlDistributionPoints] => Full Name:  URI:http://pki.example.com/root.crl
*/
function getCertFields($certFile) {
  if (! file_exists($certFile)) throw new ValueError("File $certFile does not exist"); 
  while (openssl_error_string());
  $cert = openssl_x509_read('file://' . $certFile);
  if (! $cert) {
    $error = '';
    while ($err = openssl_error_string()) $error .= $err;
    throw new ValueError("openssl_x509_read(file://$certFile) error: $error");
  }
  $cert_fields = openssl_x509_parse($cert);
  return $cert_fields;
}

// return certificate subject name as a DN; for example, /CN=server name
// $certFile must be PEM-encoded certificate
function getCertSubjectName($certFile) {
  $cert_fields = getCertFields($certFile);
  return $cert_fields['name'];
}

function getCertSerialNumber($certFile, $cmp = false) {
  $cert_fields = getCertFields($certFile);
  return $cert_fields['serialNumber'];
}

// return certificate issuer name as a DN; for example, /CN=server name
// $certFile must be PEM-encoded certificate
function getCertIssuerName($certFile) {
  $cert_fields = getCertFields($certFile);
  $dn = '';
  foreach($cert_fields['issuer'] as $key => $val) {
    $dn .= "/$key=$val";
  }
  return $dn;
}

function getCertValidFrom($certFile) {
  $cert_fields = getCertFields($certFile);
  return $cert_fields['validFrom'];
}

function getCertValidTo($certFile) {
  $cert_fields = getCertFields($certFile);
  return $cert_fields['validTo'];
}

//parse $name having a format of DN '/cn=domainname/owner=username'
function getOwner($name) {
  $subject = explode('/', $name);
  if (! is_array($subject)) return null;
  foreach($subject as $k => $atv) {
    if ($k == 0) continue;
    list($key, $val) = explode('=', $atv);
    if (strcasecmp($key, 'owner') == 0)
      return $val;
  }
  return null;
}

// Validates CN of the certificate subject
function check_cn($cn, $role = 'standard') {
  global $domains_file;

  // Allow certs for unqualified names
  if (strpos($cn, ".") === false) {
    if (strpos($cn, "*") !== false) {
      if ($role == 'master') return true;
      else return false;
    }
    return true;
  }
  
  // A list of allowed domains is kept in $domain_file
  $allowed_domains = fopen($domains_file, "r");
  if (! $allowed_domains) {
    if (! file_exists($domains_file))
      throw new Exception("File not found: $domains_file");
    else throw new Exception("Unable to open $domains_file");
  }
  // Iterate the allowed domains until it matches $cn
  while (! feof($allowed_domains)) {
    $domain = trim(fgets($allowed_domains));
    if ($domain == '') continue;
    if ($domain[0] == '#') continue;

    $domain = preg_quote($domain);
    // Prepend the regex with DNS allowed characters to the line from domains.txt
    // 'master' key is allowed to request wildcard certs
    if ($role == 'master')
      $domain = '([a-zA-Z0-9\*]\.|[a-zA-Z0-9\-]*[a-zA-Z0-9]\.)*' . $domain;
    else $domain = '([a-zA-Z0-9]\.|[a-zA-Z0-9\-]*[a-zA-Z0-9]\.)*' . $domain;
    if (preg_match("/\A$domain\z/", $cn)) {
      fclose($allowed_domains);
      return true;
    }
    else continue;
  }
  fclose($allowed_domains);
  return false;
}

//convert UTC_TIME or GENERALIZED_TIME to php DateTime
function toDateTime($time, $type) {
  $str = rtrim($time, 'Z');
  $str = explode('.', $str)[0];
  if ($type == GENERALIZED_TIME) { // YYYYMMDDhhmmss
     list($century, $year, $month, $day, $hour, $min, $sec) = str_split($str, 2);
  } elseif ($type == UTC_TIME) { // YYMMDDhhmmss
     list($year, $month, $day, $hour, $min, $sec) = str_split($str, 2);
     if ($year < 50) $century = 20; //from rfc 5280, section 4.1.2.5.1
     else $century = 19;
  }
  return new DateTime("$century$year$month$day" . 'T' . "$hour$min$sec", new DateTimeZone("+0000"));
}

//convert UTC_TIME or GENERALIZED_TIME to php DateTime->getTimestamp()
function toTimestamp($time, $type) {
  $dt = toDateTime($time, $type);
  return $dt->getTimestamp();
}

function errorLog($log, $level = 'error') {
  global $now;
  if (! str_ends_with($log, "\n"))
    $log .= "\n"; 
  error_log($now->format("y/m/d/ H:i:s") . " [$level] $log"); 
}

// Basic processing of user POST data
function sanitize($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  
  return $data;
}

function response($code, $message, $quit = true) {
  if ($code >= 400 && $code < 600) {
    errorLog('status: ' . $code . ', detail: ' . $message . "\n", 'error');
    header('Content-type: application/problem+json', true, $code); //rfc7807
  }
  else if ($code >= 200 && $code < 300) {
    errorLog('status: ' . $code . ', detail: ' . $message . "\n", 'info');
    header('Content-type: application/json', true, $code);
  }
  //non-compliant response - changed
  //$json = array('status' => $status, 'code' => $code, 'message' => $message);
  //according to RFC 7807 it should be 
  $json = array('status' => $code, 'detail' => $message);

  $json_out = json_encode($json, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
  if (! $json_out) {
    $json = array('status' => 500, 'detail' => 'json_encode failed: ' . json_last_error_msg());
    echo json_encode($json);
  } else echo $json_out;
  if ($quit) exit;
}

function ldapbind($uri, $binding_dn, $password) {
  global $ldap_network_timeout_sec, $ldap_ca_cert_file, $ldap_tls_require_cert, $ldap_tls_crl_check ;
  $con = false;
  $res = false;
  $res = ldap_set_option(null, LDAP_OPT_DEBUG_LEVEL, 7);
  if (! $res)
    throw new Exception("ldap_set_option(LDAP_OPT_DEBUG_LEVEL) error");
  $con = ldap_connect($uri);
  if (! $con)
    throw new Exception("ldap_connect($uri) failed");
  $res = ldap_set_option($con, LDAP_OPT_NETWORK_TIMEOUT, $ldap_network_timeout_sec);
  if (! $res)
    throw new Exception("ldap_set_option(LDAP_OPT_NETWORK_TIMEOUT) error: " . ldap_error($con));
  $res = ldap_set_option($con, LDAP_OPT_X_TLS_CACERTFILE, $ldap_ca_cert_file);
  if (! $res)
    throw new Exception("ldapbind() ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE) error: " . ldap_error($con));
  $res = ldap_set_option($con, LDAP_OPT_X_TLS_REQUIRE_CERT, $ldap_tls_require_cert);
  if (! $res)
    throw new Exception("ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT) error: " . ldap_error($con));
  $res = ldap_set_option($con, LDAP_OPT_X_TLS_CRLCHECK, $ldap_tls_crl_check );
  if (! $res)
    throw new Exception("ldap_set_option(LDAP_OPT_X_TLS_CRLCHECK) error: " . ldap_error($con));
  $res = ldap_bind($con, $binding_dn, $password);
  if ($res) ldap_unbind($con);
  else {
    ldap_get_option($con, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error);
    errorLog("ldapbind() error: $extended_error");
  }
  return $res;
}

/*
$attributes = array of attributes
$filter="(|(sn=$person*)(givenname=$person*))"; see RFC 4515
example:
$base = 'OU=Users,DC=example,DC=com';
$uris = ['ldaps://ldap.example.com', 'ldaps://ldap2.example.com'];
$filter = "(sAMAccountName=$username)";
$attr = ['distinguishedName'];
$ca_cert_file = '/etc/ssl/certs/example.com.pem';
*/
function ldapsearch($uri, $binding_dn, $password, $base, $filter, $attributes) {
  global $ldap_network_timeout_sec, $ldap_ca_cert_file, $ldap_tls_require_cert, $ldap_tls_crl_check ;
  $attr_values = array();
  $res = false;
  $con = false;
  $res = ldap_set_option(null, LDAP_OPT_DEBUG_LEVEL, 7);
  if (! $res)
    throw new Exception("ldap_set_option(LDAP_OPT_DEBUG_LEVEL) error");
  $con = ldap_connect($uri);
  if (! $con)
    throw new Exception("ldap_connect($uri) failed");
  //$res = ldap_set_option($con, LDAP_OPT_REFERRALS, 0);
  //if (! $res)
    //throw new Exception("ldap_set_option(LDAP_OPT_REFERRALS, 0) error: " . ldap_error($con));
  $res = ldap_set_option($con, LDAP_OPT_NETWORK_TIMEOUT, $ldap_network_timeout_sec);
  if (! $res)
    throw new Exception("ldap_set_option(LDAP_OPT_NETWORK_TIMEOUT) error: " . ldap_error($con));
  $res = ldap_set_option($con, LDAP_OPT_X_TLS_CACERTFILE, $ldap_ca_cert_file);
  if (! $res)
    throw new Exception("ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE) error: " . ldap_error($con));
  $res = ldap_set_option($con, LDAP_OPT_X_TLS_REQUIRE_CERT, $ldap_tls_require_cert);
  if (! $res)
    throw new Exception("ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT) error: " . ldap_error($con));
  $res = ldap_set_option($con, LDAP_OPT_X_TLS_CRLCHECK, $ldap_tls_crl_check );
  if (! $res)
    throw new Exception("ldap_set_option(LDAP_OPT_X_TLS_CRLCHECK) error: " . ldap_error($con));
  $res = ldap_bind($con, $binding_dn, $password);
  if (! $res) {
    ldap_get_option($con, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error);
    throw new Exception("ldap_bind() error: " . ldap_error($con) . "; extended error: $extended_error");
  }

  $res = ldap_search($con, $base, $filter, $attributes);
  if ($res) {
    $entry = ldap_first_entry($con, $res);
    while($entry) {
      $dn = ldap_get_dn($con, $entry);
      foreach($attributes as $attribute)
        $attr_values[$dn][$attribute] = ldap_get_values($con, $entry, $attribute)[0];
      $entry = ldap_next_entry($con, $entry);
    }
    ldap_free_result($res);
  }
  ldap_unbind($con);
  return $attr_values;
}

function auth($username, $password) {
  global $ldap_uri, $ldap_encrypted_pass, $signing_ca_privkey_path, $ldap_binding_dn, $ldap_base_dn, $ldap_service_accounts_base_dn;
  //decrypt service account password
  while (openssl_error_string());
  $pass = null;
  $encrypted_pass = hex2bin($ldap_encrypted_pass);
  $res = openssl_private_decrypt($encrypted_pass, $pass, file_get_contents($signing_ca_privkey_path));
  if (! $res) {
    $error = '';
    while ($err = openssl_error_string()) $error .= $err;
    throw new Exception("openssl_private_decrypt() error: $error");
  }

  //find DN of sAMAccountName=$username attribute
  foreach ($ldap_base_dn as $base_dn) {
    $atv = ldapsearch($ldap_uri, $ldap_binding_dn, $pass, $base_dn, "(sAMAccountName=$username)", ['distinguishedName', 'mail']);
    if (count($atv) > 0) break;
  }
  if (count($atv) == 0)
    throw new Exception("Username ($username) or password is invalid");
  //attempt to bind using $dn and the $password
  $key = array_keys($atv)[0];
  $dn = $atv[$key]['distinguishedName'];
  if (key_exists('mail', $atv[$key]))
    $email = $atv[$key]['mail'];
  else $email = false;
  $res = ldapbind($ldap_uri, $dn, $password);
  if (! $res)
    throw new Exception("Username ($username, $dn) or password is invalid");
  return $email;
}
