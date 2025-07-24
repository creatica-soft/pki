<?php

require_once 'config.php';
require_once 'helper_functions.php';
require_once 'algorithm_identifier.php';
require_once 'cert_template.php';
require_once 'certificate.php';
require_once 'sql.php';


function exception_handler($e) {
  errorLog($e, 'exception');
  response(500, $e->getMessage());
}

set_exception_handler('exception_handler');

$certFolder = '';

if (empty($_REQUEST["username"]) || empty($_REQUEST["password"]) || empty($_REQUEST["role"]))
  response(400, 'Usage: ' . $base_url . '/cert_request.php?username=<username>&password=<password>&role=<standard|master>');
    
$username = sanitize($_REQUEST["username"]);
$password = sanitize($_REQUEST["password"]);
$role = sanitize($_REQUEST["role"]);
$pubkey = sanitize($_REQUEST["pubkey"]);
if ($ldap_auth)
  $mail = auth($username, $password);

//at this point we authenticated the user and can
//issue CMP Client SSL Certificate for /CN=$username/ROLE=$role
//$username could be a service account
//if $role is master, do not return the cert until Jira ticket is approved!
//if the ticket is not approved, then this cert needs to be revoked manually
//could do it for standard role as well but probably it is not needed
//certs requested by this cert should have the subject set to /CN=$cn/OWNER=$username
//hence, to update, overwrite or revoke existing certs, the OWNER should match the CN in the client cert!

//first, we need to check if the cert for a user exists and is still valid
//and for this we need to expire certs in the db where "notAfter" field is in the past
sqlUpdateAllCerts(); //set status to 1 for all expired certs

if ($role == 'smime' && isset($mail)) {
  $certs = sqlSearchCertsByCN($cn = $mail);
  if (! $certs) $certs = null;
} 
else
  $certs = sqlGetCerts($subject = "/cn=$username/role=$role", $status = 0); 

if (! is_null($certs)) {
  $cert = new Certificate();
  $cert->decode($certs[0]['cert']);
} elseif ($role != 'master' || in_array($username, $master_users)) { //create a new cert
  if (empty($_REQUEST["pubkey"]))
    response(400, 'Usage: ' . $base_url . '/cert_request.php?username=<username>&password=<password>&role=<standard|master>&description=<jira_ticket_description>');
  $certTemplate = new CertTemplate();
  if ($role == 'smime')
    $certTemplate->subject = new Name(null);
  else
    $certTemplate->subject = new Name("/cn=$username/role=$role");
  $der = pem2der($pubkey);
  if (! $der)
    response(400, 'error: bad or missing RSA public key');
  $certTemplate->publicKey = new SubjectPublicKeyInfo();
  $certTemplate->publicKey->decode($der);
  switch($certTemplate->publicKey->algorithm->algorithm) {
    case '1.2.840.113549.1.1.1': //rsaEncryption
      if (is_null($certTemplate->publicKey->subjectPublicKey->publicExponent))
        response(400, 'RSA key is corrupt, public exponent is null.');  
    break;
    case '1.2.840.10040.4.1': //DSA
      if (is_null($certTemplate->publicKey->subjectPublicKey->publicKey))
        response(400, 'DSA key is corrupt, public key is null.');  
    break;
    case '1.2.840.10045.2.1': //EC
      if (is_null($certTemplate->publicKey->subjectPublicKey->ecPoint))
        response(400, 'DSA key is corrupt, public key is null.');  
    break;
    default:
      response(400, 'Unknown key algorithm. Only RSA, DSA and ECDSA keys are supported');  
  }
  $certTemplate->extensions = new Extensions();
  $keyUsage = new Extension();
  if ($role == 'smime')
    $ku = ['digitalSignature' => 1, 'nonRepudiation' => 1, 'keyEncipherment' => 1, 'dataEncipherment' => 0, 'keyAgreement' => 0, 'keyCertSign' => 0, 'crlSign' => 0, 'encipherOnly' => 0, 'decipherOnly' => 0];
  else
    $ku = ['digitalSignature' => 1, 'nonRepudiation' => 0, 'keyEncipherment' => 0, 'dataEncipherment' => 0, 'keyAgreement' => 0, 'keyCertSign' => 0, 'crlSign' => 0, 'encipherOnly' => 0, 'decipherOnly' => 0];
  $keyUsage->setKeyUsage($ku);
  $certTemplate->extensions->extensions[] = $keyUsage;
  if ($role == 'smime' && isset($mail)) {
    $extKeyUsage = new Extension();
    $extKeyUsage->setExtendedKeyUsage(['E-mail Protection'], $critical = true);
    $certTemplate->extensions->extensions[] = $extKeyUsage;
    $generalNames = array();
    $generalNames[] = new GeneralName($mail);
    $san = new Extension();
    $san->setSubjectAltName($generalNames);
    $certTemplate->extensions->extensions[] = $san;
  }
  $cert = new Certificate();
  $cert->tbsCertificate = new TBSCertificate();
  $cert->tbsCertificate->set($certTemplate, $owner = null, $defaultExtKeyUsages = false, $role);
  $cert->signatureAlg = new AlgorithmIdentifier($default_signing_alg);
  $cert->sign($signing_ca_privkey_path);
  if ($role == 'master' && ! in_array($username, $master_users))
    $status = 2;
  else $status = 0;
  $cert->save($status);
}

// Return the CMP Client SSL Cert
if ($role == 'master' && ! in_array($username, $master_users)) {
  $json = array('status' => 401, 'detail' => array('message' => "$username is not a master user"));
  header('Content-type: application/json', true, 401);
  echo json_encode($json, JSON_UNESCAPED_SLASHES);
}
else {
  if ($role == 'smime' && isset($mail))
    $cn = $mail;
  else
    $cn = $cert->tbsCertificate->subject->getCN();
  header("Content-Disposition: attachment; filename=$cn.cer"); //RFC-2585
  header('Content-Type: application/pkix-cert', true, 200); //RFC-2585
  echo $cert->encode();
}
