<?php
//This is PHP server-side implementation of MS-XCEP Certificate Enrollment Policy protocol
//described in https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCEP/%5bMS-XCEP%5d.pdf
require_once 'globals.php';
require_once 'helper_functions.php';
require_once 'classes.php';

//global declarations
$server = null;

function exception_handler($e) {
  global $server;
  errorLog($e);
  if (is_null($server))
    exit(1);
  else 
    $server->fault("Internal PKI MS-XCEP SOAP Server", $e->getMessage());
}

set_exception_handler('exception_handler');

$classmap = array('GetPolicies' => 'GetPolicies', 
                  'Client' => 'Client', 
                  'RequestFilter' => 'RequestFilter', 
                  'FilterOIDCollection' => 'FilterOIDCollection',
                  'GetPoliciesResponse' => 'GetPoliciesResponse',
                  'Response' => 'Response',
                  'CACollection' => 'CACollection',
                  'OIDCollection' => 'OIDCollection',
                  'PolicyCollection' => 'PolicyCollection',
                  'CA' => 'CA',
                  'OID' => 'OID',
                  'PolicyCollection' => 'PolicyCollection',
                  'CertificateEnrollmentPolicy' => 'CertificateEnrollmentPolicy',
                  'CAReferenceCollection' => 'CAReferenceCollection',
                  'Attributes' => 'Attributes',
                  'CertificateValidity' => 'CertificateValidity',
                  'EnrollmentPermission' => 'EnrollmentPermission',
                  'PrivateKeyAttributes' => 'PrivateKeyAttributes',
                  'Revision' => 'Revision',
                  'SupersededPolicies' => 'SupersededPolicies',
                  'RARequirements' => 'RARequirements',
                  'KeyArchivalAttributes' => 'KeyArchivalAttributes',
                  'ExtensionCollection' => 'ExtensionCollection',
                  'CryptoProviders' => 'CryptoProviders',
                  'OIDReferenceCollection' => 'OIDReferenceCollection',
                  'Extension' => 'Extension',
                  'CAURICollection' => 'CAURICollection');

function parse($xml) {
  file_put_contents('/tmp/msxcep-response.xml', $xml); //for debugging purpose - uncomment ob_start() and ob_end_flush()
  return $xml;
}

if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("msxcep server.php: receiving data from " . $_SERVER['REMOTE_ADDR'] . "\n", 'info');
if (! str_starts_with($_SERVER['CONTENT_TYPE'], $content_type))
  throw new Exception('wrong Content-Type Header: ' . $_SERVER['CONTENT_TYPE'] . ". Content-Type header must be $content_type");

if ($_SERVER['REQUEST_URI'] != $xcep_path)
  throw new Exception('wrong request uri: ' . $_SERVER['REQUEST_URI'] . ". Request uri must be $xcep_path");

if ($log_level == LOG_DEBUG) 
  errorLog("msxcep server.php: content-type http header has been verified: " . $_SERVER['CONTENT_TYPE'] . "\n", 'debug');
 
$request = file_get_contents('php://input');
$len = strlen($request);

if ($_SERVER['CONTENT_LENGTH'] != $len)
  throw new Exception('wrong Content-Length Header: ' . $_SERVER['CONTENT_LENGTH'] . ". Content-Length is not equal content size $len");

if ($log_level == LOG_DEBUG) {
  errorLog("msxcep server.php: verified that http header Content-Length was equaled to the actual data size: " . $_SERVER['CONTENT_LENGTH'] . "\n", 'debug');
  errorLog("$request\n", 'debug');
}

//ob_start('parse'); 
$server = new SoapServer("policy-service.wsdl", array('soap_version' => SOAP_1_2, 'classmap' => $classmap, 'cache_wsdl' => WSDL_CACHE_NONE, 'keep_alive' => false, 'exceptions' => true));
$server->setClass('GetPoliciesService');
$server->handle();
//ob_end_flush();
?>