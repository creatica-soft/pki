<?php
//This is PHP server-side implementation of MS-WSTEP Certificate Enrollment protocol
//described in https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-WSTEP/%5bMS-WSTEP%5d.pdf
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
    $server->fault($e->getCode(), $e->getMessage());
}

set_exception_handler('exception_handler');

$classmap = array('BinarySecurityTokenType' => 'BinarySecurityTokenType', 
                  'RequestSecurityTokenType' => 'RequestSecurityTokenType', 
                  'RequestedSecurityTokenType' => 'RequestedSecurityTokenType', 
                  'RequestSecurityTokenResponseType' => 'RequestSecurityTokenResponseType',
                  'RequestSecurityTokenResponseCollectionType' => 'RequestSecurityTokenResponseCollectionType',
                  'DispositionMessageType' => 'DispositionMessageType');
                  
function parse($xml) {
  file_put_contents('/tmp/mswstep-response.xml', $xml); //for debugging purpose - uncomment ob_start() and ob_end_flush()
  return $xml;
}

if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("mswstep server.php: receiving data from " . $_SERVER['REMOTE_ADDR'] . "\n", 'info');
if (! str_starts_with($_SERVER['CONTENT_TYPE'], $content_type))
  throw new Exception('wrong Content-Type Header: ' . $_SERVER['CONTENT_TYPE'] . ". Content-Type header must be $content_type");

if ($_SERVER['REQUEST_URI'] != $wstep_path)
  throw new Exception('wrong request uri: ' . $_SERVER['REQUEST_URI'] . ". Request uri must be $wstep_path");

if ($log_level == LOG_DEBUG) 
  errorLog("mswstep server.php: content-type http header has been verified: " . $_SERVER['CONTENT_TYPE'] . "\n", 'debug');
 
$request = file_get_contents('php://input');
$len = strlen($request);

if ($_SERVER['CONTENT_LENGTH'] != $len)
  throw new Exception('mswstep server.php: wrong Content-Length Header: ' . $_SERVER['CONTENT_LENGTH'] . ". Content-Length is not equal content size $len");

if ($log_level == LOG_DEBUG) {
  errorLog("mswstep server.php: verified that http header Content-Length was equaled to the actual data size: " . $_SERVER['CONTENT_LENGTH'] . "\n", 'debug');
  errorLog("$request\n", 'debug');
}
// Strip UTF-8 BOM if present (common cause of parsing failures)
if (substr($request, 0, 3) === "\xEF\xBB\xBF") {
    $request = substr($request, 3);
}

// Optionally prepend XML declaration if missing (assumes UTF-8 from Content-Type)
if (!str_starts_with(trim($request), '<?xml')) {
    $request = '<?xml version="1.0" encoding="UTF-8"?>' . $request;
}
//file_put_contents('/tmp/mswstep-request.xml', $request);
/ob_start('parse'); 
$server = new SoapServer('ws-trust-1.3.wsdl', array('soap_version' => SOAP_1_2, 'classmap' => $classmap, 'cache_wsdl' => WSDL_CACHE_NONE, 'keep_alive' => false, 'exceptions' => true, 'uri' => "$base_url$wstep_path"));
$server->setClass('RequestSecurityTokenService');
$server->handle();
//ob_end_flush();
