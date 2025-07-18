<?php
require_once '../est/globals.php';
require_once 'helper_functions.php';
require_once 'sql.php';
require_once 'certificate.php';

$cert = 'user.p12';
$cmp_server = "$PKI_DNS";
$base_url = 'https://' . $cmp_server . '/.well-known/est';

$dns_cmp = checkdnsrr($cmp_server, "ANY");
if (! $dns_cmp) {
  $cmp_found = false;
  $hosts = file("/etc/hosts");
  if ($hosts) {
    foreach ($hosts as $host) {
      if (str_contains($host, $cmp_server)) {
        $cmp_found = true;
        break;
      }
    }
    if (!$cmp_found) {
      print "$cmp_server is not found in DNS. If testing, add 127.0.0.1 $cmp_server into /etc/hosts\n";
      exit(1);
    }
  }
}

$numberOfRuns = 1;

$runNumber = 0;
$testNumber = 0;
$timeStart = date_create();

$uris = ['simpleenroll']; //'simplereenroll' - is identical at this time;

$subjects = [ 'test.example.internal', 'test.google.com'];

$exts = ['',
         '-addext subjectAltName=DNS:test2.example.internal', 
         '-addext subjectAltName=DNS:test.example.internal,DNS:test2.example.internal', 
         '-addext subjectAltName=IP:10.2.3.4', 
         '-addext subjectAltName=DNS:test.example.internal,IP:10.2.3.4', 
         '-addext subjectAltName=DNS:test.example.internal,DNS:test2.example.internal,IP:10.2.3.4', 
         '-addext subjectAltName=DNS:test.example.internal.com',
         '-addext subjectAltName=IP:192.168.1.1',
         '-addext subjectAltName=DNS:test.example.internal.com,IP:192.168.1.1'];

$keys = ['-newkey rsa:2048',
         '-newkey rsa:1024',
         '-newkey dsa:dsaparams',
         '-newkey ec -pkeyopt ec_paramgen_curve:P-384',
         '-newkey ec -pkeyopt ec_paramgen_curve:P-256'];

$serialNumbers = array();

if (!is_file($cert)) {
  if (is_file("../cmp_client/priv.key") && is_file("../cmp_client/user.pem")) {
    $command = "openssl pkcs12 -export -in ../cmp_client/user.pem -inkey ../cmp_client/priv.key -out $cert -passout pass:''";
    $res = exec($command, $output, $result_code);
    if ($result_code != 0) {
      print "$command\n";
      print_r($output);
      exit(1);
    }
    unset($output);
  } else {
    print "../cmp_client/priv.key and/or ../cmp_client/user.pem file(s) are missing. Unable to create $cert";
    exit(1); 
  }
}

//generate default dsa params (2048 bits in prime, sha224 digest matching 224 bits in q parameter)
//dsaparams file is used in "openssl req -newkey dsa:dsaparams ..." command (see above)
//an attempt to generate dsa key with certain parameters in "openssl req -newkey dsa -pkeyopt ..." command fails with an error fixup_params
//but works for EC keys
$res = `openssl genpkey -quiet -genparam -algorithm dsa -out dsaparams`;

$success = true;
while($runNumber++ < $numberOfRuns) {
  print "runNumber: $runNumber\n";

  if (file_exists("cacerts.pem")) unlink("cacerts.pem");
  $command = "curl -4 --silent -k $base_url/cacerts | openssl base64 -d -A | openssl pkcs7 -inform der -print_certs -out cacerts.pem";
  $res = `$command`;
  if (file_exists("cacerts.pem")) {
    $res = openssl_x509_read('file://cacerts.pem');
    if (! $res) print 'unable to read file://cacerts.pem' . "\n";
    else openssl_x509_free($res);
  }

  foreach ($uris as $uri) {
    foreach ($subjects as $subject) {
      foreach ($exts as $ext) {
        foreach($keys as $key) {
          $testNumber++;
          $command = "openssl req -new -subj /CN=$subject $ext $key -keyout $subject.key -nodes -out $subject.req";
          $res = `$command`;
          $command = "curl -4 --silent --cacert cacerts.pem --cert-type P12 --cert $cert --data-binary @$subject.req" . ' -H "Content-Type: application/pkcs10"' . " $base_url/simpleenroll | openssl base64 -d -A | openssl pkcs7 -inform der -print_certs -out $subject.crt";
          $res = `$command`;
          if (file_exists("$subject.crt")) {
            $serial = `openssl x509 -in $subject.crt -serial -noout | cut -f2 -d'='`;
            $serial = gmp_init($serial, 16);
            $serialNumbers[] = gmp_strval($serial, 10);
            unlink("$subject.crt");
          } else {
          if (! in_array($testNumber,  [2, 5, 7, 12, 17, 22, 27]) && $testNumber < 31) { //all tests after 30 should fail
              print "Test No $testNumber: failed to get certificate with a subj /CN=$subject, extensions $ext using key $key\n";
              $success = false;
            }
          }         
        }
      }
    }
  }
}
$timeEnd = date_create();
print "Exec time for $numberOfRuns runs and $testNumber tests is " . date_diff($timeStart, $timeEnd)->format("%M:%S.%F") . "min:sec\n";
if ($success) print "All tests are successful!\n";
else print "Some tests have failed, please review the output\n";
foreach ($serialNumbers as $serial)
  sqlDeleteCert($serial);
