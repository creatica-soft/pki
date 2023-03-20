<?php
require_once 'globals.php';
require_once 'helper_functions.php';
require_once 'sql.php';
require_once 'certificate.php';

$now = date_create(null, new DateTimeZone("+0000"))->getTimestamp();
$openssl_path = "/usr/bin/openssl3";

$verbosity = 3; //0 = EMERG, 1 = ALERT, 2 = CRIT, 3 = ERR, 4 = WARN, 5 = NOTE, 6 = INFO, 7 = DEBUG, 8 = TRACE. Defaults to 6 = INFO
$sections = "cmp";

$extNumber = 35;
$numberOfRuns = 1;

$runNumber = 0;
$testNumber = 0;
$timeStart = date_create(null);

$cmds = ['cr','kur','rr','genm'];
$options = ['',
            '-sans test2.example.internal', 
            '-sans test.example.internal,test2.example.internal', 
            '-sans 10.2.3.4', 
            '-sans test.example.internal,10.2.3.4', 
            '-sans test.example.internal,test2.example.internal,10.2.3.4', 
            '-sans test.example.com',
            '-sans 192.168.1.1',
            '-sans test.example.internal.com,192.168.1.1'];
$options2 = "-crl_download -crl_check_all -untrusted $signing_ca_path -trusted $root_ca_path";
$command2 = "$openssl_path verify $options2 test.example.internal.crt 2>&1";
$options3 = "-url http://pki.example.com/ocsp/ -issuer $signing_ca_path";
$command3 = "$openssl_path ocsp $options3 -cert test.example.internal.crt 2>&1";

$serialNumbers = array();

$command = "$openssl_path cmp -config openssl.conf -section $sections,ir -x509_strict -verbosity $verbosity 2>&1";
$res = exec($command, $output, $result_code);
if ($result_code != 0) {
  print "Test No $testNumber: $command\n";
  print_r($output);
}
unset($output);

while($runNumber++ < $numberOfRuns) {
  print "runNumber: $runNumber\n";

  foreach ($options as $option) {
    foreach ($cmds as $cmd) {

      switch($cmd) {
        case 'rr':
          $testNumber++;
          $command = "$openssl_path cmp -config openssl.conf -section $sections,$cmd $option -x509_strict -verbosity $verbosity 2>&1";
          $res = exec($command, $output, $result_code);
          if ($result_code != 0) {
            if (! in_array($testNumber, [259,267,275])) {
              print "Test No $testNumber: $command\n";
              print_r($output);
            }
          }
          unset($output);

        break;
        case 'genm':
          $testNumber++;
          $command = "$openssl_path cmp -config openssl.conf -section $sections,$cmd $option -x509_strict -verbosity $verbosity 2>&1";
          $res = exec($command, $output, $result_code);
          if ($result_code != 0) {
            print "Test No $testNumber: $command\n";
            print_r($output);
          }
          unset($output);
        break;
      default:
        if ($option == '') {
          for ($i = 1; $i <= $extNumber; $i++) {
            $testNumber++;
            $command = "$openssl_path cmp -config openssl.conf -section $sections,$cmd -reqexts ext_$i -x509_strict -verbosity $verbosity 2>&1";
            $res = exec($command, $output, $result_code);
            if ($result_code != 0) {
              if ( ! in_array($i, [17,29,30,31,33,34,35])) {
                print "Test No $testNumber: $command\n";
                print_r($output);
              }
            } else {
              $sn = gmp_init(getCertSerialNumber('test.lat.internal.crt'));
              $serialNumbers[] = gmp_strval($sn);
            }
            unset($output);
         
            $testNumber++;
            $res = exec($command2, $output, $result_code);
            if ($result_code != 0) {
              print "Test No $testNumber: $command2\n";
              print_r($output);
            }
            unset($output);

            $testNumber++;
            $res = exec($command3, $output, $result_code);
            if ($result_code != 0) {
              print "Test No $testNumber: $command3\n";
              print_r($output);
            }
            unset($output);
          }
        } else {
            $testNumber++;
            $command = "$openssl_path cmp -config openssl.conf -section $sections,$cmd $option -x509_strict -verbosity $verbosity 2>&1";
            $res = exec($command, $output, $result_code);
            if ($result_code != 0) {
              if ( ! in_array($testNumber, [253,256,261,264,269,272])) {
                print "Test No $testNumber: $command\n";
                print_r($output);
              }
            } else {
              $sn = gmp_init(getCertSerialNumber('test.lat.internal.crt'));
              $serialNumbers[] = gmp_strval($sn);
            }
            unset($output);
       
            $testNumber++;
            $res = exec($command2, $output, $result_code);
            if ($result_code != 0 && ! in_array($testNumber, [254,257,262,265,270,273])) {
              print "Test No $testNumber: $command2\n";
              print_r($output);
            }
            unset($output);
  
            $testNumber++;
            $res = exec($command3, $output, $result_code);
            if ($result_code != 0) {
              print "Test No $testNumber: $command3\n";
              print_r($output);
            }
            unset($output);
        }
      }
    }
  }
}
$timeEnd = date_create(null);
print "Exec time for $numberOfRuns runs and $testNumber tests is " . date_diff($timeStart, $timeEnd)->format("%M:%S.%F") . "min:sec\n";
foreach ($serialNumbers as $serial)
  sqlDeleteCert($serial, $cmp = false);
?>