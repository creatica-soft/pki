<?php
require_once 'globals.php';
require_once 'helper_functions.php';
require_once 'sql.php';
require_once 'certificate.php';
require_once 'base64url.php';

//just for testing - use real name if integrated with AD and comment out if ($username == "test") line here and in ../key_request.php
//you may use key_request.php or https://pki.example.com/key_request.html to get a key
//in this case no need to include the $password here, just update openssl.conf file in this dir
$username = "test"; 
$password = "123";
$cmp_server = "$PKI_DNS";
$test_server = "$TEST_DNS";
$openssl_path = "/usr/bin/openssl";

if (!is_executable($openssl_path)) {
  print "File $openssl_path is not found\n";
  exit(1);
}

$dns_cmp = checkdnsrr($cmp_server, "A");
$dns_test = checkdnsrr($test_server, "A");
if (! $dns_cmp || ! $dns_test) {
  $cmp_found = false;
  $test_found = false;
  $hosts = file("/etc/hosts");
  if ($hosts) {
    foreach ($hosts as $host) {
      if (str_contains($host, $cmp_server)) {
        $cmp_found = true;
        if ($test_found) break;
      }
      if (str_contains($host, $test_server)) {
        $test_found = true;
        if ($cmp_found) break;
      }
    }
    if (!$cmp_found || !$test_found) {
      print "$cmp_server or $test_server or both is/are not found in DNS. If testing, add 127.0.0.1 $cmp_server $test_server into /etc/hosts\n";
      exit(1);
    }
  }
}

if (!is_file('priv.key')) {
  $command = "$openssl_path genrsa -out priv.key 2048 2>&1";
  $res = exec($command, $output, $result_code);
  if ($result_code != 0) {
    print "$command\n";
    print_r($output);
    exit(1);
  }
  unset($output);
}

if (!is_file('test.example.internal.key')) {
  $command = "$openssl_path genrsa -out test.example.internal.key 2048 2>&1";
  $res = exec($command, $output, $result_code);
  if ($result_code != 0) {
    print "$command\n";
    print_r($output);
    exit(1);
  }
  unset($output);
}

$lines = file('openssl.conf');
if ($lines) {
  $modified = false;
  foreach ($lines as &$line) {
    if (strncmp($line, 'secret = pass:', 14) == 0) {
      if ($ldap_auth)
        auth($username, $password);
      $key = base64url_encode(openssl_random_pseudo_bytes(64));
      sqlSaveKey($username, $key);
      $line = "secret = pass:$key\n";
      $modified = true; 
    } else if (strncmp($line, 'subject = "/CN=username"', 24) == 0) {
      $line = 'subject = "/CN=' . $username . '"' . "\n";
      $modified = true; 
    }
  }
  if ($modified) file_put_contents("openssl.conf", $lines);
}

$now = date_create("now", new DateTimeZone("+0000"))->getTimestamp();

$verbosity = 3; //0 = EMERG, 1 = ALERT, 2 = CRIT, 3 = ERR, 4 = WARN, 5 = NOTE, 6 = INFO, 7 = DEBUG, 8 = TRACE. Defaults to 6 = INFO
$sections = "cmp";

$extNumber = 35;
$numberOfRuns = 1;

$runNumber = 0;
$testNumber = 0;
$timeStart = date_create();

$cmds = ['cr','kur','rr','genm'];
$options = ['',
            '-sans test2.example.internal', 
            '-sans test.example.internal,test2.example.internal', 
            '-sans 10.2.3.4', 
            '-sans test.example.internal,10.2.3.4', 
            '-sans test.example.internal,test2.example.internal,10.2.3.4', 
            "-sans $TEST_DNS",
            '-sans 192.168.1.1',
            '-sans test.example.internal.com,192.168.1.1'];
$options2 = "-crl_download -crl_check_all -untrusted $signing_ca_path -trusted $root_ca_path";
$command2 = "$openssl_path verify $options2 test.example.internal.crt 2>&1";
$options3 = "-url http://$PKI_DNS/ocsp/ -issuer $signing_ca_path";
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
              $sn = gmp_init(getCertSerialNumber('test.example.internal.crt'));
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
              $sn = gmp_init(getCertSerialNumber('test.example.internal.crt'));
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
$timeEnd = date_create();
print "Exec time for $numberOfRuns runs and $testNumber tests is " . date_diff($timeStart, $timeEnd)->format("%M:%S.%F") . "min:sec\n";
foreach ($serialNumbers as $serial)
  sqlDeleteCert($serial, $cmp = false);
