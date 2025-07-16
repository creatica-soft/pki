<?php

function sqlGetKey($kid) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetKey() pg_connect() error');
    $res = pg_query_params($db, 'select key from keys where kid=$1;', array($kid));
    if (! $res) throw new Exception('sqlGetKey() pg_query_params() error');
    $key = pg_fetch_assoc($res);
    if (! pg_free_result($res)) throw new Exception('sqlGetKey() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('select key from keys where kid=:kid;');
    if (! $query)
      throw new Exception('sqlGetKey() $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':kid', $kid, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlGetKey() $query->bindValue(kid) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlGetKey() $query->execute(select) error: ' . $db->lastErrorMsg());
    $key = $res->fetchArray($mode = SQLITE3_ASSOC);
    $query->close();
    $db->close();
  }
  if (! $key) return false;
  return $key['key'];
}

function sqlSaveKey($kid, $key) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSaveKey() pg_connect() error');
    $res = pg_query_params($db, 'select key from keys where kid=$1;', array($kid));
    if (! $res) throw new Exception('sqlSaveKey() pg_query_params() error');
    $k = pg_fetch_assoc($res);
    if (! pg_free_result($res)) throw new Exception('sqlSaveKey() pg_free_result() error');
    if ($k) { //update
      $res = pg_query_params($db, 'update keys set key=$1 where kid=$2;', array($key, $kid));
      if (! $res) throw new Exception('sqlSaveKey() pg_query_params(update) error');
      if (! pg_free_result($res)) throw new Exception('sqlSaveKey() pg_free_result(update) error');    
    } else { //insert
      $res = pg_query_params($db, 'insert into keys(kid, key) values($1, $2);', array($kid, $key));
      if (! $res) throw new Exception('sqlSaveKey() pg_query_params(insert) error');
      if (! pg_free_result($res)) throw new Exception('sqlSaveKey() pg_free_result(insert) error');          
    }
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('select kid from keys where kid=:kid;');
    if (! $query)
      throw new Exception('sqlSaveKey() $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':kid', $kid, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveKey() $query->bindValue(kid) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSaveKey() $query->execute(select...) error: ' . $db->lastErrorMsg());
    $k = $res->fetchArray($mode = SQLITE3_ASSOC);
    $query->close();
    if ($k) {
      $query = $db->prepare('update keys set key=:key where kid=:kid;');
      if (! $query)
        throw new Exception('sqlSaveKey $db->prepare(update...) error: ' . $db->lastErrorMsg());
    } else {
      $query = $db->prepare('insert into keys(kid, key) values(:kid, :key);');
      if (! $query)
        throw new Exception('sqlSaveKey $db->prepare(insert...) error: ' . $db->lastErrorMsg());
    }
    $res = $query->bindValue(':kid', $kid, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveKey() $query->bindValue(kid) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':key', $key, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveKey() $query->bindValue(key) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSaveKey() $query->execute(insert...) error: ' . $db->lastErrorMsg());
    $query->close();
    $db->close();
  }
}

function sqlDeleteKey($key) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlDeleteKey() pg_connect() error');
    $res = pg_query_params($db, 'delete from keys where key=$1;', array($key));
    if (! $res) throw new Exception('sqlDeleteKey() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlDeleteKey() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('delete from keys where key=:key;');
    if (! $query)
      throw new Exception('sqlDeleteKey() $db->prepare(delete from keys...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':key', $key, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlDeleteKey() $query->bindValue(key) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlDeleteKey() $query->execute(delete from keys) error: ' . $db->lastErrorMsg());
    $query->close();
    $db->close();
  }
}

//SQLite3 single action functions. For performance reason, bulk actions should be wrapped by $db->open(), $db->close()
function sqlGetCert($serial) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetCert() pg_connect() error');
    $res = pg_query_params($db, 'select * from certs where serial=$1;', array($serial));
    if (! $res) throw new Exception('sqlGetCert() pg_query_params() error');
    $cert = pg_fetch_assoc($res);
    if ($cert) {
      $cert['cert'] = hex2bin($cert['cert']);
      $cert['fingerprint'] = hex2bin($cert['fingerprint']);
      $cert['shash'] = hex2bin($cert['shash']);
      $cert['iandshash'] = hex2bin($cert['iandshash']);
      $cert['skidhash'] = hex2bin($cert['skidhash']);      
    }
    if (! pg_free_result($res)) throw new Exception('sqlGetCert() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('select * from certs where serial=:serial;');
    if (! $query)
      throw new Exception('sqlGetCert $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':serial', $serial, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlGetCert() $query->bindValue(serial) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlGetCert() $query->>execute(select) error: ' . $db->lastErrorMsg());
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
    $query->close();
    $db->close();
  }
  if (! $cert) return null;
  return $cert;
}

function sqlSearchCertsByCN($cn, $status = 0) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  $certs = array();
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSearchCertsByCN() pg_connect() error');
    $res = pg_query_params($db, 'select * from certs where cn=$1 and status=$2;', array($cn, $status));
    if (! $res) throw new Exception('sqlSearchCertsByCN() pg_query_params() error');
    while ($cert = pg_fetch_assoc($res)) {
      $cert['cert'] = hex2bin($cert['cert']);
      $cert['fingerprint'] = hex2bin($cert['fingerprint']);
      $cert['shash'] = hex2bin($cert['shash']);
      $cert['iandshash'] = hex2bin($cert['iandshash']);
      $cert['skidhash'] = hex2bin($cert['skidhash']);      
      $certs[] = $cert;      
    }
    if (! pg_free_result($res)) throw new Exception('sqlSearchCertsByCN() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare("select * from certs where cn=:cn and status=:status;");
    if (! $query)
      throw new Exception('sqlSearchCertsByCN $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':cn', $cn, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSearchCertsByCN() $query->bindValue(cn) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlSearchCertsByCN() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSearchCertsByCN() $query->execute(select) error: ' . $db->lastErrorMsg());
    while ($cert = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certs[] = $cert;
    }
    $query->close();  
    $db->close();
  }
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlSearchCertsByFingerprint($fingerprint, $status = 0) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  $certs = array();
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSearchCertsByFingerprint() pg_connect() error');
    $res = pg_query_params($db, 'select * from certs where fingerprint=$1 and status=$2;', array(bin2hex($fingerprint), $status));
    if (! $res) throw new Exception('sqlSearchCertsByFingerprint() pg_query_params() error');
    while ($cert = pg_fetch_assoc($res)) {
      $cert['cert'] = hex2bin($cert['cert']);
      $cert['fingerprint'] = hex2bin($cert['fingerprint']);
      $cert['shash'] = hex2bin($cert['shash']);
      $cert['iandshash'] = hex2bin($cert['iandshash']);
      $cert['skidhash'] = hex2bin($cert['skidhash']);      
      $certs[] = $cert;      
    }
    if (! pg_free_result($res)) throw new Exception('sqlSearchCertsByFingerprint() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare("select * from certs where fingerprint=:fingerprint and status=:status;");
    if (! $query)
      throw new Exception('sqlSearchCertsByFingerprint $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':fingerprint', $fingerprint, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSearchCertsByFingerprint() $query->bindValue(fingerprint) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlSearchCertsByFingerprint() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSearchCertsByFingerprint() $query->execute(select) error: ' . $db->lastErrorMsg());
    while ($cert = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certs[] = $cert;
    }
    $query->close();  
    $db->close();
  }
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlSearchCertsBySHash($sHash, $status = 0) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  $certs = array();
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSearchCertsBySHash() pg_connect() error');
    $res = pg_query_params($db, 'select * from certs where sHash=$1 and status=$2;', array(bin2hex($sHash), $status));
    if (! $res) throw new Exception('sqlSearchCertsBySHash() pg_query_params() error');
    while ($cert = pg_fetch_assoc($res)) {
      $cert['cert'] = hex2bin($cert['cert']);
      $cert['fingerprint'] = hex2bin($cert['fingerprint']);
      $cert['shash'] = hex2bin($cert['shash']);
      $cert['iandshash'] = hex2bin($cert['iandshash']);
      $cert['skidhash'] = hex2bin($cert['skidhash']);      
      $certs[] = $cert;      
    }
    if (! pg_free_result($res)) throw new Exception('sqlSearchCertsBySHash() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare("select * from certs where sHash=:sHash and status=:status;");
    if (! $query)
      throw new Exception('sqlSearchCertsBySHash $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':sHash', $sHash, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSearchCertsBySHash() $query->bindValue(sHash) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlSearchCertsBySHash() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSearchCertsBySHash() $query->execute(select) error: ' . $db->lastErrorMsg());
    while ($cert = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certs[] = $cert;
    }
    $query->close();  
    $db->close();
  }
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlSearchCertsByIAndSHash($iAndSHash, $status = 0) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  $certs = array();
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSearchCertsByIAndSHash() pg_connect() error');
    $res = pg_query_params($db, 'select * from certs where iAndSHash=$1 and status=$2', array(bin2hex($iAndSHash), $status));
    if (! $res) throw new Exception('sqlSearchCertsByIAndSHash() pg_query_params() error');
    while ($cert = pg_fetch_assoc($res)) {
      $cert['cert'] = hex2bin($cert['cert']);
      $cert['fingerprint'] = hex2bin($cert['fingerprint']);
      $cert['shash'] = hex2bin($cert['shash']);
      $cert['iandshash'] = hex2bin($cert['iandshash']);
      $cert['skidhash'] = hex2bin($cert['skidhash']);      
      $certs[] = $cert;      
    }
    if (! pg_free_result($res)) throw new Exception('sqlSearchCertsByIAndSHash() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare("select * from certs where iAndSHash=:iAndSHash and status=:status;");
    if (! $query)
      throw new Exception('sqlSearchCertsByIAndSHash $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':iAndSHash', $iAndSHash, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSearchCertsByIAndSHash() $query->bindValue(iAndSHash) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlSearchCertsByIAndSHash() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSearchCertsByIAndSHash() $query->execute(select) error: ' . $db->lastErrorMsg());
    while ($cert= $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certs[] = $cert;
    }
    $query->close();  
    $db->close();
  }
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlSearchCertsBySKIDHash($sKIDHash, $status = 0) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  $certs = array();
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSearchCertsBySKIDHash() pg_connect() error');
    $res = pg_query_params($db, 'select * from certs where sKIDHash=$1 and status=$2', array(bin2hex($sKIDHash), $status));
    if (! $res) throw new Exception('sqlSearchCertsBySKIDHash() pg_query_params() error');
    while ($cert = pg_fetch_assoc($res)) {
      $cert['cert'] = hex2bin($cert['cert']);
      $cert['fingerprint'] = hex2bin($cert['fingerprint']);
      $cert['shash'] = hex2bin($cert['shash']);
      $cert['iandshash'] = hex2bin($cert['iandshash']);
      $cert['skidhash'] = hex2bin($cert['skidhash']);      
      $certs[] = $cert;      
    }
    if (! pg_free_result($res)) throw new Exception('sqlSearchCertsBySKIDHash() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare("select * from certs where sKIDHash=:sKIDHash and status=:status;");
    if (! $query)
      throw new Exception('sqlSearchCertsBySKIDHash $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':sKIDHash', $sKIDHash, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSearchCertsBySKIDHash() $query->bindValue(sKIDHash) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlSearchCertsBySKIDHash() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSearchCertsBySKIDHash() $query->execute(select) error: ' . $db->lastErrorMsg());
    while ($cert = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certs[] = $cert;
    }
    $query->close();  
    $db->close();
  }
  if (count($certs) == 0) return false;
  return $certs;
}

//$status: 0 - valid, 1 - expired, -1 - revoked
//$subject: DN
// return an array of certs
function sqlGetCerts($subject = null, $status = 0) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  $certs = array();
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetCerts() pg_connect() error');
    if (is_null($subject)) {
      $res = pg_query_params($db, 'select * from certs where status=$1', array($status));
    } else {
      $res = pg_query_params($db, 'select * from certs where subject=$1 and status=$2;', array($subject, $status));      
    }
    if (! $res) throw new Exception('sqlGetCerts() pg_query_params() error');
    while ($cert = pg_fetch_assoc($res)) {
      $cert['cert'] = hex2bin($cert['cert']);
      $cert['fingerprint'] = hex2bin($cert['fingerprint']);
      $cert['shash'] = hex2bin($cert['shash']);
      $cert['iandshash'] = hex2bin($cert['iandshash']);
      $cert['skidhash'] = hex2bin($cert['skidhash']);
      $certs[] = $cert;      
    }
    if (! pg_free_result($res)) throw new Exception('sqlGetCerts() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    if (is_null($subject)) {
      $query = $db->prepare('select * from certs where status=:status;');
      if (! $query)
        throw new Exception('sqlGetCerts $db->prepare(select...) error: ' . $db->lastErrorMsg());
    } else {
      $query = $db->prepare('select * from certs where subject=:subject and status=:status;');
      if (! $query)
        throw new Exception('sqlGetCerts $db->prepare(select...) error: ' . $db->lastErrorMsg());
      $res = $query->bindValue(':subject', $subject, SQLITE3_TEXT);
      if (! $res)
        throw new Exception('sqlGetCerts() $query->bindValue(subject) error: ' . $db->lastErrorMsg());
    }
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlGetCerts() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlGetCerts() $query->execute(select) error: ' . $db->lastErrorMsg());
    while ($cert = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certs[] = $cert;
    }
    $query->close();  
    $db->close();
  }
  if (count($certs) == 0) return null;
  return $certs;
}

function sqlGetOwnCerts($owner, $status = null) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  $certs = array();
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetOwnCerts() pg_connect() error');
    if (is_null($status)) {
      $res = pg_query_params($db, 'select serial, status, revocationReason, revocationDate, notBefore, notAfter, subject from certs where owner=$1;', array($owner));
    } else {
      $res = pg_query_params($db, 'select serial, status, revocationReason, revocationDate, notBefore, notAfter, subject from certs where owner=$1 and status=$2;', array($owner, $status));      
    }
    if (! $res) throw new Exception('sqlGetOwnCerts() pg_query_params() error');
    while ($cert = pg_fetch_assoc($res)) {
      $certs[] = $cert;      
    }
    if (! pg_free_result($res)) throw new Exception('sqlGetOwnCerts() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    if (is_null($status)) {
      $query = $db->prepare('select serial, status, revocationReason, revocationDate, notBefore, notAfter, subject from certs where owner=:owner;');
      if (! $query)
        throw new Exception('sqlGetOwnCerts() $db->prepare(select...) error: ' . $db->lastErrorMsg());
    } else {
      $query = $db->prepare('select serial, status, revocationReason, revocationDate, notBefore, notAfter, subject from certs where owner=:owner and status=:status;');
      if (! $query)
        throw new Exception('sqlGetOwnCerts() $db->prepare(select...) error: ' . $db->lastErrorMsg());
      $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
      if (! $res)
        throw new Exception('sqlGetOwnCerts() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    }
    $res = $query->bindValue(':owner', $owner, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlGetOwnCerts() $query->bindValue(owner) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlGetOwnCerts() $query->execute(select) error: ' . $db->lastErrorMsg());
    while ($cert = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certs[] = $cert;
    }
    $query->close();  
    $db->close();
  }
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlGetOwnCertsCount($owner, $subject = null) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetOwnCertsCount() pg_connect() error');
    if (is_null($subject)) {
      $res = pg_query_params($db, 'select count(*) from certs where owner=$1 and status=0;', array($owner));
      if (! $res) throw new Exception('sqlGetOwnCertsCount() pg_query_params() error');
      $number = pg_fetch_result($res, 0, 0);
      if (! pg_free_result($res)) throw new Exception('sqlGetOwnCertsCount() pg_free_result() error');
      if (! $number) return 0;
      return $number;
    } else {
      $res = pg_query_params($db, 'select cert from certs where owner=$1 and status=0;', array($owner));
      if (! $res) throw new Exception('sqlGetOwnCertsCount() pg_query_params() error');
      $number = 0;
      while ($cert = pg_fetch_assoc($res)) {
        if (key_exists('cert', $cert)) {
          $certificate = new Certificate();
          $certificate->decode($cert['cert']);
          $sans = $certificate->tbsCertificate->extensions->getSubjectAltName();
          if ($sans) {
            foreach($sans as $san) {
              if ($san == $subject)
                $number++;
            }
          }
        }
      }   
      if (! pg_free_result($res)) throw new Exception('sqlGetOwnCertsCount() pg_free_result() error');
            return $number;
    }
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    if (is_null($subject)) {
      $number = array();
      $query = $db->prepare("select count(*) from certs where owner=:owner and status=0;");
      if (! $query)
        throw new Exception('sqlGetOwnCertsCount() $db->prepare(select...) error: ' . $db->lastErrorMsg());
      $res = $query->bindValue(':owner', $owner, SQLITE3_TEXT);
      if (! $res)
        throw new Exception('sqlGetOwnCertsCount() $query->bindValue(owner) error: ' . $db->lastErrorMsg());
      $res = $query->execute();
      if (! $res)
        throw new Exception('sqlGetOwnCertsCount() $query->execute(select) error: ' . $db->lastErrorMsg());
      $number = $res->fetchArray($mode = SQLITE3_NUM);
      $query->close();  
      $db->close();
      if (count($number) == 0) return 0;
      return $number[0];
    } else {
      $query = $db->prepare("select cert from certs where owner=:owner and status=0;");
      if (! $query)
        throw new Exception('sqlGetOwnCertsCount() $db->prepare(select...) error: ' . $db->lastErrorMsg());
      $res = $query->bindValue(':owner', $owner, SQLITE3_TEXT);
      if (! $res)
        throw new Exception('sqlGetOwnCertsCount() $query->bindValue(owner) error: ' . $db->lastErrorMsg());
      $res = $query->execute();
      if (! $res)
        throw new Exception('sqlGetOwnCertsCount() $query->execute(select) error: ' . $db->lastErrorMsg());
      $number = 0;
      while ($cert = $res->fetchArray($mode = SQLITE3_ASSOC)) {
        if (key_exists('cert', $cert)) {
          $certificate = new Certificate();
          $certificate->decode($cert['cert']);
          $sans = $certificate->tbsCertificate->extensions->getSubjectAltName();
          if ($sans) {
            foreach($sans as $san) {
              if ($san == $subject)
                $number++;
            }
          }
        }
      }
      $query->close();  
      $db->close();
      return $number;
    }
  }
}

function sqlGetCertsToExpire($owner, $within_days) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con, $now;
  $i = date_interval_create_from_date_string("$within_days days");
  $notAfter = date_add($now, $i);
  $certs = array();
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetCertsToExpire() pg_connect() error');
    $res = pg_query_params($db, 'select serial, notAfter, subject from certs where owner=$1 and status=0 and notAfter <= $2;', array($owner, $notAfter->getTimestamp()));
    if (! $res) throw new Exception('sqlGetCertsToExpire() pg_query_params() error');
    while ($cert = pg_fetch_assoc($res)) {
      $certs[] = $cert;      
    }
    if (! pg_free_result($res)) throw new Exception('sqlGetCertsToExpire() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('select serial, notAfter, subject from certs where owner=:owner and status=0 and notAfter<=:notAfter;');
    if (! $query)
      throw new Exception('sqlGetCertsToExpire() $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':notAfter', $notAfter->getTimestamp(), SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlGetCertsToExpire() $query->bindValue(notAfter) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':owner', $owner, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlGetCertsToExpire() $query->bindValue(owner) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlGetCertsToExpire() $query->execute(select) error: ' . $db->lastErrorMsg());
    while ($cert = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certs[] = $cert;
    }
    $query->close();  
    $db->close();
  }
  if (count($certs) == 0) return false;
  return $certs;
}

//notBefore and notAfter are unix timestamps integers
function sqlSaveCert($serial, $status, $subject, $notBefore, $notAfter, $owner, $role, $cert) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSaveCert() pg_connect() error');
    $res = pg_query_params($db, 'select serial from certs where serial=$1;', array($serial));
    if (! $res) throw new Exception('sqlSaveCert() pg_query_params() error');
    $certificate = pg_fetch_assoc($res);
    if (! pg_free_result($res)) throw new Exception('sqlSaveCert() pg_free_result() error');
    if ($certificate) return false;
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare("select serial from certs where serial=:serial;");
    if (! $query)
      throw new Exception('sqlSaveCert $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':serial', $serial, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(serial) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSaveCert() $query->execute(select...) error: ' . $db->lastErrorMsg());
    $certificate = $res->fetchArray($mode = SQLITE3_ASSOC);
    $query->close();
    if ($certificate) return false; //serialNumber exists
  }
  
  $cn = null;
  $fingerprint = null;
  $sHash = null;
  $iAndSHash = null;
  $sKIDHash = null;
  if ($subject != 'CRL') {
    if (str_contains($subject, '/')) {
      $attrs = explode('/', $subject);
      foreach ($attrs as $attr) {
        if (empty($attr)) continue;
        list($attrib, $value) = explode('=', $attr);
        switch(strtolower($attrib)) {
          case 'cn':
            $cn = $value;
          break;
        }
      }
    }
    $sslCert = new Certificate(null);
    $sslCert->decode($cert);
    $sHash = hash('sha1', $sslCert->tbsCertificate->subject->encode(), $binary = true);
    $iAndSHash = $sslCert->tbsCertificate->issuer->encode();
    $iAndSHash .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $sslCert->tbsCertificate->serialNumber);
    $iAndSHash = asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $iAndSHash);
    $iAndSHash = hash('sha1', $iAndSHash, $binary = true);
    $sKIDHash = $sslCert->tbsCertificate->extensions->getSubjectKeyIdentifier();
    if ($sKIDHash)
      $sKIDHash = hash('sha1', $sKIDHash, $binary = true);
    else $sKIDHash = null;
    if (is_null($cn) && ! is_null($sslCert->tbsCertificate->extensions)) {
      $san = $sslCert->tbsCertificate->extensions->getSubjectAltName();
      if ($san && count($san) >= 1) 
        $cn = $san[0];
    }
    if (! $owner && ! is_null($cn))
      $owner = explode('@', $cn)[0];
  }
  $fingerprint = hash('sha1', $cert, $binary = true);
  
  if ($sql_db == 'postgres') {
    $cert = bin2hex($cert);
    $fingerprint = bin2hex($fingerprint);
    $sHash = bin2hex($sHash);
    $sKIDHash = bin2hex($sKIDHash);
    $iAndSHash = bin2hex($iAndSHash);
    
    if (! $owner && ! $role)
      $res = pg_query_params($db, 'insert into certs(serial, status, notBefore, notAfter, subject, cert, cn, fingerprint, sHash, iAndSHash, sKIDHash) values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);', array($serial, $status, $notBefore, $notAfter, $subject, $cert, $cn, $fingerprint, $sHash, $iAndSHash, $sKIDHash));
    elseif ($owner && ! $role)
      $res = pg_query_params($db, 'insert into certs(serial, status, notBefore, notAfter, subject, owner, cert, cn, fingerprint, sHash, iAndSHash, sKIDHash) values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);', array($serial, $status, $notBefore, $notAfter, $subject, $owner, $cert, $cn, $fingerprint, $sHash, $iAndSHash, $sKIDHash));
    elseif (! $owner && $role)
      $res = pg_query_params($db, 'insert into certs(serial, status, notBefore, notAfter, subject, role, cert, cn, fingerprint, sHash, iAndSHash, sKIDHash) values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);', array($serial, $status, $notBefore, $notAfter, $subject, $role, $cert, $cn, $fingerprint, $sHash, $iAndSHash, $sKIDHash));
    else
      $res = pg_query_params($db, 'insert into certs(serial, status, notBefore, notAfter, subject, owner, role, cert, cn, fingerprint, sHash, iAndSHash, sKIDHash) values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);', array($serial, $status, $notBefore, $notAfter, $subject, $owner, $role, $cert, $cn, $fingerprint, $sHash, $iAndSHash, $sKIDHash));
    if (! $res) throw new Exception('sqlSaveCert() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlSaveCert() pg_free_result() error');
  } else {
    if (! $owner && ! $role)
      $query = $db->prepare('insert into certs(serial, status, notBefore, notAfter, subject, cert, cn, fingerprint, sHash, iAndSHash, sKIDHash) values(:serial, :status, :notBefore, :notAfter, :subject, :cert, :cn, :fingerprint, :sHash, :iAndSHash, :sKIDHash);');
    elseif ($owner && ! $role)
      $query = $db->prepare('insert into certs(serial, status, notBefore, notAfter, subject, owner, cert, cn, fingerprint, sHash, iAndSHash, sKIDHash) values(:serial, :status, :notBefore, :notAfter, :subject, :owner, :cert, :cn, :fingerprint, :sHash, :iAndSHash, :sKIDHash);');
    elseif (! $owner && $role)
      $query = $db->prepare('insert into certs(serial, status, notBefore, notAfter, subject, role, cert, cn, fingerprint, sHash, iAndSHash, sKIDHash) values(:serial, :status, :notBefore, :notAfter, :subject, :role, :cert, :cn, :fingerprint, :sHash, :iAndSHash, :sKIDHash);');
    else
      $query = $db->prepare('insert into certs(serial, status, notBefore, notAfter, subject, owner, role, cert, cn, fingerprint, sHash, iAndSHash, sKIDHash) values(:serial, :status, :notBefore, :notAfter, :subject, :owner, :role, :cert, :cn, :fingerprint, :sHash, :iAndSHash, :sKIDHash);');
    if (! $query)
      throw new Exception('sqlSaveCert $db->prepare(insert...) error: ' . $db->lastErrorMsg());
  
    $res = $query->bindValue(':serial', $serial, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(serial) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':subject', $subject, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(subject) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':notBefore', $notBefore, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(notBefore) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':notAfter', $notAfter, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(notAfter) error: ' . $db->lastErrorMsg());
    if ($owner)
      $res = $query->bindValue(':owner', $owner, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(owner) error: ' . $db->lastErrorMsg());
    if ($role)
      $res = $query->bindValue(':role', $role, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(role) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':cert', $cert, SQLITE3_BLOB);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(cert) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':cn', $cn, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(cn) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':fingerprint', $fingerprint, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(fingerprint) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':sHash', $sHash, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(sHash) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':iAndSHash', $iAndSHash, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(iAndSHash) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':sKIDHash', $sKIDHash, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCert() $query->bindValue(sKIDHash) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSaveCert() $query->execute(insert...) error: ' . $db->lastErrorMsg());
    $query->close();
    $db->close();
  }
  return true;
}

function sqlUpdateCert($serial, $notBefore, $notAfter) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlUpdateCert() pg_connect() error');
    $res = pg_query_params($db, 'update certs set notBefore = $1, notAfter = $2 where serial = $3;', array($notBefore, $notAfter, $serial));
    if (! $res) throw new Exception('sqlUpdateCert() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlUpdateCert() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('update certs set notBefore = :notBefore, notAfter = :notAfter where serial = :serial');
    if (! $query)
      throw new Exception('sqlUpdateCert $db->prepare(update...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':serial', $serial, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlUpdateCert() $query->bindValue(serial) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':notBefore', $notBefore, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlUpdateCert() $query->bindValue(notBefore) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':notAfter', $notAfter, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlUpdateCert() $query->bindValue(notAfter) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlUpdateCert() $query->execute(update) error: ' . $db->lastErrorMsg());
    $query->close();
    $db->close();
  }
}

function sqlUpdateCertStatus($serial, $status) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlUpdateCertStatus() pg_connect() error');
    $res = pg_query_params($db, 'update certs set status = $1 where serial = $2;', array($status, $serial));
    if (! $res) throw new Exception('sqlUpdateCertStatus() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlUpdateCertStatus() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('update certs set status = :status where serial = :serial;');
    if (! $query)
      throw new Exception('sqlUpdateCertStatus $db->prepare(update...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':serial', $serial, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlUpdateCertStatus() $query->bindValue(serial) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlUpdateCertStatus() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlUpdateCertStatus() $query->execute(update) error: ' . $db->lastErrorMsg());
    $query->close();
    $db->close();
  }
}

/*
$status = 0 (valid), 1 (expired), -1 (revoked)
$revocationReason
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

*/
function sqlRevokeCert($serial, $revocationDate = null, $revocationReason = 0) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlRevokeCert() pg_connect() error');
    if (is_null($revocationDate)) {
      $res = pg_query_params($db, 'update certs set status = $1, revocationReason = $2 where serial = $3;', array(-1, $revocationReason, $serial));
    }
    else {
      $res = pg_query_params($db, 'update certs set status = $1, revocationDate = $2, revocationReason = $3 where serial = $4;', array(-1, $revocationDate, $revocationReason, $serial));      
    }
    if (! $res) throw new Exception('sqlRevokeCert() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlRevokeCert() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    if (is_null($revocationDate)) {
      $query = $db->prepare('update certs set status = :status, revocationReason = :revocationReason where serial = :serial;');
      if (! $query)
        throw new Exception('sqlRevokeCert() $db->prepare(update...) error: ' . $db->lastErrorMsg());
    } else {
      $query = $db->prepare('update certs set status = :status, revocationDate = :revocationDate, revocationReason = :revocationReason where serial = :serial;');
      if (! $query)
        throw new Exception('sqlRevokeCert() $db->prepare(update...) error: ' . $db->lastErrorMsg());
      $res = $query->bindValue(':revocationDate', $revocationDate, SQLITE3_INTEGER);
      if (! $res)
        throw new Exception('sqlRevokeCert() $query->bindValue(revocationDate) error: ' . $db->lastErrorMsg());
    }
    $res = $query->bindValue(':serial', $serial, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlRevokeCert() $query->bindValue(serial) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':status', -1, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlRevokeCert() $query->bindValue(status) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':revocationReason', $revocationReason, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlRevokeCert() $query->bindValue(revocationReason) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlRevokeCert() $query->execute(update) error: ' . $db->lastErrorMsg());
    $query->close();
    $db->close();
  }
}

//checks if a cert is expired and update its status to 1
function sqlUpdateAllCerts() {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con, $now;
  $certs = array();
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlUpdateAllCerts() pg_connect() error');
    $res = pg_query_params($db, "select serial, notAfter from certs where status != 1 and subject != 'CRL';");
    if (! $res) throw new Exception('sqlUpdateAllCerts() pg_query_params() error');
    while ($cert = pg_fetch_assoc($res)) {
      $certs[] = $cert;
    }
    if (! pg_free_result($res)) throw new Exception('sqlUpdateAllCerts(select) pg_free_result() error');
    $res = pg_prepare($db, "", 'update certs set status = 1 where serial = $1;');
    foreach ($certs as $cert) {
      if ($cert['notAfter'] < $now->getTimestamp()) {
        $serial = $cert['serial'];
        $res = pg_execute($db, "", array($serial));
        if (! $res) throw new Exception('sqlUpdateAllCerts() pg_execute(update) error');
        if (! pg_free_result($res)) throw new Exception('sqlUpdateAllCerts(update) pg_free_result() error');
      }      
    }
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare("select serial, notAfter from certs where status != 1 and subject != 'CRL';");
    if (! $query)
      throw new Exception('sqlUpdateAllCerts $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlUpdateAllCerts() $query->execute(select) error: ' . $db->lastErrorMsg());
    while ($cert = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certs[] = $cert;
    }
    $query->close();  
    
    $query = $db->prepare('update certs set status = 1 where serial = :serial;');
    if (! $query)
      throw new Exception('sqlUpdateAllCerts $db->prepare(update...) error: ' . $db->lastErrorMsg());
    $serial = '';
    $res = $query->bindParam(':serial', $serial, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlUpdateAllCerts() $query->bindParam(serial) error: ' . $db->lastErrorMsg());
    foreach($certs as $cert) {
      if ($cert['notAfter'] < $now->getTimestamp()) {
        $serial = $cert['serial'];
        $res = $query->execute();
        if (! $res)
          throw new Exception('sqlUpdateAllCerts() $query->execute(update) error: ' . $db->lastErrorMsg());
      }
    }
    $query->close();  
    $db->close();
  }
}

// for testing purpose, certs should not be deleted but expired or revoked instead
// CLR cert should be deleted before adding a new one
function sqlDeleteCert($serial) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con;
  if ($sql_db == 'postgres') {
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlDeleteCert() pg_connect() error');
    $res = pg_query_params($db, 'delete from certs where serial = $1;', array($serial));
    if (! $res) throw new Exception('sqlDeleteCert() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlDeleteCert() pg_free_result() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('delete from certs where serial = :serial;');
    if (! $query)
      throw new Exception('sqlDeleteCert $db->prepare(delete...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':serial', $serial, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlDeleteCert() $query->bindValue(serial) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlDeleteCert() $query->execute(delete) error: ' . $db->lastErrorMsg());
    $query->close();
    $db->close();
  }
}

?>