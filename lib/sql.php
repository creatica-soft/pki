<?php

function sqlGetKey($kid) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  if (! $key) return false;
  return $key['key'];
}

function sqlSaveKey($kid, $key) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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

function sqlDeleteKey($key) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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

//SQLite3 single action functions. For performance reason, bulk actions should be wrapped by $db->open(), $db->close()
function sqlGetCert($serial) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  if (! $cert) return null;
  return $cert;
}

function sqlSearchCertsByCN($cn, $status = 0) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  $certs = array();
  $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($cert) {
    $certs[] = $cert;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();  
  $db->close();
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlSearchCertsByFingerprint($fingerprint, $status = 0) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  $certs = array();
  $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($cert) {
    $certs[] = $cert;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();  
  $db->close();
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlSearchCertsBySHash($sHash, $status = 0) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  $certs = array();
  $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($cert) {
    $certs[] = $cert;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();  
  $db->close();
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlSearchCertsByIAndSHash($iAndSHash, $status = 0) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  $certs = array();
  $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($cert) {
    $certs[] = $cert;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();  
  $db->close();
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlSearchCertsBySKIDHash($sKIDHash, $status = 0) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  $certs = array();
  $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($cert) {
    $certs[] = $cert;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();  
  $db->close();
  if (count($certs) == 0) return false;
  return $certs;
}

//$status: 0 - valid, 1 - expired, -1 - revoked
//$subject: DN
// return an array of certs
function sqlGetCerts($subject = null, $status = 0) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  $certs = array();
  $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($cert) {
    $certs[] = $cert;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();  
  $db->close();
  if (count($certs) == 0) return null;
  return $certs;
}

function sqlGetOwnCerts($owner, $status = null) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  $certs = array();
  $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($cert) {
    $certs[] = $cert;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();  
  $db->close();
  if (count($certs) == 0) return false;
  return $certs;
}

function sqlGetOwnCertsCount($owner, $subject = null) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
  $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
  $db->busyTimeout($sqlite3_busy_timeoute_msec);
  if (is_null($subject)) {
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
    $query = $db->prepare("select cert from certs where owner=:owner and status=0");
    if (! $query)
      throw new Exception('sqlGetOwnCertsCount() $db->prepare(select...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':owner', $owner, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlGetOwnCertsCount() $query->bindValue(owner) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlGetOwnCertsCount() $query->execute(select) error: ' . $db->lastErrorMsg());
    $number = 0;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
    while ($cert) {
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
      $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
    }
    $query->close();  
    $db->close();
    return $number;
  }
}

function sqlGetCertsToExpire($owner, $within_days) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec, $now;
  $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
  $db->busyTimeout($sqlite3_busy_timeoute_msec);
  $query = $db->prepare('select serial, notAfter, subject from certs where owner=:owner and status=0 and notAfter<=:notAfter;');
  if (! $query)
    throw new Exception('sqlGetCertsToExpire() $db->prepare(select...) error: ' . $db->lastErrorMsg());
  $i = date_interval_create_from_date_string("$within_days days");
  $notAfter = date_add($now, $i);
  $res = $query->bindValue(':notAfter', $notAfter->getTimestamp(), SQLITE3_INTEGER);
  if (! $res)
    throw new Exception('sqlGetCertsToExpire() $query->bindValue(notAfter) error: ' . $db->lastErrorMsg());
  $res = $query->bindValue(':owner', $owner, SQLITE3_TEXT);
  if (! $res)
    throw new Exception('sqlGetCertsToExpire() $query->bindValue(owner) error: ' . $db->lastErrorMsg());
  $res = $query->execute();
  if (! $res)
    throw new Exception('sqlGetCertsToExpire() $query->execute(select) error: ' . $db->lastErrorMsg());
  $certs = array();
  $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($cert) {
    $certs[] = $cert;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();  
  $db->close();
  if (count($certs) == 0) return false;
  return $certs;
}

//notBefore and notAfter are unix timestamps integers
function sqlSaveCert($serial, $status, $subject, $notBefore, $notAfter, $owner, $role, $cert) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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
  $res = $query->bindValue(':fingerprint', hash('sha1', $cert, $binary = true), SQLITE3_TEXT);
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
  return true;
}

function sqlUpdateCert($serial, $notBefore, $notAfter) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
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

function sqlUpdateCertStatus($serial, $status) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
  $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
  $db->busyTimeout($sqlite3_busy_timeoute_msec);
  $query = $db->prepare('update certs set status = :status where serial = :serial');
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
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
  $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
  $db->busyTimeout($sqlite3_busy_timeoute_msec);
  if (is_null($revocationDate)) {
    $query = $db->prepare('update certs set status = :status, revocationReason = :revocationReason where serial = :serial');
    if (! $query)
      throw new Exception('sqlRevokeCert() $db->prepare(update...) error: ' . $db->lastErrorMsg());
  } else {
    $query = $db->prepare('update certs set status = :status, revocationDate = :revocationDate, revocationReason = :revocationReason where serial = :serial');
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

//checks if a cert is expired and update its status to 1
function sqlUpdateAllCerts() {
  global $now, $sqlite_db, $sqlite3_busy_timeoute_msec;
  $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
  $db->busyTimeout($sqlite3_busy_timeoute_msec);
  $query = $db->prepare("select serial, notAfter from certs where status != :status and subject != 'CRL';");
  if (! $query)
    throw new Exception('sqlUpdateAllCerts $db->prepare(select...) error: ' . $db->lastErrorMsg());
  $res = $query->bindValue(':status', 1, SQLITE3_INTEGER);
  if (! $res)
    throw new Exception('sqlUpdateAllCerts() $query->bindValue(status) error: ' . $db->lastErrorMsg());
  $res = $query->execute();
  if (! $res)
    throw new Exception('sqlUpdateAllCerts() $query->execute(select) error: ' . $db->lastErrorMsg());
  $certs = array();
  $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($cert) {
    $certs[] = $cert;
    $cert = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();  
  
  $query = $db->prepare('update certs set status = 1 where serial = :serial');
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

// for testing purpose, certs should not be deleted but expired or revoked instead
// CLR cert should be deleted before adding a new one
function sqlDeleteCert($serial) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
  $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
  $db->busyTimeout($sqlite3_busy_timeoute_msec);
  $query = $db->prepare('delete from certs where serial = :serial');
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

?>