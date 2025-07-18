<?php

function getCertReqIds($transactionID, $db) {
  global $sql_db;
  $certReqIds = array();
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'select * from cert_req_ids where "transactionID"=$1;', array($transactionID));
    if (! $res) throw new Exception('getCertReqIds() pg_query_params() error');
    while ($certReqId = pg_fetch_assoc($res)) {
      $certReqIds[] = $certReqId;      
    }    
    if (! pg_free_result($res)) throw new Exception('getCertReqIds() pg_free_result() error');
  } else {
    $query = $db->prepare("select * from cert_req_ids where transactionID=:transactionID;");
    if (! $query)
      throw new Exception('getCertReqIds() $db->prepare(select from cert_req_ids...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':transactionID', $transactionID, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('getCertReqIds() $query->bindValue(transactionID) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('getCertReqIds() $query->execute(select from cert_req_ids) error: ' . $db->lastErrorMsg());
    while ($certReqId = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $certReqIds[] = $certReqId;
    }
    $query->close();
  }
  if (count($certReqIds) == 0) return false;
  return $certReqIds;
}

function sqlGetCertReqIds($transactionID) {
  global $sql_db, $pg_con, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetCertReqIds() pg_connect() error');
    $certReqIds = getCertReqIds($transactionID, $db);
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $certReqIds = getCertReqIds($transactionID, $db);
    $db->close();
  }
  return $certReqIds;
}

function sqlSaveCertReqIds($serial, $certReqId, $timestamp, $nonce, $transactionID) {
  global $sql_db, $sqlite_db, $sqlite3_busy_timeoute_msec, $pg_con, $confirm_wait_time_sec, $now, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSaveCertReqIds() pg_connect() error');
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
  }
  $certReqIds = getCertReqIds($transactionID, $db);
  if ($certReqIds) {
    foreach($certReqIds as $id) {
      $ts = date_create_from_format("U", $id['timestamp']);
      $confirmWaitTimeInterval = DateInterval::createFromDateString("$confirm_wait_time_sec seconds");
      $expTime = date_add($ts, $confirmWaitTimeInterval);
      $diff = date_diff($now, $expTime);
      if ($diff->format('%R')  == '-') { //confirm_wait_time expired - transactionID may be deleted from both tables nonces and cert_req_ids
        deleteCertReqIds($transactionID, $db);
      } else
        throw new Exception('sqlSaveCertReqIds() error: transactionID is in use');
    }
  }
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'insert into cert_req_ids(serial, "certReqId", timestamp, nonce, "transactionID") values($1, $2, $3, $4, $5);', array($serial, $certReqId, $timestamp, $nonce, $transactionID));
    if (! $res) throw new Exception('sqlSaveCertReqIds() pg_query_params() error');
  } else {
    $query = $db->prepare('insert into cert_req_ids(serial, certReqId, timestamp, nonce, transactionID) values(:serial, :certReqId, :timestamp, :nonce, :transactionID);');
    if (! $query)
      throw new Exception('sqlSaveCertReqIds() $db->prepare(insert...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':serial', $serial, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCertReqIds() $query->bindValue(serial) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':certReqId', $certReqId, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCertReqIds() $query->bindValue(certReqId) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':timestamp', $timestamp, SQLITE3_INTEGER);
    if (! $res)
      throw new Exception('sqlSaveCertReqIds() $query->bindValue(timestamp) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':nonce', $nonce, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCertReqIds() $query->bindValue(nonce) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':transactionID', $transactionID, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlSaveCertReqIds() $query->bindValue(transactionID) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlSaveCertReqIds() $query->execute(insert...) error: ' . $db->lastErrorMsg());
    $query->close();
    $db->close();
  }
}

function deleteCertReqIds($transactionID, $db) {
  global $sql_db;
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'delete from cert_req_ids where "transactionID" = $1;', array($transactionID));
    if (! $res) throw new Exception('deleteCertReqIds() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('deleteCertReqIds() pg_free_result() error');
  } else {
    $query = $db->prepare('delete from cert_req_ids where transactionID = :transactionID');
    if (! $query)
      throw new Exception('sqlDeleteCertReqIds() $db->prepare(delete from cert_req_ids...) error: ' . $db->lastErrorMsg());
    $res = $query->bindValue(':transactionID', $transactionID, SQLITE3_TEXT);
    if (! $res)
      throw new Exception('sqlDeleteCertReqIds() $query->bindValue(transactionID) error: ' . $db->lastErrorMsg());
    $res = $query->execute();
    if (! $res)
      throw new Exception('sqlDeleteCertReqIds() $query->execute(delete from cert_req_ids) error: ' . $db->lastErrorMsg());
    $query->close();
  }
}

function sqlDeleteCertReqIds($transactionID) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec, $sql_db, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlDeleteCertReqIds() pg_connect() error');
    deleteCertReqIds($transactionID, $db);
  } else {
    $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    deleteCertReqIds($transactionID, $db);
    $db->close();
  }
}
