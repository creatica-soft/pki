<?php

function getCertReqIds($transactionID, $db) {
  $query = $db->prepare("select * from cert_req_ids where transactionID=:transactionID;");
  if (! $query)
    throw new Exception('getCertReqIds() $db->prepare(select from cert_req_ids...) error: ' . $db->lastErrorMsg());
  $res = $query->bindValue(':transactionID', $transactionID, SQLITE3_TEXT);
  if (! $res)
    throw new Exception('getCertReqIds() $query->bindValue(transactionID) error: ' . $db->lastErrorMsg());
  $res = $query->execute();
  if (! $res)
    throw new Exception('getCertReqIds() $query->execute(select from cert_req_ids) error: ' . $db->lastErrorMsg());
  $certReqIds = array();
  $certReqId = $res->fetchArray($mode = SQLITE3_ASSOC);
  while ($certReqId) {
    $certReqIds[] = $certReqId;
    $certReqId = $res->fetchArray($mode = SQLITE3_ASSOC);
  }
  $query->close();
  if (count($certReqIds) == 0) return false;
  return $certReqIds;
}

function sqlGetCertReqIds($transactionID) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
  $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READONLY);
  $db->busyTimeout($sqlite3_busy_timeoute_msec);
  $certReqIds = getCertReqIds($transactionID, $db);
  $db->close();
  return $certReqIds;
}

function sqlSaveCertReqIds($serial, $certReqId, $timestamp, $nonce, $transactionID) {
  global $now, $sqlite_db, $sqlite3_busy_timeoute_msec, $confirm_wait_time_sec;
  $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
  $db->busyTimeout($sqlite3_busy_timeoute_msec);
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

function deleteCertReqIds($transactionID, $db) {
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

function sqlDeleteCertReqIds($transactionID) {
  global $sqlite_db, $sqlite3_busy_timeoute_msec;
  $db = new SQLite3($sqlite_db,  SQLITE3_OPEN_READWRITE);
  $db->busyTimeout($sqlite3_busy_timeoute_msec);
  deleteCertReqIds($transactionID, $db);
  $db->close();
}

?>