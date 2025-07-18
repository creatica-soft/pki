<?php

function sqlGetNonces($ip) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  $nonces = array();
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetNonces() pg_connect() error');
    $res = pg_query_params($db, 'select nonce from nonces where ip=$1;', array($ip));
    if (! $res) throw new Exception('sqlGetNonces() pg_query_params() error');
    while ($nonce = pg_fetch_assoc($res)) {
      $nonces[] = $nonce;      
    }
    if (! pg_free_result($res)) throw new Exception('sqlGetNonces() pg_free_result() error');
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('select nonce from nonces where ip=:ip;');
    if (! $query) {
      errorLog('sqlGetNonce() $db->prepare(select...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':ip', $ip, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlGetNonce() $query->bindValue(ip) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlGetNonce() $query->execute(select) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    while ($nonce = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $nonces[] = $nonce;
    }
    $query->close();
    $db->close();
  }
  if (count($nonces) == 0) return false;
  return $nonces;
}

function sqlSaveNonce($nonce, $ip) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $now, $nonce_expires_sec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSaveNonce() pg_connect() error');
    $res = pg_query_params($db, 'select nonce from nonces where nonce=$1;', array($nonce));
    if (! $res) throw new Exception('sqlSaveNonce() pg_query_params(select) error');
    $n = pg_fetch_assoc($res);
    if (! pg_free_result($res)) throw new Exception('sqlSaveNonce() pg_free_result() error');
    if ($n) return false; //nonce exists
    $res = pg_query_params($db, 'insert into nonces(nonce, ip, expires) values($1, $2, $3);', array($nonce, $ip, $now->getTimestamp() + $nonce_expires_sec));
    if (! $res) throw new Exception('sqlSaveNonce() pg_query_params(insert) error');
    if (! pg_free_result($res)) throw new Exception('sqlSaveNonce() pg_free_result() error');
  } else {  
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('select nonce from nonces where nonce=:nonce;');
    if (! $query) {
      errorLog('sqlSaveNonce() $db->prepare(select...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':nonce', $nonce, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlSaveNonce() $query->bindValue(nonce) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlSaveNonce() $query->execute(select...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $n = $res->fetchArray($mode = SQLITE3_ASSOC);
    $query->close();
    if ($n) return false; //nonce exists
  
    $query = $db->prepare('insert into nonces(nonce, ip, expires) values(:nonce, :ip, :expires);');
    if (! $query) {
      errorLog('sqlSaveNonce $db->prepare(insert...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':nonce', $nonce, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlSaveNonce() $query->bindValue(nonce) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':ip', $ip, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlSaveNonce() $query->bindValue(ip) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':expires', $now->getTimestamp() + $nonce_expires_sec, SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlSaveNonce() $query->bindValue(expires) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlSaveNonce() $query->execute(insert...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
    $db->close();
  }
  return true;
}

function sqlDeleteNonce($nonce) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlDeleteNonce() pg_connect() error');
    $res = pg_query_params($db, 'delete from nonces where nonce=$1;', array($nonce));
    if (! $res) throw new Exception('sqlDeleteNonce() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlDeleteNonce() pg_free_result() error');
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('delete from nonces where nonce = :nonce;');
    if (! $query) {
      errorLog('sqlDeleteNonce() $db->prepare(delete from nonces...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':nonce', $nonce, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlDeleteNonce() $query->bindValue(nonce) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlDeleteNonce() $query->execute(delete from nonces) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
    $db->close();
  }
}

function sqlDeleteNonces() {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path, $now;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlDeleteNonces() pg_connect() error');
    $res = pg_query_params($db, 'delete from nonces where expires < $1;', array($now->getTimestamp()));
    if (! $res) throw new Exception('sqlDeleteNonces() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlDeleteNonces() pg_free_result() error');
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    
    $query = $db->prepare('delete from nonces where expires < :now;');
    if (! $query) {
      errorLog('sqlDeleteNonces() $db->prepare(delete from nonces) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':now', $now->getTimestamp(), SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlDeleteNonces() $query->bindValue(now) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlDeleteNonces() $query->execute(delete from nonces) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
    $db->close();
  }
}

function getAccount($id, $jwk_hash, $kid, $db) {
  global $sql_db;
  if ($sql_db == 'postgres') {
    if (! is_null($jwk_hash)) {
      $res = pg_query_params($db, 'select * from accounts where jwk_hash = $1;', array($jwk_hash));
    } elseif (! is_null($id)) {
      $res = pg_query_params($db, 'select * from accounts where id = $1;', array($id));
    } elseif (! is_null($kid)) {
      $res = pg_query_params($db, 'select * from accounts where kid = $1;', array($kid));
    } else {
      errorLog('getAccount() error: at least one of arguments id or jwk_hash must not be null');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    if (! $res) throw new Exception('getAccount() pg_query_params() error');
    $account = pg_fetch_assoc($res);
    if ($account)
      $account['jwk'] = pg_unescape_bytea($account['jwk']);
    if (! pg_free_result($res)) throw new Exception('getAccount() pg_free_result() error');
  } else {
    if (! is_null($jwk_hash)) {
      $query = $db->prepare('select * from accounts where jwk_hash = :jwk_hash;');
      if (! $query) {
        errorLog('getAccount() $db->prepare(select from accounts...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':jwk_hash', $jwk_hash, SQLITE3_TEXT);
      if (! $res) {
        errorLog('getAccount() $query->bindValue(jwk_hash) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    } elseif (! is_null($id)) {
      $query = $db->prepare('select * from accounts where id = :id;');
      if (! $query) {
        errorLog('getAccount() $db->prepare(select from accounts...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
      if (! $res) {
        errorLog('getAccount() $query->bindValue(id) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    } elseif (! is_null($kid)) {
      $query = $db->prepare('select * from accounts where kid = :kid;');
      if (! $query) {
        errorLog('getAccount() $db->prepare(select from accounts...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':kid', $kid, SQLITE3_TEXT);
      if (! $res) {
        errorLog('getAccount() $query->bindValue(kid) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    } else {
      errorLog('getAccount() error: at least one of arguments id or jwk_hash must not be null');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('getAccount() $query->execute(select from accounts) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $account = $res->fetchArray($mode = SQLITE3_ASSOC); //returns false if there are no more rows
    $query->close();
  }
  return $account;
}

function sqlGetAccount($id, $jwk_hash = null, $kid = null) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetAccount() pg_connect() error');
    $account = getAccount($id, $jwk_hash, $kid, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $account = getAccount($id, $jwk_hash, $kid, $db);
    $db->close();
  }
  return $account;
}

function sqlSaveAccount($id, $status, $termsOfServiceAgreed, $jwk_hash, $kid, $jwk, $contacts, $externalAccountBinding) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSaveAccount() pg_connect() error');
    $account = getAccount($id, null, null, $db);
    if ($account) { //account exists
      $res = pg_query_params($db, 'update accounts set contacts = $1, "termsOfServiceAgreed" = $2 where id = $3;', array($contacts, $termsOfServiceAgreed, $id));
    } else { //new account
      $jwk = pg_escape_bytea($db, $jwk);
      $res = pg_query_params($db, 'insert into accounts(id, status, "termsOfServiceAgreed", jwk_hash, kid, jwk, contacts, "externalAccountBinding") values($1, $2, $3, $4, $5, $6, $7, $8);', array($id, $status, $termsOfServiceAgreed, $jwk_hash, $kid, $jwk, $contacts, $externalAccountBinding));
    }
    if (! $res) throw new Exception('sqlSaveAccount() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlSaveAccount() pg_free_result() error');
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $account = getAccount($id, null, null, $db);
    if ($account) { //account exists
      $query = $db->prepare('update accounts set contacts = :contacts, termsOfServiceAgreed = :termsOfServiceAgreed where id = :id;');
      if (! $query) {
        errorLog('sqlSaveAccount() $db->prepare(update accounts...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    } else { //new account
      $query = $db->prepare('insert into accounts(id, status, termsOfServiceAgreed, jwk_hash, kid, jwk, contacts, externalAccountBinding) values(:id, :status, :termsOfServiceAgreed, :jwk_hash, :kid, :jwk, :contacts, :externalAccountBinding);');
      if (! $query) {
        errorLog('sqlSaveAccount() $db->prepare(insert into accounts...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':jwk_hash', $jwk_hash, SQLITE3_TEXT);
      if (! $res) {
        errorLog('sqlSaveAccount() $query->bindValue(jwk) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':kid', $kid, SQLITE3_TEXT);
      if (! $res) {
        errorLog('sqlSaveAccount() $query->bindValue(kid) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':jwk', $jwk, SQLITE3_BLOB);
      if (! $res) {
        errorLog('sqlSaveAccount() $query->bindValue(jwk) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
      if (! $res) {
        errorLog('sqlSaveAccount() $query->bindValue(status) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':externalAccountBinding', $externalAccountBinding, SQLITE3_BLOB);
      if (! $res) {
        errorLog('sqlSaveAccount() $query->bindValue(kid) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlSaveAccount() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':contacts', $contacts, SQLITE3_BLOB);
    if (! $res) {
      errorLog('sqlSaveAccount() $query->bindValue(contacts) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':termsOfServiceAgreed', $termsOfServiceAgreed, SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlSaveAccount() $query->bindValue(termsOfServiceAgreed) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlSaveAccount() $query->execute(insert into accounts... or update accounts...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
    $db->close();
  }
}

function deleteAccount($id, $db) {
  global $sql_db;
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'delete from accounts where id = $1;', array($id));
    if (! $res) throw new Exception('deleteAccount() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('deleteAccount() pg_free_result() error');
 } else {
    $query = $db->prepare('delete from accounts where id = :id');
    if (! $query) {
      errorLog('deleteAccount() $db->prepare(delete from accounts...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('deleteAccount() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('deleteAccount() $query->execute(delete from accounts) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
  }
}

function sqlDeleteAccount($id) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSaveAccount() pg_connect() error');
    deleteAccount($id, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $res = $db->exec('PRAGMA foreign_keys = ON;');
    deleteAccount($id, $db);
    $db->close();
  }
}

function getOrder($id, $db) {
  global $sql_db;
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'select * from orders where id=$1;', array($id));
    if (! $res) throw new Exception('getOrder() pg_query_params() error');
    $order = pg_fetch_assoc($res);
    if ($order)
      $order['identifiers'] = pg_unescape_bytea($order['identifiers']);
    if (! pg_free_result($res)) throw new Exception('getOrder() pg_free_result() error');
  } else {
    $query = $db->prepare('select * from orders where id=:id;');
    if (! $query) {
      errorLog('getOrder() $db->prepare(select from orders...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('getOrder() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('getOrder() $query->execute(select from orders) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $order = $res->fetchArray($mode = SQLITE3_ASSOC);
    $query->close();
  }
  return $order;
}

function sqlGetOrder($id) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetOrder() pg_connect() error');
    $order = getOrder($id, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $order = getOrder($id, $db);
    $db->close();
  }
  return $order;
}

function sqlGetExpiredOrders() {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path, $now;
  $orders = array();
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetExpiredOrders() pg_connect() error');
    $res = pg_query_params($db, 'select id from orders where expires < $1;', array($now->getTimestamp()));
    if (! $res) throw new Exception('sqlGetExpiredOrders() pg_query_params() error');
    while($order = pg_fetch_assoc($res)) {
      $orders[] = $order;
    }
    if (! pg_free_result($res)) throw new Exception('sqlGetExpiredOrders() pg_free_result() error');
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $query = $db->prepare('select id from orders where expires < :now;');
    if (! $query) {
      errorLog('sqlGetExpiredOrders() $db->prepare(select from orders...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':now', $now->getTimestamp(), SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlGetExpiredOrders() $query->bindValue(now) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlGetExpiredOrders() $query->execute(select from orders) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    while ($order = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $orders[] = $order;
    }
    $query->close();
    $db->close();
  }
  if (count($orders) == 0) return false;
  return $orders;
}

function sqlSaveOrder($id, $status, $expires, $identifiers, $notBefore, $notAfter, $certSerial, $account) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  $orders = array();
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSaveOrder() pg_connect() error');
    $order = getOrder($id, $db);
    if ($order) {
      $res = pg_query_params($db, 'update orders set status = $1, expires = $2, "certSerial" = $3 where id = $4;', array($status, $expires, $certSerial, $id));
    } else {
      $identifiers = pg_escape_bytea($db, $identifiers);
      $res = pg_query_params($db, 'insert into orders(id, status, expires, identifiers, "notBefore", "notAfter", "certSerial", account) values($1, $2, $3, $4, $5, $6, $7, $8);', array($id, $status, $expires, $identifiers, $notBefore, $notAfter, $certSerial, $account));
    }
    if (! $res) throw new Exception('sqlSaveOrder() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlSaveOrder() pg_free_result() error');
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $res = $db->exec('PRAGMA foreign_keys = ON;');
    if (! $res) {
      errorLog('sqlSaveOrder() $db->exec(PRAGMA foreign_keys = ON;');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $order = getOrder($id, $db);
    if ($order) {
      $query = $db->prepare('update orders set status = :status, expires = :expires, certSerial = :certSerial where id = :id;');
      if (! $query) {
        errorLog('sqlSaveOrder() $db->prepare(update accounts...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    } else {
      $query = $db->prepare('insert into orders(id, status, expires, identifiers, notBefore, notAfter, certSerial, account) values(:id, :status, :expires, :identifiers, :notBefore, :notAfter, :certSerial, :account);');
      if (! $query) {
        errorLog('sqlSaveOrder() $db->prepare(insert into accounts...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':identifiers', $identifiers, SQLITE3_BLOB);
      if (! $res) {
        errorLog('sqlSaveOrder() $query->bindValue(identifiers) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':notBefore', $notBefore, SQLITE3_INTEGER);
      if (! $res) {
        errorLog('sqlSaveOrder() $query->bindValue(notBefore) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':notAfter', $notAfter, SQLITE3_INTEGER);
      if (! $res) {
        errorLog('sqlSaveOrder() $query->bindValue(notAfter) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':account', $account, SQLITE3_TEXT);
      if (! $res) {
        errorLog('sqlSaveOrder() $query->bindValue(account) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlSaveOrder() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlSaveOrder() $query->bindValue(status) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':expires', $expires, SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlSaveOrder() $query->bindValue(expires) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':certSerial', $certSerial, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlSaveOrder() $query->bindValue(certSerial) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlSaveOrder() $query->execute(insert into orders... or update orders...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
    $db->close();
  }
}

function deleteOrder($id, $db) {
  global $sql_db;
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'delete from orders where id = $1;', array($id));
    if (! $res) throw new Exception('deleteOrder() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('deleteOrder() pg_free_result() error');
  } else {
    $query = $db->prepare('delete from orders where id = :id');
    if (! $query) {
      errorLog('deleteOrder() $db->prepare(delete from orders...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('deleteOrder() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('deleteOrder() $query->execute(delete from orders) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
  }
}

function sqlDeleteOrder($id) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlDeleteOrder() pg_connect() error');
    deleteOrder($id, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $res = $db->exec('PRAGMA foreign_keys = ON;');
    if (! $res) {
      errorLog('sqlDeleteOrder() $db->exec(PRAGMA foreign_keys = ON;');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    deleteOrder($id, $db);
    $db->close();
  }
}

function getAuthorization($id, $db) {
  global $sql_db;
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'select * from authorizations where id=$1;', array($id));
    if (! $res) throw new Exception('getAuthorization() pg_query_params() error');
    $authorization = pg_fetch_assoc($res);
    if ($authorization)
      $authorization['identifier'] = pg_unescape_bytea($authorization['identifier']);
    if (! pg_free_result($res)) throw new Exception('getAuthorization() pg_free_result() error');
  } else {
    $query = $db->prepare('select * from authorizations where id=:id;');
    if (! $query) {
      errorLog('getAuthorization() $db->prepare(select from authorizations...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('getAuthorization() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('getAuthorization() $query->execute(select from authorizations) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $authorization = $res->fetchArray($mode = SQLITE3_ASSOC);
    $query->close();
  }
  return $authorization;
}

function getAuthorizations($orderID, $db) {
  global $sql_db;
  $authorizations = array();
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'select * from authorizations where id=$1;', array($id));
    if (! $res) throw new Exception('getAuthorizations() pg_query_params() error');
    while ($authorization = pg_fetch_assoc($res)) {
      $authorization['identifier'] = pg_unescape_bytea($authorization['identifier']);
      $authorizations[] = $authorization;
    }
    if (! pg_free_result($res)) throw new Exception('getAuthorizations() pg_free_result() error');
  } else {
    $query = $db->prepare('select * from authorizations where "order"=:order;');
    if (! $query) {
      errorLog('getAuthorizations() $db->prepare(select from authorizations...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':order', $orderID, SQLITE3_TEXT);
    if (! $res) {
      errorLog('getAuthorizations() $query->bindValue(order) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('getAuthorizations() $query->execute(select from authorizations) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    while ($authorization = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $authorizations[] = $authorization;
    }
    $query->close();
  }
  if (count($authorizations) == 0) return false;
  return $authorizations;
}

function sqlGetAuthorization($id) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetAuthorization() pg_connect() error');
    $authorization = getAuthorization($id, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $authorization = getAuthorization($id, $db);
    $db->close();
  }
  return $authorization;
}

function sqlGetAuthorizations($orderID) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetAuthorizations() pg_connect() error');
    $authorizations = getAuthorizations($orderID, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $authorizations = getAuthorizations($orderID, $db);
    $db->close();
  }
  return $authorizations;
}

function sqlSaveAuthorization($id, $identifier, $status, $expires, $wildcard, $order) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSaveAuthorization() pg_connect() error');
    $authorization = getAuthorization($id, $db);
    if ($authorization) {
      $res = pg_query_params($db, 'update authorizations set status = $1, expires = $2 where id = $3;', array($status, $expires, $id));
    } else {
      $identifier = pg_escape_bytea($db, $identifier);
      $res = pg_query_params($db, 'insert into authorizations(id, identifier, status, expires, wildcard, "order") values($1, $2, $3, $4, $5, $6);', array($id, $identifier, $status, $expires, $wildcard, $order));    
    }
    if (! $res) throw new Exception('sqlSaveAuthorization() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlSaveAuthorization() pg_free_result() error');
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $res = $db->exec('PRAGMA foreign_keys = ON;');
    if (! $res) {
      errorLog('sqlSaveAuthorization() $db->exec(PRAGMA foreign_keys = ON;');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $authorization = getAuthorization($id, $db);
    if ($authorization) {
      $query = $db->prepare('update authorizations set status = :status, expires = :expires where id = :id;');
      if (! $query) {
        errorLog('sqlSaveAuthorization() $db->prepare(update authorizations...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    } else {
      $query = $db->prepare('insert into authorizations(id, identifier, status, expires, wildcard, "order") values(:id, :identifier, :status, :expires, :wildcard, :order);');
      if (! $query) {
        errorLog('sqlSaveAuthorization() $db->prepare(insert into authorizations...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':identifier', $identifier, SQLITE3_BLOB);
      if (! $res) {
        errorLog('sqlSaveAuthorization() $query->bindValue(identifier) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':wildcard', $wildcard, SQLITE3_INTEGER);
      if (! $res) {
        errorLog('sqlSaveAuthorization() $query->bindValue(wildcard) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':order', $order, SQLITE3_TEXT);
      if (! $res) {
        errorLog('sqlSaveAuthorization() $query->bindValue(order) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlSaveAuthorization() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlSaveAuthorization() $query->bindValue(status) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':expires', $expires, SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlSaveAuthorization() $query->bindValue(expires) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlSaveAuthorization() $query->execute(insert into authorizations... or update authorizations...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
    $db->close();
  }
}

function deleteAuthorization($id, $db) {
  global $sql_db;
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'delete from accounts where id = $1;', array($id));
    if (! $res) throw new Exception('deleteAuthorization() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('deleteAuthorization() pg_free_result() error');
  } else {
    $query = $db->prepare('delete from accounts where id = :id');
    if (! $query) {
      errorLog('deleteAuthorization() $db->prepare(delete from authorizations...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('deleteAuthorization() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('deleteAuthorization() $query->execute(delete from authorizations) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
  }
}

function sqlDeleteAuthorization($id) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlDeleteAuthorization() pg_connect() error');
    deleteAuthorization($id, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $res = $db->exec('PRAGMA foreign_keys = ON;');
    if (! $res) {
      errorLog('sqlDeleteAuthorization() $db->exec(PRAGMA foreign_keys = ON;');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    deleteAuthorization($id, $db);
    $db->close();
  }
}

function getChallenge($id, $db) {
  global $sql_db;
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'select * from challenges where id=$1;', array($id));
    if (! $res) throw new Exception('getChallenge() pg_query_params() error');
    $challenge = pg_fetch_assoc($res);
    if (! pg_free_result($res)) throw new Exception('getChallenge() pg_free_result() error');
  } else {
    $query = $db->prepare('select * from challenges where id=:id;');
    if (! $query) {
      errorLog('getChallenge() $db->prepare(select from challenges...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('getChallenge() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('getChallenge() $query->execute(select from challenges) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $challenge = $res->fetchArray($mode = SQLITE3_ASSOC);
    $query->close();
  }
  return $challenge;
}

function getChallenges($authorization, $db) {
  global $sql_db;
  $challenges = array();
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'select * from challenges where "authorization" = $1;', array($authorization));
    if (! $res) throw new Exception('getChallenges() pg_query_params() error');
    while ($challenge = pg_fetch_assoc($res)) {
      $challenges[] = $challenge;
    }
    if (! pg_free_result($res)) throw new Exception('getChallenges() pg_free_result() error');
  } else {
    $query = $db->prepare('select * from challenges where authorization=:authorization;');
    if (! $query) {
      errorLog('getChallenge() $db->prepare(select from challenges...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':authorization', $authorization, SQLITE3_TEXT);
    if (! $res) {
      errorLog('getChallenge() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('getChallenge() $query->execute(select from challenges) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    while ($challenge = $res->fetchArray($mode = SQLITE3_ASSOC)) {
      $challenges[] = $challenge;
    }
    $query->close();
  }
  return $challenges;
}

function sqlGetChallenge($id) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetChallenge() pg_connect() error');
    $challenge = getChallenge($id, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $challenge = getChallenge($id, $db);
    $db->close();
  }
  return $challenge;
}

function sqlGetChallenges($authorization) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlGetChallenges() pg_connect() error');
    $challenges = getChallenges($authorization, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READONLY);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $challenges = getChallenges($authorization, $db);
    $db->close();
  }
  if (count($challenges) == 0) return false;
  return $challenges;
}

function sqlSaveChallenge($id, $type, $base_url, $status, $token, $error, $validated, $authorization) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlSaveChallenge() pg_connect() error');
    $challenge = getChallenge($id, $db);
    if ($challenge) {
      $res = pg_query_params($db, 'update challenges set status = $1, error = $2, validated = $3 where id = $4;', array($status, $error, $validated, $id));
    } else {
      $res = pg_query_params($db, 'insert into challenges(id, type, url, status, token, error, validated, "authorization") values($1, $2, $3, $4, $5, $6, $7, $8);', array($id, $type, $base_url, $status, $token, $error, $validated, $authorization));
    }
    if (! $res) throw new Exception('sqlSaveChallenge() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('sqlSaveChallenge() pg_free_result() error');
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $res = $db->exec('PRAGMA foreign_keys = ON;');
    if (! $res) {
      errorLog('sqlSaveChallenge() $db->exec(PRAGMA foreign_keys = ON;');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $challenge = getChallenge($id, $db);
    if ($challenge) {
      $query = $db->prepare('update challenges set status = :status, error = :error, validated = :validated where id = :id;');
      if (! $query) {
        errorLog('sqlSaveChallenge() $db->prepare(update challenges...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    } else {
      $query = $db->prepare('insert into challenges(id, type, url, status, token, error, validated, authorization) values(:id, :type, :url, :status, :token, :error, :validated, :authorization);');
      if (! $query) {
        errorLog('sqlSaveChallenge() $db->prepare(insert into challenges...) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':type', $type, SQLITE3_TEXT);
      if (! $res) {
        errorLog('sqlSaveChallenge() $query->bindValue(type) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':url', $base_url, SQLITE3_TEXT);
      if (! $res) {
        errorLog('sqlSaveChallenge() $query->bindValue(url) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':token', $token, SQLITE3_TEXT);
      if (! $res) {
        errorLog('sqlSaveChallenge() $query->bindValue(token) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
      $res = $query->bindValue(':authorization', $authorization, SQLITE3_TEXT);
      if (! $res) {
        errorLog('sqlSaveChallenge() $query->bindValue(authorization) error: ' . $db->lastErrorMsg());
        throw new AcmeException('serverInternal', 'Internal Server Error', 500);
      }
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlSaveChallenge() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':status', $status, SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlSaveChallenge() $query->bindValue(status) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':error', $error, SQLITE3_TEXT);
    if (! $res) {
      errorLog('sqlSaveChallenge() $query->bindValue(error) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':validated', $validated, SQLITE3_INTEGER);
    if (! $res) {
      errorLog('sqlSaveChallenge() $query->bindValue(validated) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('sqlSaveChallenge() $query->execute(insert into challenges... or update challenges...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
    $db->close();
  }
}

function deleteChallenge($id, $db) {
  global $sql_db;
  if ($sql_db == 'postgres') {
    $res = pg_query_params($db, 'delete from challenges where id = $1;', array($id));
    if (! $res) throw new Exception('deleteChallenge() pg_query_params() error');
    if (! pg_free_result($res)) throw new Exception('deleteChallenge() pg_free_result() error');
  } else {
    $query = $db->prepare('delete from challenges where id = :id');
    if (! $query) {
      errorLog('deleteChallenge() $db->prepare(delete from challenges...) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->bindValue(':id', $id, SQLITE3_TEXT);
    if (! $res) {
      errorLog('deleteChallenge() $query->bindValue(id) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $res = $query->execute();
    if (! $res) {
      errorLog('deleteChallenge() $query->execute(delete from challenges) error: ' . $db->lastErrorMsg());
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    $query->close();
  }
}

function sqlDeleteChallenge($id) {
  global $sql_db, $acme_db, $sqlite3_busy_timeoute_msec, $pg_con, $pg_encrypted_pass, $signing_ca_privkey_path;
  if ($sql_db == 'postgres') {
    $pass = '';
    openssl_private_decrypt(hex2bin($pg_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
    $pg_con = str_replace('postgres_password', $pass, $pg_con);
    $db = pg_connect($pg_con);
    if (! $db) throw new Exception('sqlDeleteChallenge() pg_connect() error');
    deleteChallenge($id, $db);
  } else {
    $db = new SQLite3($acme_db,  SQLITE3_OPEN_READWRITE);
    $db->busyTimeout($sqlite3_busy_timeoute_msec);
    $res = $db->exec('PRAGMA foreign_keys = ON;');
    if (! $res) {
      errorLog('sqlDeleteChallenge() $db->exec(PRAGMA foreign_keys = ON;');
      throw new AcmeException('serverInternal', 'Internal Server Error', 500);
    }
    deleteChallenge($id, $db);
    $db->close();
  }
}
