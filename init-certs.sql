create table if not exists certs(serial TEXT PRIMARY KEY ASC, status INTEGER, revocationReason INTEGER, revocationDate INTEGER, notBefore INTEGER, notAfter INTEGER, subject TEXT, owner TEXT, role TEXT, cert BLOB, cn TEXT, fingerprint TEXT, sHash TEXT, iAndSHash TEXT, sKIDHash TEXT);
CREATE INDEX if not exists subj_idx on certs(subject); CREATE INDEX status_idx on certs(status); CREATE INDEX from_idx on certs(notBefore);
CREATE INDEX if not exists to_idx on certs(notAfter); CREATE INDEX owner_idx on certs(owner); CREATE INDEX role_idx on certs(role);
CREATE INDEX if not exists cn_idx on certs(cn); CREATE INDEX fingerprint_idx on certs(fingerprint); CREATE INDEX sHash_idx on certs(sHash);
CREATE INDEX if not exists iAndSHash_idx on certs(iAndSHash); CREATE INDEX sKIDHash_idx on certs(sKIDHash);
create table if not exists cert_req_ids(serial TEXT PRIMARY KEY ASC, certReqId TEXT, timestamp INTEGER, nonce TEXT, transactionID TEXT);
CREATE INDEX if not exists certReqId_idx on cert_req_ids(certReqId); CREATE INDEX transactionID_idx on cert_req_ids(transactionID);
create table keys(kid TEXT PRIMARY KEY ASC, key TEXT);