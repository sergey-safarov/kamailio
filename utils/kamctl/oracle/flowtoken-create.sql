CREATE TABLE flowtoken (
    id NUMBER(10) PRIMARY KEY,
    key_name VARCHAR2(64) DEFAULT '',
    key_type NUMBER(10) DEFAULT 0 NOT NULL,
    value_type NUMBER(10) DEFAULT 0 NOT NULL,
    key_value VARCHAR2(128) DEFAULT '',
    expires NUMBER(10) DEFAULT 0 NOT NULL
);

CREATE OR REPLACE TRIGGER flowtoken_tr
before insert on flowtoken FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END flowtoken_tr;
/
BEGIN map2users('flowtoken'); END;
/
INSERT INTO version (table_name, table_version) values ('flowtoken','2');

