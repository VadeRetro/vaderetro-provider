drop table if exists keystore_entries, keystore_metadata;
create table keystore_metadata (major_version int not null, version varchar(64) not null, salt varchar(128) not null, iv varchar(256) not null, key_iv varchar(256) not null, key_iv_hash varchar(256) not null, primary key (major_version));
create table keystore_entries  (alias varchar(256) not null, entry_type int default 0, rank int default 0, creation_date bigint default 0, algorithm varchar(256), data text not null, primary key (alias, entry_type, rank));
