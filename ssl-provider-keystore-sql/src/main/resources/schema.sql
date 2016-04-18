create table versions
(
	table_name varchar(128) not null,
	version int not null,
	primary key(table_name)
);

create table integrity
(
	id bigint not null,
	salt varchar(128) not null, 
	iv varchar(128) not null, 
	data varchar(256) not null, 
	data_hash varchar(64) not null, 
	primary key(id)
);

create table entries
(
	alias_hash varchar(64) not null,
	entry_type int default 0,
	alias varchar(256) not null,
	creation_date bigint default 0,
	algorithm varchar(32),
	data text not null,
	protection_key text default null,
	protection_param varchar(128) default null,
	primary key(alias_hash),
	key (algorithm)
);

create table certificate_chains
(
	alias_hash varchar(64) not null,
	rank int default 0, 
	data text not null, 
	primary key (alias_hash, rank)
);

create table names
(
	alias_hash varchar(64) not null,
	name_hash varchar(64) not null,
	name varchar(256) not null,
	primary key(alias_hash, name_hash),
	key (name_hash)
);
