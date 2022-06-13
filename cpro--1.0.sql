\echo Use "CREATE EXTENSION cpro '1.0'" to load this file. \quit
CREATE SCHEMA cpro;


CREATE TABLE cpro.cpro_info
(
	cpuinfotime	timestamp	NOT NULL,
	cpuinfo		text		NOT NULL
);


CREATE FUNCTION what_is_cpro()
RETURNS text
LANGUAGE C STRICT
AS 'MODULE_PATHNAME', 'what_is_cpro';


CREATE FUNCTION cpro_query
(
	IN	aaa			timestamp,
    OUT cap_time    timestamp,
    OUT pid_num     bigint,
    OUT cpu_num     int
)
RETURNS record
LANGUAGE C STRICT
AS 'MODULE_PATHNAME', 'cpro_query';


CREATE FUNCTION crosstab(text)
RETURNS setof record
AS 'MODULE_PATHNAME','crosstab'
LANGUAGE C STABLE STRICT;


CREATE TYPE cpro.cpro_crosstab_2 AS
(
	row_name	TEXT,
	category_1	TEXT,
	category_2	TEXT
);

CREATE FUNCTION crosstab2(text)
RETURNS setof cpro.cpro_crosstab_2
AS 'MODULE_PATHNAME','crosstab'
LANGUAGE C STABLE STRICT;


CREATE FUNCTION cpro_time(
	IN	start_time		timestamp,
	IN	end_time		timestamp,
	OUT cpu_num			int,
	OUT pid_num_time1	int,
	OUT pid_num_time2	int,
	OUT pid_variation	int
)
RETURNS SETOF record
LANGUAGE C STRICT
AS 'MODULE_PATHNAME', 'cpro_time';


