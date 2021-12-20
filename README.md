### tips

此扩展是一个最基本的PostgreSQL extension，没有hook钩子等用法。
可以直接整合进PostgreSQL的contrib目录中。

eds--1.0.sql	创建了一个表，创建了查询此表的一个函数。
eds.c		实现了此函数。



postgresql.conf
`shared_preload_libraries = 'eds'`
