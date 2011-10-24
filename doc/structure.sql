CREATE TABLE server (id integer primary key autoincrement, hostname text, port text, has_lb integer, has_waf integer, server text, lb text, waf text, use_ssl integer);
CREATE TABLE request (id integer primary key autoincrement, request text not null, notes text);
CREATE TABLE response (server_id integer, request_id integer, response text not null, time text not null, http_version text, code text);
