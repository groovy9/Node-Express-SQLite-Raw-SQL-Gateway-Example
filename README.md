# SQLite raw SQL REST API

You know how sometimes, you start to write a REST API, but decide you really want to skip the abstraction and just talk SQL?  Me too.

This repository is just a single JS file that you run with node.js and gives you a simple 
but powerful REST-ish API with only two routes: One for authenticating and one for
POSTing SQL queries.

### Features

1. No traditional REST API nonsense with slew of GET/PUT/POST/DELETE routes
2. Simly POST to a single URL with an array of SQL commands in the body in JSON format
3. Get back a JSON array with the results of each query
4. SQL queries can reference the lastID of previous queries for chaining
   together in a single APi call multiple queries that depend on each other
5. Arrays of queries are wrapped in transactions for data integrity
6. Provide security with Bcrypt authentication against a passwords database table, then including
   JWT tokens with subsequent queries
7. Enforce per-user per-table read/write permissions by parsing the supplied SQL
8. Relies on a small number of well-tested NPM packages 

### Setup

1. Grab the api.js file
2. Install some NPM packages: `npm install express bcrypt promise co sqlite3 jwt-simple`
3. Create the database (paste this into a terminal)
```
sqlite3 test.db <<EOF
pragma journal_mode=wal;

create table permissions (user text not null, tbl text not null, read integer not null default 0, write integer not null default 0) ;
insert into permissions (user, tbl, read, write) values ("bob", "test", 1, 1);

create table test (id integer primary key autoincrement, stuff text) ;
insert into test (stuff) values ("some stuff");
insert into test (stuff) values (123);

create table passwords (user text not null primary key, pass text not null);
insert into passwords (user, pass) values ('bob', '\$2a\$10\$Inlwwxmlv8MSoUN0k1Z1fOvRpXDi24RrhFP.0CiSNCMIWGgLMn4nu');
EOF
```
4. Fire it up: `node api.js`
5. Authenticate: 
```
auth="Authorization: Bearer `curl -s localhost:3000/auth -H "content-type:application/json" --data '{"user":"bob","pass":"abc123"}' |sed -e 's/\"//g'`"
```
6. Query:
```
curl -s localhost:3000/sql -H "content-type:application/json" -H "$auth" --data '[{"sql":"insert into test (stuff) values (?)","args":[2345]},{"sql":"insert into test (stuff) values (?)","args":["@lastID"]}]'
````
7. Check the results:
```
sqlite3 test.db 'select * from test'
```
