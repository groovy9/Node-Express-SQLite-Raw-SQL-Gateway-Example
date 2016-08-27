# SQLite raw SQL REST API

You know how sometimes, you start to write a REST API, but decide you really want to skip the abstraction and just talk SQL via Ajax?  Me too.

This repository is just a single JS file that you run with node.js (or PM2 or similar) and gives you a simple 
but powerful REST-ish API with only two routes: One for authenticating and one for POSTing SQL queries.

### Features

1. No traditional REST API nonsense with a slew of GET/PUT/POST/DELETE routes
2. Simply POST to a single URL with an array of SQL commands in the body in JSON format
3. Get back a JSON array with the results of each query
4. SQL queries can reference the lastID of previous queries for chaining
   together in a single API call multiple queries that depend on each other
5. Arrays of queries are wrapped in transactions for data integrity.  If any query in the array fails, nothing is committed.
6. Provide security with Bcrypt authentication against a passwords database table, then including
   JWT tokens with subsequent queries
7. Enforce per-user per-table read/write permissions by parsing the supplied SQL
8. By default, limits the number of rows returned by selects to keep performance snappy
9. Relies on a small number of well-tested NPM packages 

### Setup

1. Grab the api.js file
2. Install some NPM packages: `npm install express bcrypt promise co sqlite3 jwt-simple body-parser`
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
Fire it up:
```
node api.js
```
Authenticate: 
```
auth="Authorization: Bearer `curl -s localhost:3000/auth -H "content-type:application/json" --data '{"user":"bob","pass":"abc123"}' |sed -e 's/\"//g'`"
```
Query:
```
curl -s localhost:3000/sql -H "content-type:application/json" -H "$auth" --data '[{"sql":"insert into test (stuff) values (?)","args":[2345]},{"sql":"insert into test (stuff) values (?)","args":["@lastID"]}]'
````
Check the results:
```
sqlite3 test.db 'select * from test'
```
Tweak the configurable top section of api.js to taste and consider running with the something like PM2.


### SQL Format

Queries are passed in JSON format in the body of the POST.  The structure is below, but this would need to be converted to JSON before sending.

```
[
  { sql: 'insert into test (stuff) values (?)', args: ['blah blah'] },
  { sql: 'insert into test (stuff) values (?)', args: ['@lastID'] }, // inserts row id from the insert of 'blah blah' above
  { sql: 'insert into test (stuff) values (?)', args: ['foo bar baz'] },
  { sql: 'insert into test (stuff) values (?)', args: [9] },
  { sql: 'insert into test (stuff) values (?)', args: ['@lastID2'] }, // inserts the row id from the insert of 'foo bar baz'
  { sql: 'select * from test where stuff = ? or stuff = ?', args: [9, '@lastID2'] }
]
```

A single query can dispense with the array:

```
{ sql: 'insert into test (stuff) values (?)', args: ['whatever'] }
```

### Results Format

The result on success is an array of arrays lined up with the query array

```
[
  [{id:1, stuff: "some stuff"}], // first query, select results
  [{id:1, stuff: "some stuff"},{id:2,stuff:"123"}], // second query
  [{sql: "insert into test (stuff) values (?)", lastID:7, changes:1}] // non-select results
] 
```

### Error format

On any kind of failure, the HTTP return code is set to 4XX and the body of the response is a string with the error message.

### Limitations

1. Does not currently parse subqueries and enforce permissions accordingly. e.g.  `insert into ... select from ...`
2. Is not a complete implementation of the SQLite dialect.  Only aware of insert/delete/select/update with no WITH clauses
3. Slow queries block the thread, so by default, select statements are modified with a configurable 'limit' clause.  
4. HTTP return codes are simplistic - 200 for ok, 401 for authentication failure, and 400 for any other failure
