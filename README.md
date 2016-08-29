# SQLite Raw SQL Ajax API

For small projects, developing a full REST API can be overkill.  This code is intended to accelerate front end development by removing the need to simultaneously develop a back end API while building your front end.  Develop your front end with plain old SQL and when you're ready for production, it's a snap to move your SQL into traditional REST API routes if desired.

By default, you get an API with only two routes: One for authenticating and one for POSTing SQL queries.

For the security-conscious thinking "What about SQL injection?" Security can range from poor to excellent depending on how you configure it.  See the security section below.

### Features

1. Simply POST to a single URL with an array of SQL commands in the body in JSON format and get back an array of results
2. SQL queries can reference the lastID of previous queries for chaining
   together in a single API call multiple queries that depend on each other
3. Arrays of queries are wrapped in transactions for data integrity.  If any query in the array fails, nothing is committed.
4. Security via bcrypt password authentication, JWT tokens, complete SQL parsing
5. Enforce per-user per-table read/write permissions by parsing the supplied SQL including joins, subqueries
6. By default, limits the number of rows returned by selects to keep performance snappy

### Setup

1. Grab the api.js file
2. Install some NPM packages: `npm install express bcrypt promise co sqlite3 jwt-simple body-parser sqlite-parser`
3. Create the database (paste this into a terminal)
```
sqlite3 test.db <<EOF
pragma journal_mode=wal;
create table permissions (user text not null, tbl text not null, read integer not null default 0, write integer not null default 0) ;
insert into permissions (user, tbl, read, write) values ("bob", "test", 1, 1);
create table test (id integer primary key autoincrement, stuff text) ;
insert into test (stuff) values ("some stuff");
insert into test (stuff) values (123);
create table knownqueries (query text primary key);
create table passwords (user text not null primary key, pass text not null);
insert into passwords (user, pass) values ('bob', '\$2a\$10\$Inlwwxmlv8MSoUN0k1Z1fOvRpXDi24RrhFP.0CiSNCMIWGgLMn4nu');
EOF
```
Fire it up:
```
node api.js
```
In another terminal, create a JSON content type header to pass to Curl:
```
json="content-type:application/json" 

```
Authenticate and store token in a variable:
```
auth="Authorization: Bearer `curl -s localhost:3000/auth -H "$json" --data '{"user":"bob","pass":"abc123"}' |sed -e 's/\"//g'`"

````
Create some SQL in JSON format:
```
twoinserts='[{"sql":"insert into test (stuff) values (?)","args":[2345]},{"sql":"insert into test (stuff) values (?)","args":["@lastID"]}]'
select='[{"sql":"select * from test"}]'
permissiondenied='[{"sql":"select * from test join passwords"}]'

```
Query:
```
echo -e "\n" `curl -s localhost:3000/sql -H "$json" -H "$auth" --data "$twoinserts"` "\n\n"
echo -e "\n" `curl -s localhost:3000/sql -H "$json" -H "$auth" --data "$select"` "\n\n"
echo -e "\n" `curl -s localhost:3000/sql -H "$json" -H "$auth" --data "$permissiondenied"` "\n\n"

````
Tweak the configurable top section of api.js to taste and consider running with it something like PM2.


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

### Security

The obvious concern is SQL injection, specifically a malicious user going around your front end and manually running SQL to modify tables he has write access to.  

To mitigate this, there's a flag in the config section called freezeQueries that defaults to false.  When false, we store every new query in a known queries table minus placeholder args.  e.g. "select foo from bar where baz = ?".  As most front ends will have a finite number of queries, once you've run through every operation your front end can do, set freezeQueries to true and users will then be unable to run any custom SQL.

If this isn't enough, the raw SQL route can be disabled in lieu of traditional REST API routes before moving to production. See the next section below.

As authentication uses JWT and doesn't store it in cookies, Cross-site request forgery (CSRF) is not a concern.

### Traditional REST API for production

You may choose to only use the raw SQL API for rapid development, but need a traditional API for production.  This is easily accomplished by adding route modules to the 'routes' subdirectory with the following format.  When present, they'll be automatically included by api.js.

```
// routes/widget.js
module.exports = function(app, safeQuery) {
  app.get('/widget/:id', function(req, res) {
    var sql = [{ sql: 'select * from widgets where id = ?', args: [req.params.id] },
               { sql: 'select * from widgetusers where widget = ?', args: [req.params.id] }]
    
    // safeQuery enforces authentication and permissions automagically   
    return safeQuery(req, res, sql)
  })
}
```

See the Express documentation for creating routes.  safeQuery() takes your SQL object, ensures you're authenticated via JWT, parses your SQL, ensures you have permission to read or write the requested tables, runs the query and returns the results or the error.

### Limitations

1. Is not a complete implementation of the SQLite dialect.  Only allows insert/delete/select/update to cover typical CRUD operations
2. Slow queries block the thread (because Javascript), so by default, select statements are modified on the fly with a configurable 'limit' clause.  
3. HTTP return codes are simplistic - 200 for ok, 401 for authentication failure, and 400 for any other failure
4. SSL is not enabled by default. For production, put it behind a Nginx reverse proxy or refer to the Express docs for enabling SSL and generating certificates.


### Populating the passwords table

By default, a /bcrypt route is enabled that spits out password hashes for supplied passwords:

```
curl --data '{"password":"foobar"}' -H "content-type:application/json" localhost:3000/bcrypt
```

Just take the string you get from that URL (minus any enclosing quotes), put it in the 'pass' column of the passwords table and then you can authenticate with the password 'foobar'
