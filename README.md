# SQLite raw SQL REST API

You know how sometimes, you start to write a REST API, but decide you really want to skip the abstraction and just talk SQL?  Me too.

This repository is just a single JS file that you run with node.js and gives you a simple 
but powerful REST-ish API with only two routes: One for authenticating and one for
POSTing SQL queries.

###Features: 

1. No traditional REST API nonsense with slew of GET/PUT/POST/DELETE routes
2. Simly POST to a single URL with an array of SQL commands in the body in JSON format
3. Get back a JSON array with the results of each query
4. SQL queries can reference the lastID of previous queries for chaining
   together in a single APi call multiple queries that depend on each other
5. Arrays of queries are wrapped in transactions for data integrity
6. Provide security with Bcrypt authentication against a passwords database table, then including
   JWT tokens with subsequent queries
7. Enforce per-user per-table read/write permissions by parsing the supplied SQL



