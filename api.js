'use strict'
var express = require('express')
var bcrypt = require('bcrypt')
var Promise = require('promise')
var co = require('co')
var sqlite3 = require('sqlite3')
var jwt = require('jwt-simple')

///////////////////////////////////////////////////
//  user configurable section
//
var dbFile = 'test.db',
  permissionsTable = 'permissions',
  passwordsTable = 'passwords',
  JWTDuration = 1440, // JWT tokens are good for this many *minutes*
  enforceJWTDuration = true,
  // enable special /bcrypt route to generating password hashes to store in the database
  // e.g.
  // curl --data '{"password":"foobar"}' -H "content-type:application/json" localhost:3000/bcrypt
  enableBcryptRoute = true,
  bcryptPath = '/bcrypt',
  authPath = '/auth',
  SQLPath = '/sql',
  port = 3000,
  JWTSecret = 'ChangeMeToSomethingLongAndRandom', // used to encrypt/decrypt JWT tokens.
  freezeQueries = false, // disallow any queries that haven't been run before and stored in knownQueriesTable 
  knownQueriesTable = 'knownqueries'
 
// security alert.  this app is vulnerable to malicious users going around the
// front end and doing unexpected queries on tables they have write access to.
// to prevent this, we store every query (minus placeholder args) in knownQueriesTable 
// until freezeQueries above is set to true, at which point we stop allowing any
// new queries.  As most front ends will have a finite set of queries, this 
// effectively locks down the database to "safe" queries.  A user could still
// run a safe query with custom args, but this is much less potential damage than
// running any valid SQL

// limit sql select queries to this many rows.  Long queries cause Express to
// block, potentially slowing down other users.  Using PM2's cluster feature helps,
// but it does dumb round-robin and doesn't take into account busy workers.
//
// Should maybe run a second instance on a different port for heavy queries if there
// are multiple concurrent users
var maxRows = 5000 

// end user-configurable
///////////////////////////////////////////////////

//////////////////////////////////////////////////
// Express configuration, routes
var app = express()
app.use(require('body-parser').json()) // auto-parse post bodies in JSON format
app.use(express.static('public')) // serve up static files in the public directory

// helper route for generating some password hashes to stick in the passwords
// table for testing
if(enableBcryptRoute) {
  // return an encrypted password string
  app.post(bcryptPath, function(req, res) {
    if(! (req.body.password && typeof req.body.password === 'string'))
      return HTTPFail(res, 'No password supplied')
  
    bcrypt.hash(req.body.password, 10, function(err, hash) {
      if(err) return HTTPFail(res, 'Bcrypt failed: ' + err)
      else return HTTPSuccess(res, hash)
    })
  })
}

// user passed in 'user' and 'pass' in the post body.  check it against
// the database with bcrypt and return a JWT on success
app.post(authPath, function(req, res) {
  if (!req.body.user || !req.body.pass) 
    return HTTPFail(res, 'Missing username or password', 'auth')

  query({sql: 'select pass from ' + passwordsTable + ' where user = ?', args: [req.body.user]})
    .then(function(dbres) {
      if (!dbres) return HTTPFail(res, 'Wrong username/password.', 'auth')
      var p = dbres[0][0].pass
      if (bcrypt.compareSync(req.body.pass, p)) { // check password
        var expires = epochSeconds() + JWTDuration * 60
        var token = jwt.encode({ user: req.body.user, expires: expires }, JWTSecret)
        if (token) return HTTPSuccess(res, token)
        else return HTTPFail(res, 'Failed to generate JWT token.  Weird.', 'auth')
      } else return HTTPFail(res, 'Wrong username/password.', 'auth')
    })
    .catch(function(err) {
      return HTTPFail(res, err.message, 'auth')
    })
})

// user passed in some SQL in the post body.  Parse it, check the user's permissions
// for the requested query, run the query and return the results
app.post(SQLPath, function(req, res) {
  var sql = req.body

  validateSQL(sql)
  .then(function() { return validateJWT(req) })
  .then(function(jwt) { return sqlCheckPerms(jwt.user, sql) })
  .then(function() { return query(sql) }) 
  .then(function(r) { return HTTPSuccess(res, r) })
  .catch(function(e) { return HTTPFail(res, e.message) })
})

// GO!
app.listen(port)

// end express config
////////////////////////////////////////////////

// time in seconds since 1970 for generating/enforcing JWT expiration
function epochSeconds() {  return new Date().getTime() / 1000 }

// HTTP fail function.  
var HTTPFailCodes = { general: 400, auth: 401 }
function HTTPFail(res, msg, type) {
  type = type || 'general' // default to 'general' if not specified
  return res.status(HTTPFailCodes[type]).json(msg)
}

// dinner is served
function HTTPSuccess(res, data) { res.status(200).json(data) }

// check the authorization header, validate and return decoded JWT token
function validateJWT(req) {
  return new Promise(function (resolve, reject) {
    if (!req.headers.authorization) reject({message:'No authorization header'})
    var jwtText = req.headers.authorization.split(' ', 2)[1]
    if (!jwtText) reject({message:'Invalid authorization header'})
    var jwtToken
    try { jwtToken = jwt.decode(jwtText, JWTSecret) } 
    catch (e) { reject({message:'Invalid authorization header'}) }

    // make sure it hasn't expired
    if(enforceJWTDuration && (! jwtToken.expires || jwtToken.expires < epochSeconds())) 
      reject({message: 'Expired authorization token'})

    resolve(jwtToken)
  })
}

/////////////////////////////////
// database stuff

var isSelect = sql =>  typeof sql === 'string' && sql.match(/^\s*select\s+/i)

// Promisified wrapper for sqlite3's all function, 
function dbAll(sql, args) {
  return new Promise(function(resolve, reject) {
    this.all(sql, args, function(err, res) {
      if(err) reject(err)
      else resolve(res)
    })
  }.bind(this))
}

// Promisified wrapper for sqlite3's run function
function dbRun(sql, args) {
  return new Promise(function(resolve, reject) {
    this.run(sql, args, function(err) {
      if(err) reject(err)
      else resolve(this)
    })
  }.bind(this))
}

// extend the callback-style sqlite3.Database class and add our promisified
// wrapper functions. use it with:  var db = new _sqlite(dbFile)
class _sqlite extends sqlite3.Database {
  constructor(dbFile) {
    super(dbFile)
    this._all = dbAll
    this._run = dbRun
  }
}

// see if sql includes a limit clause, make sure it's less than maxRows.
// if not, add one but preserve any 'offset' clause after the limit
function imposeLimit(SQLString) {
  var limitRE = /\s+limit\s+(\d+)(\s+offset\s+\d+)?\s*$/i
  var newSQL = SQLString,
    limitMatch = SQLString.match(limitRE)
  if (limitMatch) {
    if (limitMatch[1] > maxRows) { // the number after 'limit'
      var offsetClause = limitMatch[2] || '' // the optional full offset clause
      newSQL = newSQL.replace(limitRE, ' limit ' + maxRows + offsetClause)
    } // else just leave as-is
  } else newSQL += ' limit ' + maxRows
  return newSQL
}

// perform a series of SQL queries as contained in the 'sql' argument array.
// this is called after JWT validation and permissions checks
// sql arg has format: 
// [ { sql: 'select * from foo where a = ?', args: 123 },
//   { sql: 'insert into bar (a,b) values (?, ?)', args: ['foo', 'bar'] }, ... ]
//
//   or for one SQL object, optionally skip the array: 
//     { sql: 'select ...', args: [1,2] }
//
//   or for a simple SQL statement with no args, optionally just a string:
//   'select * from foo'
//
//  for a single arg, optionally skip the array: arg: 'foo' / arg: ['foo']
//   
function query(sql) {
  var db // set in co main function, needed in catch() to roll back transaction
  var SQLArray = arrayify(sql) // user can pass in array, single object or string
  return co(function*() {
    db = new _sqlite(dbFile)
    yield db._run('begin') // wrap all operations in a transaction
    var allQueryResults = []
    var lastIDs = []

    for (var i = 0; i < SQLArray.length; i++) { // loop through array of SQL queries
      var thisSQL = SQLArray[i].sql,
        thisArgs = SQLArray[i].args

      // user can pass in single arg without array, convert to array
      thisArgs = Array.isArray(thisArgs) ? thisArgs : [ thisArgs ]
      
      // see if this query has been run before and if we're frozen to new queries, error out
      var isKnown = yield db._all('select count(query) as count from ' + knownQueriesTable + ' where query = ? ', [thisSQL])
        .then(c => c[0].count == 1 )

      if(! isKnown) {
        if(freezeQueries) throw { message: 'Custom SQL queries are disabled: ' + thisSQL }
        else yield db._run('insert or ignore into knownqueries (query) values (?)', [thisSQL])
      }

      // selects go through db._all, everything else through db._run
      if (isSelect(thisSQL)) { 
        // run query (limiting number of rows returned), store result
        allQueryResults.push(yield db._all(imposeLimit(thisSQL), thisArgs))
      } else {
        // queries can have a '@lastID<num>' argument (case-insensitive), which gets
        // replaced with the lastID of the <num>th query.  Leaving off <num> means query 0
        // e.g. @lastID and @lastID0 mean the first, @lastID22 is 23rd, etc.
        var newArgs = [] 
        thisArgs.forEach(function(thisArg) {
          var lastMatch = String(thisArg).match(/^\s*@lastid(\d*)\s*$/i)
          if (lastMatch) {
            var matchNum = lastMatch[1] || lastIDs.length - 1
            if (lastIDs[matchNum]) newArgs.push(lastIDs[matchNum])
            else throw { message: 'No lastID' + matchNum + ' available. SQL: ' + thisSQL }
          } else newArgs.push(thisArg)
        })

        // run query, store result
        var thisResult = yield db._run(thisSQL, newArgs)
        allQueryResults.push(thisResult)
        
        // remember for subsequent queries that might reference @lastID<num>
        lastIDs.push(thisResult.lastID)
      }
    }

    // finish up transaction
    yield db._run('end')
    db.close()
    return allQueryResults
  })
  .catch(function(error) { // anything fails, roll back the transaction and close the db handle
    db._run('rollback')
      .then(()  => db.close())
      .catch((err) => { db.close(); console.log('Rollback error ?? ', err) })

    throw error
  })
}

// figure out what kind of SQL query we're doing.  Must be one of
// select, update, delete, insert
function queryType(SQLObject) {
  if(! (SQLObject && SQLObject.sql && typeof SQLObject.sql === 'string')) return null
  var type = SQLObject.sql.match(/^\s*(select|update|delete|insert)\s+/i)
  return type ? type[1].toLowerCase() : null
}

// parse SQL for the name of the table it will read/change
//
// accepted sql begins with 'insert into table ...', 'update table ...',
// 'select ... from table' and 'delete from table'.  This is a subset of the full
// SQLite dialect.  Expand as needed.  Known limitation: doesn't know about or
// enforce permissions on subqueries like 'insert into ... select from ...'
// 
var queryMatches = {
  update: /^\s*update\s+(\w+)\s+/i,
  delete: /^\s*delete\s+from\s+(\w+)/i,
  insert: /^\s*insert\s+into\s+(\w+)\s+/i,
  select: /^\s*select\s+.+\s+from\s+(\w+)/i
}
function tableName(SQLObject) {
  var type = queryType(SQLObject)
  if (!type) return null
  var table = SQLObject.sql.match(queryMatches[type])
  if (!table) return null
  return table[1].toLowerCase()
}

// sanity-check the supplied SQL
function validateSQL(sql) {
  var SQLArray = arrayify(sql)
  return new Promise(function(resolve, reject) {
    if (!SQLArray[0].sql) reject({message:'No SQL supplied with query'})

    for (var i = 0; i < SQLArray.length; i++) {
      var type = queryType(SQLArray[i])
      if (!type) reject({message: 'Invalid SQL: ' + SQLArray[i].sql})

      var table = tableName(SQLArray[i])
      if (!table) reject({message: 'Invalid SQL: ' + SQLArray[i].sql})
    }
    resolve(true)
  })
}

// make sure the user has permission to perform the requested query by checking
// the permissions table.  
function sqlCheckPerms(user, sql) {
  var SQLArray = arrayify(sql)
  return co(function*() {
    for (var i = 0; i < SQLArray.length; i++) {
      var type = queryType(SQLArray[i]),
        table = tableName(SQLArray[i]),
        right = type === 'select' ? 'read' : 'write',
        rightSelect = 'select ' + right + ' from ' + 
                 permissionsTable + ' where user = ? and tbl = ?' 

      yield query({sql: rightSelect, args: [user, table]})
        .then(function(res) {
          if (!(res && res[0] && res[0][0] && res[0][0][right])) {
            throw { message: 'Permission denied for ' + right + ' on table ' + table }
          }
        })
    }
  })
}

// take an sql string or object and convert it to an array of objects
//  with members sql and args (if applicable)
function arrayify(sql) {
  if (typeof sql === 'string') return [ { sql: sql } ]
  if(! Array.isArray(sql)) return [ sql ]
  return sql
}

// end database stuff
/////////////////////////////////


