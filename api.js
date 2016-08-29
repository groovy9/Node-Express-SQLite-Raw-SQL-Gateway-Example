'use strict'
var express = require('express')
var bcrypt = require('bcrypt')
var Promise = require('promise')
var co = require('co')
var sqlite3 = require('sqlite3')
var jwt = require('jwt-simple')
var fs = require('fs')
var sqliteParser = require('sqlite-parser')

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
  knownQueriesTable = 'knownqueries',
  routeDir = 'routes', // directory holding JS modules with dedicated API routes
  disableSQLRoute = false // optionally, disable the raw SQL route in lieu of custom routes
 
//
// security alert. In its default config, this app is vulnerable to malicious users 
// going around your front end and doing unexpected queries on tables they have write 
// access to.  To mitigate this, we store every query (minus placeholder args) in 
// knownQueriesTable until freezeQueries above is set to true, at which point we stop 
// allowing any new queries.  As most front ends will have a finite set of queries, 
// this effectively locks down the database to "safe" queries.  A user could still
// run a safe query with custom args, but this is much less potential damage than
// running any valid SQL.  
//
// If this is not enough, you can use the raw SQL function only for development,
// move your SQL into traditional REST api routes as per the docs, and disable
// the raw SQL route by setting disableSQLRoute above to true.
//

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
      if (! (dbres && dbres[0] && dbres[0][0])) return HTTPFail(res, 'Wrong username/password.', 'auth')
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
function safeQuery(req, res, sql) {
  if(! Array.isArray(sql)) sql = [ sql ]
  validateSQL(sql)
    .then(function() { return validateJWT(req) })
    .then(function(jwt) { return sqlCheckPerms(jwt.user, sql) })
    .then(function() { return query(sql) }) 
    .then(function(r) { return HTTPSuccess(res, r) })
    .catch(function(e) { return HTTPFail(res, e.message) })
}

if(! disableSQLRoute) 
  app.post(SQLPath, (req, res) => safeQuery(req, res, req.body))

// include user defined routes under routeDir
var routePath = require('path').join(__dirname, routeDir) /*eslint no-undef: "__dirname"*/

try {
  fs.readdirSync(routePath).forEach(function(file) {
    if(file.match(/^\w/)) {
      require(routePath + '/' + file)(app, safeQuery)
    }
  })
} catch(err) {
  console.log('routeDir ' + routeDir + ' is not accessible.  Custom routes disabled.')
}

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
  var SQLArray = arrayify(sql) // user can pass in array, single object or string
  var needsWrt = needsWrite(sql)
  return co(function*() {
    if(needsWrt) 
      yield db._run('begin') // wrap everything in a transaction if any writes
     
    var allQueryResults = []
    var lastIDs = []

    for (var i = 0; i < SQLArray.length; i++) { // loop through array of SQL queries
      var thisSQL = SQLArray[i].sql,
        thisArgs = SQLArray[i].args

      // user can pass in single arg without array, convert to array
      thisArgs = Array.isArray(thisArgs) ? thisArgs : [ thisArgs ]

      // make sure it's an acceptable query type
      var qType = queryType(thisSQL)
      if(! (qType === 'select' || qType === 'update' || qType === 'insert' || qType === 'delete'))
        throw { message: 'Invalid query type: ' + qType } 
      
      // see if this query has been run before and if we're frozen to new queries, error out
      var isKnown = yield db._all('select count(query) as count from ' + knownQueriesTable + ' where query = ? ', [thisSQL])
        .then(c => c[0].count == 1 )

      if(! isKnown) {
        if(freezeQueries) throw { message: 'Custom SQL queries are disabled: ' + thisSQL }
        else yield db._run('insert or ignore into knownqueries (query) values (?)', [thisSQL])
      }

      // selects go through db._all, everything else through db._run
      if (qType === 'select') { 
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
    if(needsWrt) yield db._run('end')

    return allQueryResults
  })
  .catch(function(error) { // anything fails, roll back the transaction and close the db handle
    if(needsWrt) 
      db._run('rollback').catch((err) => { console.log('Rollback error ?? ', err) })
     
    throw error
  })
}

// sanity-check the supplied SQL
function validateSQL(sql) {
  var SQLArray = arrayify(sql)
  return new Promise(function(resolve, reject) {
    if (!SQLArray[0].sql) reject({message:'No SQL supplied with query'})

    for (var i = 0; i < SQLArray.length; i++) {
      var tp = tablePerms(sql[i].sql),
        count = 0
      count += tp.read ? tp.length : 0
      count += tp.write ? tp.write : 0
      if (count < 1) reject({message: 'Invalid SQL: ' + SQLArray[i].sql})
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
      var tables = tablePerms(SQLArray[i].sql)
      for(var j = 0; j < tables.write.length; j++) {
        var s = 'select write from ' + permissionsTable + ' where user = ? and tbl = ?'
        yield query({sql: s, args: [user, tables.write[j]]})
          .then(function(res) {
            if (!(res && res[0] && res[0][0] && res[0][0].write)) {
              throw { message: 'Permission denied for writing to table ' + tables.write[j] }
            }
          })
      }
      for(var k = 0; k < tables.read.length; k++) {
        var ss = 'select read from ' + permissionsTable + ' where user = ? and tbl = ?'
        yield query({sql: ss, args: [user, tables.read[k]]})
          .then(function(res) {
            if (!(res && res[0] && res[0][0] && res[0][0].read)) {
              throw { message: 'Permission denied for reading from table ' + tables.read[k] }
            }
          })
      }
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

// parse a single SQL query and return what kind of query it is 
// (select/insert/update/delete)
function queryType(sql) {
  var ast = sqliteParser(sql)
  if (!(ast && ast.statement)) return null
  if (ast.statement.length !== 1) return null // only one SQL statement per SQL object
  return ast.statement[0].variant.toLowerCase()
}

// parse a single SQL query and return an object containing two arrays,
// one for the tables that the query will read from and one for the tables
// the query will write to
function tablePerms(sql) {
  var allInto = [],
    allFrom = []

  function parseFrom(ast) {
    if (Array.isArray(ast)) ast.map(a => parseFrom(a))
    else if (typeof ast === 'object') {
      for (var p in ast) {
        if (p === 'variant' && ast[p] === 'table') allFrom.push(ast.name)
        parseFrom(ast[p])
      }
    }
  }

  function parse(ast) {
    if (Array.isArray(ast)) ast.map(a => parse(a))
    else if (typeof ast === 'object') {
      for (var p in ast) {
        if (p === 'into' && (ast[p].variant === 'table' || ast[p].format === 'table')) allInto.push(ast[p].name) 
        if (p === 'from') {
          if (ast.variant === 'delete' && ast[p].variant === 'table') allInto.push(ast[p].name)
          else parseFrom(ast[p])
        } else parse(ast[p])
      }
    }
  }

  parse(sqliteParser(sql))
  return { write: allInto, read: allFrom }
}

// see if anything in the SQL array requires a write
function needsWrite(SQLObject) {
  var sqlObj = SQLObject
  if(!Array.isArray(sqlObj)) sqlObj = [ sqlObj ]

  for(var i = 0; i < sqlObj.length; i++) {
    var perms = tablePerms(sqlObj[i].sql)
    if(perms && perms.write && perms.write.length > 0) return true
  }
  return false
}

// end database stuff
/////////////////////////////////

var db = new _sqlite(dbFile)
db._all('select * from ' + passwordsTable)
  .then(function() { db._all('select * from ' + permissionsTable) })
  .catch(function() {
    console.log('Database file ' + dbFile + ' is missing, corrupt or does not contain required tables.')
    process.exit()
  })

// GO!
app.listen(port)

