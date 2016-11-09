'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/* eslint no-underscore-dangle: ["off"] */
/* eslint class-methods-use-this: "error"*/
var crypto = require('crypto');
var moment = require('moment');
var _debug = require('debug');
var mysql = require('mysql');
var parallel = require('async/parallel');
var series = require('async/series');
var colors = require('colors/safe');

var debug = _debug('vbauth');
debug('Initializing vbauth');

var __DEV__ = process.env.NODE_ENV !== 'production';

// e-mail confirmed / not banned users
var _isUser = function _isUser(userinfo) {
  return userinfo.usergroupid > 1 && userinfo.usergroupid !== 8 && // banned
  userinfo.usergroupid !== 3 && // awaiting email confirmation
  userinfo.usergroupid !== 4 // awaiting moderation
  ;
};

// admins
var _isAdmin = function _isAdmin(userinfo) {
  return userinfo.usergroupid === 6;
};

// admins, moderators and super moderators
var _isModerator = function _isModerator(userinfo) {
  return userinfo.usergroupid >= 5 && userinfo.usergroupid <= 7;
};

var VBAuth = function () {
  function VBAuth(database, options) {
    var _this = this;

    _classCallCheck(this, VBAuth);

    if (typeof options.cookieSalt !== 'string' || options.cookieSalt.length === 0) {
      console.error(colors.red('A cookieSalt must be specified in VBAuth.options! You can find your cookie salt at \'includes/functions.php\' of your vBulletin install folder.\nIf you don\'t specify the correct cookie salt "remember-me cookies" won\'t work'));
    }

    if (!database) {
      throw new Error('You must pass the database information on vbauth initialization');
    } else if ({}.hasOwnProperty.call(database, 'connectionLimit') && {}.hasOwnProperty.call(database, 'host') && {}.hasOwnProperty.call(database, 'user') && {}.hasOwnProperty.call(database, 'password') && {}.hasOwnProperty.call(database, 'database')) {
      this.database = mysql.createPool(database);
    } else if (!{}.hasOwnProperty.call(database, 'config')) {
      throw new Error('Invalid MySQL info passed on vbauth initialization');
    } else {
      // an actual mysql pool was passed
      this.database = database;
    }

    this.options = Object.assign({
      // Used to salt the remember me password before setting the cookie.
      // The cookieSalt is located at the file 'includes/functions.php' of your vBulletin install
      cookieSalt: '',

      // Cookie prefix used by vBulletin. Defaults to 'bb_'.
      cookiePrefix: 'bb_',

      // How long it takes for a session to timeout.
      cookieTimeout: 900,

      // Cookie domain.
      cookieDomain: '',

      // Default path, for activity refresh. Set a url, or null. null defaults to req.path
      defaultPath: 'http://my.domain.com',

      // The strike system will block the user from trying to log in after 5 wrong tries
      useStrikeSystem: true,

      // Should it refresh activity or not? If not, it will simply attach the userinfo to the
      // request object, and will not make any writes or updates in to the Forum database
      refreshActivity: true,

      // Use Secure cookies for remember me. Secure cookies only gets stored if transmitted
      // via TLS/SSL (https sites)
      secureCookies: false,

      // Use a redis cache for faster session look-up?
      // If so, you must pass a redis-client instance to this
      redisCache: false,

      // Query user subscriptions?
      subscriptions: true,

      // Subscription id to query
      subscriptionId: 1,

      // The subnet mask which reflects the level of checking you wish to run
      // against IP addresses when a session is being fetched.
      // To check this, go to:
      //  vBulletin Options ->
      //    Server Settings and Optimization Options ->
      //      Session IP Octet Length Check
      // 255.255.255.255 = 0
      // 255.255.255.0   = 1
      // 255.255.0.0     = 2
      sessionIpOctetLength: 1
    }, options);

    this.defaultUserObject = {
      userid: 0,
      username: 'unregistered',
      usergroupid: 1,
      membergroupids: '',
      email: '',
      posts: 0
    };

    if (this.options.subscriptions) {
      this.defaultUserObject.subscriptionexpirydate = 0;
      this.defaultUserObject.subscriptionstatus = 0;
    }

    this.isUser = options.isUser || _isUser;
    this.isModerator = options.isModerator || _isModerator;
    this.isAdmin = options.isAdmin || _isAdmin;

    if (typeof this.options.refreshActivity === 'function') {
      this.refreshActivity = this.options.refreshActivity;
    } else if (this.options.refreshActivity === true) {
      this.refreshActivity = function () {
        return true;
      };
    } else {
      this.refreshActivity = function () {
        return false;
      };
    }

    // enable query logging
    if (debug.enabled) {
      (function () {
        var originalQuery = _this.database.query;

        _this.database.query = function () {
          for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }

          if (args.length === 3) {
            debug(mysql.format(args[0], args[1]));
          } else if (args.length === 2) {
            debug(args[0]);
          }

          originalQuery.apply(_this.database, args);
        };
      })();
    }
  }

  // Removes ipv6 from ip


  _createClass(VBAuth, [{
    key: '_fetchIdHash',


    // Unique id based on user ip and user agent
    value: function _fetchIdHash(req) {
      var ip = VBAuth._getIpv4(req.ip);
      var ipSubStr = VBAuth._getSubstrIp(ip, this.options.sessionIpOctetLength);
      var userAgent = req.header('user-agent');

      return crypto.createHash('md5').update(userAgent + ipSubStr).digest('hex');
    }
  }, {
    key: '_mysqlCreateSession',
    value: function _mysqlCreateSession(userid, ip, idHash, sessionHash, url, userAgent, req) {
      var _this2 = this;

      return new Promise(function (resolve, reject) {
        if (!_this2.refreshActivity(req)) {
          resolve(sessionHash);
          return;
        }

        var query = mysql.format('INSERT INTO session' + ' (userid, sessionhash, host, idhash, lastactivity, location, useragent, loggedin)' + ' VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [userid, sessionHash, ip, idHash, moment().unix(), url, userAgent, userid > 0]);

        _this2.database.query(query, function (err) {
          if (err) {
            reject(err);
            return;
          }

          resolve(sessionHash);
        });
      });
    }
  }, {
    key: '_redisCreateSession',
    value: function _redisCreateSession(userid, ip, idHash, sessionHash, url, userAgent) {
      var _this3 = this;

      return new Promise(function (resolve, reject) {
        if (!_this3.options.redisCache) {
          resolve();
          return;
        }

        var key = 'vbsession:' + sessionHash;

        var multi = _this3.options.redisCache.multi();
        multi.hmset(key, {
          userid: userid,
          sessionhash: sessionHash,
          host: ip,
          idhash: idHash,
          lastactivity: moment().unix(),
          location: url,
          useragent: userAgent,
          loggedin: userid > 0
        });
        multi.expire(key, _this3.options.cookieTimeout * 0.25);
        multi.exec(function (err) {
          if (err) {
            reject(err);
            return;
          }

          resolve();
        });
      });
    }

    // Create a new session in the database for the user

  }, {
    key: 'createSession',
    value: function createSession(req, res, userid /* , loginType*/) {
      var ip = VBAuth._getIpv4(req.ip);
      var idHash = this._fetchIdHash(req);
      var url = this.options.defaultPath ? this.options.defaultPath : req.path;
      var userAgent = req.header('user-agent').slice(0, 100);
      var hash = moment().valueOf().toString() + userid + ip;
      hash = crypto.createHash('md5').update(hash).digest('hex');

      // Sets cookie to the response
      res.cookie(this.options.cookiePrefix + 'sessionhash', hash, {
        domain: this.options.cookieDomain,
        httpOnly: true
      });

      // Use Redis cache, if available
      this._redisCreateSession(userid, ip, idHash, hash, url, userAgent);

      // Returns a promise
      return this._mysqlCreateSession(userid, ip, idHash, hash, url, userAgent, req);
    }
  }, {
    key: '_mysqlUpdateUserActivity',
    value: function _mysqlUpdateUserActivity(userid, sessionHash, lastUrl, req) {
      var _this4 = this;

      return new Promise(function (resolve, reject) {
        if (!_this4.refreshActivity(req)) {
          resolve(true);
          return;
        }

        var query = mysql.format('UPDATE session SET \n          lastactivity = ?,\n          location = ?,\n          userid = ?,\n          loggedin = ? \n          WHERE sessionhash = ?', [moment().unix(), lastUrl, userid, userid > 0, sessionHash]);

        _this4.database.query(query, function (err, result) {
          if (err) {
            reject(err);
            return;
          }

          resolve(result.affectedRows > 0);
        });
      });
    }
  }, {
    key: '_redisUpdateUserActivity',
    value: function _redisUpdateUserActivity(userid, sessionHash, lastUrl) {
      var _this5 = this;

      return new Promise(function (resolve, reject) {
        var key = 'vbsession:' + sessionHash;

        if (!_this5.options.redisCache) {
          resolve(false); // redis not available
          return;
        }

        _this5.options.redisCache.exists(key, function (err, exists) {
          if (err) {
            reject(err);
            return;
          }
          if (!exists) {
            resolve(false); // not updated
            return;
          }

          _this5.options.redisCache.hmset(key, {
            lastactivity: moment().unix(),
            location: lastUrl,
            userid: userid,
            loggedin: userid > 0
          }, function (err2) {
            if (err2) {
              reject(err2);
              return;
            }

            resolve(true);
          });
        });
      });
    }

    // Refreshes the user activity in the database, according to its session

  }, {
    key: 'updateUserActivity',
    value: function updateUserActivity(lastUrl, userid, sessionHash, req) {
      var _this6 = this;

      if (!sessionHash || sessionHash.length === 0) {
        return Promise.resolve(false);
      }

      return this._redisUpdateUserActivity(userid, sessionHash, lastUrl).then(function (updated) {
        if (!updated) {
          return _this6._mysqlUpdateUserActivity(userid, sessionHash, lastUrl, req);
        }

        return Promise.resolve(updated);
      });
    }

    // Deletes a session

  }, {
    key: 'deleteSession',
    value: function deleteSession(sessionhash, redisOnly, req) {
      var _this7 = this;

      return new Promise(function (resolve, reject) {
        if (typeof sessionhash !== 'string') {
          resolve(true);
          return;
        }

        parallel([function (cb) {
          if (redisOnly || !_this7.refreshActivity(req)) {
            return cb(null, true);
          }

          var query = mysql.format('DELETE FROM session WHERE sessionhash = ?', [sessionhash]);
          return _this7.database.query(query, function (err) {
            return cb(err, true);
          });
        }, function (cb) {
          if (!_this7.options.redisCache) {
            return cb(null, true);
          }

          return _this7.options.redisCache.del('vbsession:' + sessionhash, function (err) {
            return cb(err, true);
          });
        }], function (err) {
          if (err) {
            reject(err);
            return;
          }
          resolve(true);
        });
      });
    }

    // Returns the userinfo if the username/password are valid, or null if it's not valid

  }, {
    key: 'isValidLogin',
    value: function isValidLogin(username, password) {
      var _this8 = this;

      return new Promise(function (resolve, reject) {
        var query = mysql.format('SELECT userid, password FROM user WHERE ' + 'username = ? AND ' + '(password = md5(concat(?, salt)) OR password = md5(concat(md5(?), salt)))', [username, password, password]);

        _this8.database.query(query, function (err, rows) {
          if (err) {
            reject(err);
            return;
          }

          resolve(rows[0]);
        });
      });
    }

    // Returns true if the cookie userid/password is valid, false otherwise

  }, {
    key: 'checkRememberMeCredentials',
    value: function checkRememberMeCredentials(userid, password) {
      var _this9 = this;

      return new Promise(function (resolve, reject) {
        var query = mysql.format('SELECT userid FROM user' + ' WHERE userid = ? AND md5(concat(password, ?)) = ?', [userid, _this9.options.cookieSalt, password]);

        _this9.database.query(query, function (err, rows) {
          if (err) {
            reject(err);
            return;
          }

          resolve(rows.length > 0);
        });
      });
    }
  }, {
    key: '_redisStoreUserInfo',
    value: function _redisStoreUserInfo(userinfo) {
      var _this10 = this;

      return new Promise(function (resolve, reject) {
        if (!_this10.options.redisCache) {
          resolve(true);
          return;
        }

        var key = 'vbuser:' + userinfo.userid;

        var multi = _this10.options.redisCache.multi();
        multi.hmset(key, userinfo);
        multi.expire(key, _this10.options.cookieTimeout * 0.25);
        multi.exec(function (err) {
          if (err) {
            reject(err);
            return;
          }
          resolve(true);
        });
      });
    }
  }, {
    key: '_redisGetUserInfo',
    value: function _redisGetUserInfo(userid) {
      var _this11 = this;

      return new Promise(function (resolve, reject) {
        if (!_this11.options.redisCache) {
          resolve(null);
          return;
        }

        var key = 'vbuser:' + userid;
        _this11.options.redisCache.hgetall(key, function (err, results) {
          if (err) {
            return reject(err);
          }

          if (!results) {
            return resolve(null);
          }

          var ret = results;
          ret.userid = parseInt(results.userid, 10);
          ret.usergroupid = parseInt(results.usergroupid, 10);
          ret.posts = parseInt(results.posts, 10);
          if (_this11.options.subscriptions) {
            ret.subscriptionstatus = parseInt(results.subscriptionstatus, 10) || 0;
            ret.subscriptionexpirydate = parseInt(results.subscriptionexpirydate, 10) || 0;
          } else {
            delete ret.subscriptionstatus;
            delete ret.subscriptionexpirydate;
          }

          return resolve(ret);
        });
      });
    }
  }, {
    key: '_mysqlGetUserInfo',
    value: function _mysqlGetUserInfo(userid) {
      var _this12 = this;

      return new Promise(function (resolve, reject) {
        var subscriptionFields = '';
        var subscriptionJoin = '';
        if (_this12.options.subscriptions) {
          subscriptionFields = ', IFNULL(b.status, 0) AS subscriptionstatus,' + ' IFNULL(b.expirydate, 0) AS subscriptionexpirydate';
          subscriptionJoin = 'LEFT JOIN subscriptionlog AS b' + (' ON a.userid = b.userid AND b.subscriptionid = ' + mysql.escape(_this12.options.subscriptionId));
        }

        var query = 'SELECT a.userid, a.username, ' + ' a.usergroupid, a.membergroupids,' + (' a.email, a.posts' + subscriptionFields) + (' FROM user AS a ' + subscriptionJoin) + (' WHERE a.userid = ' + mysql.escape(userid));

        _this12.database.query(query, function (err, rows) {
          if (err) {
            reject(err);
            return;
          }

          var userinfo = rows[0];
          if (!userinfo) {
            console.warn('User does not exist:', userid);
            resolve(null);
            return;
          }

          _this12._redisStoreUserInfo(userinfo);
          resolve(userinfo);
        });
      });
    }

    // Get user info

  }, {
    key: 'getUserInfo',
    value: function getUserInfo(userid) {
      var _this13 = this;

      // Avoid performing this query if the user is not authenticated
      if (!userid || userid === 0) {
        return Promise.resolve(Object.assign({}, this.defaultUserObject));
      }

      return this._redisGetUserInfo(userid).then(function (userinfo) {
        if (!userinfo) {
          return _this13._mysqlGetUserInfo(userid);
        }

        return Promise.resolve(userinfo);
      });
    }
  }, {
    key: '_mysqlGetActiveSession',
    value: function _mysqlGetActiveSession(sessionHash, idHash) {
      var _this14 = this;

      return new Promise(function (resolve, reject) {
        var query = mysql.format('SELECT a.* FROM session AS a' + ' WHERE sessionhash = ? AND idhash = ? AND lastactivity > ?', [sessionHash, idHash, moment().unix() - _this14.options.cookieTimeout]);

        _this14.database.query(query, function (err, rows) {
          if (err) {
            reject(err);
            return;
          }

          var sessionData = rows[0];
          if (!sessionData) {
            console.warn('Session expired:', sessionHash);
            resolve(null);
            return;
          }

          _this14._redisCreateSession(sessionData);
          resolve(sessionData);
        });
      });
    }
  }, {
    key: '_redisGetActiveSession',
    value: function _redisGetActiveSession(sessionHash, idHash) {
      var _this15 = this;

      return new Promise(function (resolve, reject) {
        if (!_this15.options.redisCache) {
          resolve(null);
          return;
        }

        var key = 'vbsession:' + sessionHash;
        _this15.options.redisCache.hgetall(key, function (err, results) {
          if (err) {
            reject(err);
            return;
          }

          if (!results || results.idhash !== idHash) {
            resolve(null);
          } else {
            resolve(results);
          }
        });
      });
    }

    // Returns the currently active session, or null if there isn't any

  }, {
    key: 'getActiveSession',
    value: function getActiveSession(sessionHash, idHash) {
      var _this16 = this;

      return new Promise(function (resolve, reject) {
        if (!sessionHash || sessionHash.length === 0) {
          resolve(null);
          return;
        }

        _this16._redisGetActiveSession(sessionHash, idHash).then(function (session) {
          if (!session) {
            return _this16._mysqlGetActiveSession(sessionHash, idHash);
          }

          return Promise.resolve(session);
        }).then(function (session) {
          return resolve(session);
        }).catch(function (err) {
          return reject(err);
        });
      });
    }

    // Just for code reusing

  }, {
    key: 'updateOrCreateSession',
    value: function updateOrCreateSession(req, res, sessionHash, userid) {
      var _this17 = this;

      /* eslint no-param-reassign: ["error", { "props": false }] */
      return new Promise(function (resolve, reject) {
        // Append user info to request object
        req.vbuser = { userid: userid };
        var url = _this17.options.defaultPath ? _this17.options.defaultPath : req.path;

        // call those in parallel
        var callArray = [function (cb) {
          return _this17.getUserInfo(userid).then(function (userinfo) {
            return cb(null, userinfo);
          }).catch(function (err) {
            return cb(err);
          });
        }, function (cb) {
          return (
            // this will return right away if sessionHash is null, or empty
            _this17.updateUserActivity(url, userid, sessionHash, req).then(function (updated) {
              if (!updated) {
                // if for some reason his old session wasn't in the db, then just make him a new one
                // this should never happen, but just in case...
                return _this17.createSession(req, res, userid);
              }

              return Promise.resolve(sessionHash);
            }).then(function (hash) {
              return cb(null, hash);
            }).catch(function (err) {
              return cb(err);
            })
          );
        }];

        // After the tasks have been done, we may get back to where we were...
        parallel(callArray, function (err, results) {
          if (err) {
            reject(err);
            return;
          }

          req.vbuser = results[0];
          resolve(results[1]);
        });
      });
    }

    // Increases the amount of login tries in the database

  }, {
    key: 'execStrikeUser',
    value: function execStrikeUser(username, userip) {
      var _this18 = this;

      return new Promise(function (resolve, reject) {
        if (!_this18.options.useStrikeSystem) {
          resolve(null);
          return;
        }

        var query = mysql.format('INSERT INTO strikes ' + '(striketime, strikeip, username) ' + 'VALUES ' + '(?, ?, ?)', [moment().unix(), userip, username]);

        _this18.database.query(query, function (err) {
          if (err) {
            reject(err);
            return;
          }

          resolve(null);
        });
      });
    }

    // Removes his login strikes after a successful login

  }, {
    key: 'execUnstrikeUser',
    value: function execUnstrikeUser(username, userip) {
      var _this19 = this;

      return new Promise(function (resolve, reject) {
        if (!_this19.options.useStrikeSystem) {
          resolve(null);
          return;
        }

        var query = mysql.format('DELETE FROM strikes WHERE strikeip = ? AND username = ?', [userip, username]);

        _this19.database.query(query, function (err) {
          if (err) {
            reject(err);
            return;
          }

          resolve(null);
        });
      });
    }

    // Checks whether the user can try logging in or not
    // If he already typed the password wrongly 5 times
    // in the last 15 minutes he will not be allowed to try again

  }, {
    key: 'verifyStrikeStatus',
    value: function verifyStrikeStatus(username, userip) {
      var _this20 = this;

      return new Promise(function (resolve, reject) {
        if (!_this20.options.useStrikeSystem) {
          resolve(0);
          return;
        }

        var deleteQuery = mysql.format('DELETE FROM strikes WHERE striketime < ?', [moment().unix() - 3600]);
        var selectQuery = mysql.format('SELECT COUNT(*) AS strikes, MAX(striketime) AS lasttime ' + 'FROM strikes ' + 'WHERE strikeip = ?', [userip]);

        series([function (cb) {
          return _this20.database.query(deleteQuery, cb);
        }, function (cb) {
          return _this20.database.query(selectQuery, cb);
        }], function (err, results) {
          if (err) {
            reject(err);
            return;
          }

          var strikeResults = results[1][0][0];

          if (strikeResults.strikes >= 5 && strikeResults.lasttime > moment().unix() - 900) {
            // they've got it wrong 5 times or greater for any username at the moment

            // the user is still not giving up so lets keep increasing this marker
            _this20.execStrikeUser(username, userip).catch(function (err2) {
              return console.warn(err2);
            });
            resolve(strikeResults.strikes + 1);
            return;
          }

          resolve(strikeResults.strikes);
        });
      });
    }

    // Authenticates the session, and injects vbuser information
    // in to the request object (req)

  }, {
    key: 'authenticateSession',
    value: function authenticateSession(req, res) {
      var _this21 = this;

      debug('Calling authenticateSession()');

      // userid and password are set when you login using remember-me
      var userid = parseInt(req.cookies[this.options.cookiePrefix + 'userid'], 10) || 0;
      var password = req.cookies[this.options.cookiePrefix + 'password'];

      // sessionhash is set everywhere when navigating on vbulletin
      var sessionHash = req.cookies[this.options.cookiePrefix + 'sessionhash'];

      // queried sessionObj
      var sessionObj = null;

      return this.getActiveSession(sessionHash, this._fetchIdHash(req)).then(function (session) {
        // Check if we have remember-me set
        if (userid && password && (!session || session.userid !== userid)) {
          return _this21.checkRememberMeCredentials(userid, password);
        }

        // store session we just queried in sessionObj
        sessionObj = session;

        // doesn't have a remember me
        return Promise.resolve(true);
      }).then(function (validRememberMe) {
        if (!validRememberMe) {
          // Remember me password was wrong. Lets clear it out!
          var cookieOption = { domain: _this21.options.cookieDomain };
          res.clearCookie(_this21.options.cookiePrefix + 'userid', cookieOption);
          res.clearCookie(_this21.options.cookiePrefix + 'password', cookieOption);
          userid = 0;
        }

        // update session, or create, if user doesn't have any
        userid = sessionObj ? parseInt(sessionObj.userid, 10) : userid;
        return _this21.updateOrCreateSession(req, res, sessionHash, userid);
      });
    }

    // Logs the user in

  }, {
    key: '_login',
    value: function _login(username, pass, rememberme, loginType, req, res) {
      var _this22 = this;

      var ip = VBAuth._getIpv4(req.ip);
      var sessionHash = req.cookies[this.options.cookiePrefix + 'sessionhash'];
      var userid = 0;

      return new Promise(function (resolve, reject) {
        if (!username || !pass || username.length === 0 || pass.length === 0) {
          resolve('failed, login and password are required');
          return;
        }

        _this22.verifyStrikeStatus(username, ip).then(function (strikes) {
          if (strikes >= 5) {
            throw new Error('too many tries');
          }

          return _this22.isValidLogin(username, pass);
        }).then(function (authinfo) {
          if (!authinfo) {
            _this22.execStrikeUser(username, ip).catch(function (err) {
              return console.warn(err);
            });
            throw new Error('wrong login or password');
          }

          userid = authinfo.userid;

          _this22.execUnstrikeUser(username, ip);
          if (rememberme) {
            // set remember me cookies
            var hash = authinfo.password + _this22.options.cookieSalt;
            hash = crypto.createHash('md5').update(hash).digest('hex');

            var cookieAge = 365 * 24 * 60 * 60 * 1000;
            var cookieOptions = {
              maxAge: cookieAge,
              domain: _this22.options.cookieDomain,
              secure: _this22.options.secureCookies,
              httpOnly: true
            };
            res.cookie(_this22.options.cookiePrefix + 'userid', userid, cookieOptions);
            res.cookie(_this22.options.cookiePrefix + 'password', hash, cookieOptions);
          }

          return _this22.createSession(req, res, userid, loginType);
        }).then(function () {
          // We just gave him a new session, lets delete his old one, if he had one...
          if (sessionHash && sessionHash.length > 0) {
            _this22.deleteSession(sessionHash, false, req);
          }

          return _this22.getUserInfo(userid);
        }).then(function (userinfo) {
          req.vbuser = userinfo;

          resolve('success');
        }).catch(function (err) {
          if (err.message === 'too many tries' || err.message === 'wrong login or password') {
            resolve('failed, ' + err.message);
            return;
          }

          reject(err);
        });
      });
    }

    // Logs you out

  }, {
    key: 'logoutSession',
    value: function logoutSession(req, res) {
      var _this23 = this;

      return new Promise(function (resolve, reject) {
        // Will log you out from the currently set cookie
        var sessionhash = req.cookies[_this23.options.cookiePrefix + 'sessionhash'];

        // Clear redisCache after vBulletin logout, requires a hook
        if (req.body && req.body.redisOnly) {
          _this23.deleteSession(sessionhash, true, req).then(function () {
            return resolve();
          }).catch(function (err) {
            return reject(err);
          });
          return;
        }

        // Logs out from the current cookie session
        _this23.deleteSession(sessionhash, false, req).then(function () {
          req.vbuser = Object.assign({}, _this23.defaultUserObject);

          var cookieOptions = { domain: _this23.options.cookieDomain };
          res.clearCookie(_this23.options.cookiePrefix + 'sessionhash', cookieOptions);
          res.clearCookie(_this23.options.cookiePrefix + 'userid', cookieOptions);
          res.clearCookie(_this23.options.cookiePrefix + 'password', cookieOptions);
          res.clearCookie(_this23.options.cookiePrefix + 'imloggedin', cookieOptions);

          resolve('success');
        }).catch(function (err) {
          return reject(err);
        });
      });
    }

    // Middleware wrapper to make mustBe user, moderator, or admin...

  }, {
    key: '_mustBeMiddleware',
    value: function _mustBeMiddleware(req, res, next, func) {
      var errorMsg = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : 'Invalid request';
      var errorCode = arguments.length > 5 && arguments[5] !== undefined ? arguments[5] : 400;

      var tmp = function tmp(userinfo) {
        if (func(userinfo)) {
          next();
        } else {
          var err = new Error(errorMsg);
          err.status = errorCode;
          next(err);
        }
      };

      // This will make sure the session won't get re-authenticated
      // if you had already attached a session() middleware.
      if (!req.vbuser) {
        this.authenticateSession(req, res).then(function () {
          tmp(req.vbuser);
        }).catch(function (err) {
          if (__DEV__) {
            next(err);
            return;
          }

          console.warn(err);
          next(new Error('Database error'));
        });
      } else {
        tmp(req.vbuser);
      }
    }

    /* ******* *
     * Exports *
     * ******* */

  }, {
    key: 'session',
    value: function session() {
      var _this24 = this;

      return function (req, res, next) {
        if (!req.cookies) {
          next(new Error('cookie-parser middleware is required for vbauth to work'));
          return;
        }

        _this24.authenticateSession(req, res).then(function () {
          return next();
        }).catch(function (err) {
          if (__DEV__) {
            next(err);
            return;
          }

          console.warn(err);
          next(new Error('Database error'));
        });
      };
    }
  }, {
    key: 'logout',
    value: function logout() {
      var _this25 = this;

      return function (req, res, next) {
        _this25.logoutSession(req, res).then(function (result) {
          if (result === 'success') {
            // logged out, give the user a new empty session

            // this will prevent session() from trying to query existing session
            delete req.cookies[_this25.options.cookiePrefix + 'sessionhash'];

            // make new session
            _this25.session()(req, res, next);
          } else {
            // only deleted from redis-cache, no need to give user a new session
            next();
          }
        }).catch(function (err) {
          if (__DEV__) {
            next(err);
            return;
          }

          console.warn(err);
          next(new Error('Database error'));
        });
      };
    }
  }, {
    key: 'login',
    value: function login(username, pass, rememberme, loginType, req, res) {
      var _this26 = this;

      return new Promise(function (resolve, reject) {
        _this26._login(username, pass, rememberme, loginType, req, res).then(function (result) {
          return resolve(result);
        }).catch(function (err) {
          if (__DEV__) {
            reject(err);
            return;
          }

          console.warn(err);
          reject(new Error('Database error'));
        });
      });
    }
  }, {
    key: 'mustBeUser',
    value: function mustBeUser() {
      var _this27 = this;

      return function (req, res, next) {
        _this27._mustBeMiddleware(req, res, next, _this27.isUser);
      };
    }
  }, {
    key: 'mustBeAdmin',
    value: function mustBeAdmin() {
      var _this28 = this;

      return function (req, res, next) {
        _this28._mustBeMiddleware(req, res, next, _this28.isAdmin, 'Page not found', 404);
      };
    }
  }, {
    key: 'mustBeModerator',
    value: function mustBeModerator() {
      var _this29 = this;

      return function (req, res, next) {
        _this29._mustBeMiddleware(req, res, next, _this29.isModerator, 'Page not found', 404);
      };
    }
  }, {
    key: 'mustBe',
    value: function mustBe(func) {
      var _this30 = this;

      return function (req, res, next) {
        _this30._mustBeMiddleware(req, res, next, func, 'Page not found', 404);
      };
    }
  }], [{
    key: '_getIpv4',
    value: function _getIpv4(ip) {
      /* eslint no-param-reassign: "off"*/
      var tmpIp = ip || '';
      return tmpIp.slice(tmpIp.lastIndexOf(':') + 1);
    }

    // Cuts off the the last sessions of an ip address

  }, {
    key: '_getSubstrIp',
    value: function _getSubstrIp(ip, octectLength, defaultOctectLength) {
      var length = octectLength;
      if (octectLength === undefined || octectLength > 3) {
        length = defaultOctectLength;
      }

      var arr = ip.split('.').slice(0, 4 - length);
      return arr.join('.');
    }
  }]);

  return VBAuth;
}();

module.exports = VBAuth;
