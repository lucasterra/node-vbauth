/* eslint no-underscore-dangle: ["off"] */
/* eslint no-console: ["error", { allow: ["warn", "error"] }] */
/* eslint class-methods-use-this: "error"*/
/* eslint comma-dangle: ["error", {"arrays": "always-multiline", "objects": "always-multiline", "functions": "ignore"}] */
const crypto = require('crypto');
const moment = require('moment');
const _debug = require('debug');
const mysql = require('mysql');
const parallel = require('async/parallel');
const series = require('async/series');
const colors = require('colors/safe');

const debug = _debug('vbauth');
debug('Initializing vbauth');

const __DEV__ = process.env.NODE_ENV !== 'production';

// e-mail confirmed / not banned users
const _isUser = userinfo => (
  userinfo.usergroupid > 1 &&
  userinfo.usergroupid !== 8 && // banned
  userinfo.usergroupid !== 3 && // awaiting email confirmation
  userinfo.usergroupid !== 4    // awaiting moderation
);

// admins
const _isAdmin = userinfo => userinfo.usergroupid === 6;

// admins, moderators and super moderators
const _isModerator = userinfo => userinfo.usergroupid >= 5 && userinfo.usergroupid <= 7;

class VBAuth {
  constructor(database, options) {
    if (typeof options.cookieSalt !== 'string' || options.cookieSalt.length === 0) {
      console.error(colors.red('A cookieSalt must be specified in VBAuth.options! You can find your cookie salt at \'includes/functions.php\' of your vBulletin install folder.\nIf you don\'t specify the correct cookie salt "remember-me cookies" won\'t work'));
    }

    if (!database) {
      throw new Error('You must pass the database information on vbauth initialization');
    } else if ({}.hasOwnProperty.call(database, 'connectionLimit') &&
        {}.hasOwnProperty.call(database, 'host') &&
        {}.hasOwnProperty.call(database, 'user') &&
        {}.hasOwnProperty.call(database, 'password') &&
        {}.hasOwnProperty.call(database, 'database')) {
      this.database = mysql.createPool(database);
    } else if (!{}.hasOwnProperty.call(database, 'config')) {
      throw new Error('Invalid MySQL info passed on vbauth initialization');
    } else {
      // an actual mysql pool was passed
      this.database = database;
    }

    this.options = Object.assign(options, {
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
    });

    this.defaultUserObject = {
      userid: 0,
      username: 'unregistered',
      usergroupid: 1,
      membergroupids: '',
      email: '',
      posts: 0,
    };

    if (this.options.subscriptions) {
      this.defaultUserObject.subscriptionexpirydate = 0;
      this.defaultUserObject.subscriptionstatus = 0;
    }

    this.isUser = options.isUser || _isUser;
    this.isModerator = options.isModerator || _isModerator;
    this.isAdmin = options.isAdmin || _isAdmin;

    // enable query logging
    if (debug.enabled) {
      const originalQuery = this.database.query;

      this.database.query = (...args) => {
        if (args.length === 3) {
          debug(mysql.format(args[0], args[1]));
        } else if (args.length === 2) {
          debug(args[0]);
        }

        originalQuery.apply(this.database, args);
      };
    }
  }

  // Removes ipv6 from req.ip
  static _getIp(req) {
    const ip = req.ip || '';
    return ip.slice(ip.lastIndexOf(':') + 1);
  }

  // Unique id based on user ip and user agent
  static _fetchIdHash(req) {
    let ip = req.ip;
    ip = ip.slice(ip.lastIndexOf(':') + 1, ip.lastIndexOf('.'));

    return crypto.createHash('md5')
      .update(req.header('user-agent') + ip)
      .digest('hex');
  }

  // Tries to get a login type for session authentication
  static _getLoginTypeFromUserAgent(useragent) {
    if (useragent) {
      if (useragent.match(/^WindCloud/i)) {
        return 'windcloud-app';
      } else if (useragent.match(/^WindBot/i)) {
        return 'windbot-client';
      }
    }

    return null;
  }

  _mysqlCreateSession(userid, ip, idHash, sessionHash, url, userAgent, loginType) {
    return new Promise((resolve, reject) => {
      if (!this.options.refreshActivity ||
          loginType === 'windbot-client' ||
          loginType === 'windcloud-app') {
        resolve(sessionHash);
        return;
      }

      const query = mysql.format(
        'INSERT INTO session' +
        ' (userid, sessionhash, host, idhash, lastactivity, location, useragent, loggedin)' +
        ' VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [
          userid,
          sessionHash,
          ip,
          idHash,
          moment().unix(),
          url,
          userAgent,
          (userid > 0),
        ]
      );

      this.database.query(query, (err) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(sessionHash);
      });
    });
  }

  _redisCreateSession(userid, ip, idHash, sessionHash, url, userAgent) {
    return new Promise((resolve, reject) => {
      if (!this.options.redisCache) {
        resolve();
        return;
      }

      const key = `vbsession:${sessionHash}`;

      const multi = this.options.redisCache.multi();
      multi.hmset(key, {
        userid,
        sessionhash: sessionHash,
        host: ip,
        idhash: idHash,
        lastactivity: moment().unix(),
        location: url,
        useragent: userAgent,
        loggedin: (userid > 0),
      });
      multi.expire(key, this.options.cookieTimeout);
      multi.exec((err) => {
        if (err) {
          reject(err);
          return;
        }

        resolve();
      });
    });
  }

  // Create a new session in the database for the user
  createSession(req, res, userid, loginType) {
    const ip = VBAuth._getIp(req);
    const idHash = VBAuth._fetchIdHash(req);
    const url = (this.options.defaultPath ? this.options.defaultPath : req.path);
    const userAgent = req.header('user-agent').slice(0, 100);
    let hash = moment().valueOf().toString() + userid + ip;
    hash = crypto.createHash('md5')
      .update(hash)
      .digest('hex');

    // Sets cookie to the response
    res.cookie(`${this.options.cookiePrefix}sessionhash`, hash, {
      domain: this.options.cookieDomain,
      httpOnly: true,
    });

    // Use Redis cache, if available
    this._redisCreateSession(userid, ip, idHash, hash, url, userAgent);

    // Returns a promise
    return this._mysqlCreateSession(userid, ip, idHash, hash, url, userAgent, loginType);
  }

  _mysqlUpdateUserActivity(userid, sessionHash, lastUrl, loginType) {
    return new Promise((resolve, reject) => {
      if (!this.options.refreshActivity ||
          loginType === 'windbot-client' ||
          loginType === 'windcloud-app') {
        resolve(true);
        return;
      }

      const query = mysql.format(
        `UPDATE session SET 
          lastactivity = ?,
          location = ?,
          userid = ?,
          loggedin = ? 
          WHERE sessionhash = ?`,
        [
          moment().unix(),
          lastUrl,
          userid,
          (userid > 0),
          sessionHash,
        ]
      );

      this.database.query(query, (err, result) => {
        if (err) {
          reject(err);
          return;
        }

        resolve((result.affectedRows > 0));
      });
    });
  }

  _redisUpdateUserActivity(userid, sessionHash, lastUrl) {
    return new Promise((resolve, reject) => {
      const key = `vbsession:${sessionHash}`;

      if (!this.options.redisCache) {
        resolve(false); // redis not available
        return;
      }

      this.options.redisCache.exists(key, (err, exists) => {
        if (err) {
          reject(err);
          return;
        }
        if (!exists) {
          resolve(false); // not updated
          return;
        }

        const multi = this.options.redisCache.multi();
        multi.hmset(key, {
          lastactivity: moment().unix(),
          location: lastUrl,
          userid,
          loggedin: (userid > 0),
        });
        multi.expire(key, this.options.cookieTimeout);
        multi.exec((err2) => {
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
  updateUserActivity(lastUrl, userid, sessionHash, loginType) {
    if (!sessionHash || sessionHash.length === 0) {
      return Promise.resolve(false);
    }

    return this._redisUpdateUserActivity(userid, sessionHash, lastUrl)
      .then((updated) => {
        if (!updated) {
          return this._mysqlUpdateUserActivity(userid, sessionHash, lastUrl, loginType);
        }

        return Promise.resolve(updated);
      });
  }

  // Deletes a session
  deleteSession(sessionhash, redisOnly) {
    return new Promise((resolve, reject) => {
      if (typeof sessionhash !== 'string') {
        resolve(true);
        return;
      }

      parallel([
        (cb) => {
          if (redisOnly || !this.options.refreshActivity) {
            return cb(null, true);
          }

          const query = mysql.format('DELETE FROM session WHERE sessionhash = ?', [sessionhash]);
          return this.database.query(query, err => cb(err, true));
        },
        (cb) => {
          if (!this.options.redisCache) {
            return cb(null, true);
          }

          return this.options.redisCache.del(`vbsession:${sessionhash}`, err => cb(err, true));
        },
      ], (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(true);
      });
    });
  }

  // Returns the userinfo if the username/password are valid, or null if it's not valid
  isValidLogin(username, password) {
    return new Promise((resolve, reject) => {
      const query = mysql.format('SELECT userid, password FROM user WHERE ' +
        'username = ? AND ' +
        '(password = md5(concat(?, salt)) OR password = md5(concat(md5(?), salt)))',
        [username, password, password]
      );

      this.database.query(query, (err, rows) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(rows[0]);
      });
    });
  }

  // Returns true if the cookie userid/password is valid, false otherwise
  checkRememberMeCredentials(userid, password) {
    return new Promise((resolve, reject) => {
      const query = mysql.format('SELECT userid FROM user' +
        ' WHERE userid = ? AND md5(concat(password, ?)) = ?',
        [userid, this.options.cookieSalt, password]
      );

      this.database.query(query, (err, rows) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(rows.length > 0);
      });
    });
  }

  _redisStoreUserInfo(userinfo) {
    return new Promise((resolve, reject) => {
      if (!this.options.redisCache) {
        resolve(true);
        return;
      }

      const key = `vbuser:${userinfo.userid}`;

      const multi = this.options.redisCache.multi();
      multi.hmset(key, userinfo);
      multi.expire(key, this.options.cookieTimeout);
      multi.exec((err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(true);
      });
    });
  }

  _redisGetUserInfo(userid) {
    return new Promise((resolve, reject) => {
      if (!this.options.redisCache) {
        resolve(null);
        return;
      }

      const key = `vbuser:${userid}`;
      this.options.redisCache.hgetall(key, (err, results) => {
        if (err) {
          return reject(err);
        }

        if (!results) {
          return resolve(null);
        }

        const ret = results;
        ret.userid = parseInt(results.userid, 10);
        ret.usergroupid = parseInt(results.usergroupid, 10);
        ret.posts = parseInt(results.posts, 10);
        if (this.options.subscriptions) {
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

  _mysqlGetUserInfo(userid) {
    return new Promise((resolve, reject) => {
      let subscriptionFields = '';
      let subscriptionJoin = '';
      if (this.options.subscriptions) {
        subscriptionFields = `, IFNULL(b.status, 0) AS subscriptionstatus,
                                IFNULL(b.expirydate, 0) AS subscriptionexpirydate`;
        subscriptionJoin = `LEFT JOIN subscriptionlog AS b
                            ON a.userid = b.userid AND b.subscriptionid = 1`;
      }

      const query = `SELECT a.userid, a.username,
                            a.usergroupid, a.membergroupids,
                            a.email, a.posts${subscriptionFields}
                            FROM user AS a ${subscriptionJoin}
                            WHERE a.userid = ${mysql.escape(userid)}`;

      this.database.query(query, (err, rows) => {
        if (err) {
          reject(err);
          return;
        }

        const userinfo = rows[0];
        if (!userinfo) {
          console.warn('User does not exist');
          resolve(null);
          return;
        }

        this._redisStoreUserInfo(userinfo);
        resolve(userinfo);
      });
    });
  }

  // Get user info
  getUserInfo(userid) {
    // Avoid performing this query if the user is not authenticated
    if (!userid || userid === 0) {
      return Promise.resolve(Object.assign({}, this.defaultUserObject));
    }

    return this._redisGetUserInfo()
      .then((userinfo) => {
        if (!userinfo) {
          return this._mysqlGetUserInfo(userid);
        }

        return Promise.resolve(userinfo);
      });
  }

  _mysqlGetActiveSession(sessionHash, idHash) {
    return new Promise((resolve, reject) => {
      const query = mysql.format('SELECT * FROM session' +
        ' WHERE sessionhash = ? AND idhash = ? AND lastactivity > ?',
        [sessionHash, idHash, moment().unix() - this.options.cookieTimeout]
      );

      this.database.query(query, (err, rows) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(rows[0]);
      });
    });
  }

  _redisGetActiveSession(sessionHash, idHash) {
    return new Promise((resolve, reject) => {
      if (!this.options.redisCache) {
        resolve(null);
        return;
      }

      const key = `vbsession:${sessionHash}`;
      this.options.redisCache.hgetall(key, (err, results) => {
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
  getActiveSession(sessionHash, idHash) {
    return new Promise((resolve, reject) => {
      if (!sessionHash || sessionHash.length === 0) {
        resolve(null);
        return;
      }

      this._redisGetActiveSession(sessionHash, idHash)
        .then((session) => {
          if (!session) {
            return this._mysqlGetActiveSession(sessionHash, idHash);
          }

          return Promise.resolve(session);
        })
        .then(session => resolve(session))
        .catch(err => reject(err));
    });
  }

  // Just for code reusing
  updateOrCreateSession(req, res, sessionHash, userid, loginType) {
    /* eslint no-param-reassign: ["error", { "props": false }] */
    return new Promise((resolve, reject) => {
      // Append user info to request object
      req.vbuser = { userid };
      const url = this.options.defaultPath ? this.options.defaultPath : req.path;

      // call those in parallel
      const callArray = [
        cb => this.getUserInfo(userid).then(userinfo => cb(null, userinfo)).catch(err => cb(err)),
        cb =>
          // this will return right away if sessionHash is null, or empty
          this.updateUserActivity(url, userid, sessionHash, loginType)
          .then((updated) => {
            if (!updated) {
              // if for some reason his old session wasn't in the db, then just make him a new one
              // this should never happen, but just in case...
              return this.createSession(req, res, userid, loginType);
            }

            return Promise.resolve(sessionHash);
          })
          .then(hash => cb(null, hash))
          .catch(err => cb(err)),
      ];

      // After the tasks have been done, we may get back to where we were...
      parallel(callArray, (err, results) => {
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
  execStrikeUser(username, userip) {
    return new Promise((resolve, reject) => {
      if (!this.options.useStrikeSystem) {
        resolve(null);
        return;
      }

      const query = mysql.format('INSERT INTO strikes ' +
                      '(striketime, strikeip, username) ' +
                      'VALUES ' +
                      '(?, ?, ?)',
                      [moment().unix(), userip, username]
      );

      this.database.query(query, (err) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(null);
      });
    });
  }

  // Removes his login strikes after a successful login
  execUnstrikeUser(username, userip) {
    return new Promise((resolve, reject) => {
      if (!this.options.useStrikeSystem) {
        resolve(null);
        return;
      }

      const query = mysql.format(
        'DELETE FROM strikes WHERE strikeip = ? AND username = ?',
        [userip, username]
      );

      this.database.query(query, (err) => {
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
  verifyStrikeStatus(username, userip) {
    return new Promise((resolve, reject) => {
      if (!this.options.useStrikeSystem) {
        resolve(0);
        return;
      }

      const deleteQuery = mysql.format('DELETE FROM strikes WHERE striketime < ?',
        [moment().unix() - 3600]
      );
      const selectQuery = mysql.format('SELECT COUNT(*) AS strikes, MAX(striketime) AS lasttime ' +
        'FROM strikes ' +
        'WHERE strikeip = ?',
        [userip]
      );

      series([
        cb => this.database.query(deleteQuery, cb),
        cb => this.database.query(selectQuery, cb),
      ], (err, results) => {
        if (err) {
          reject(err);
          return;
        }

        const strikeResults = results[1][0][0];

        if (strikeResults.strikes >= 5 && strikeResults.lasttime > moment().unix() - 900) {
          // they've got it wrong 5 times or greater for any username at the moment

          // the user is still not giving up so lets keep increasing this marker
          this.execStrikeUser(username, userip).catch(err2 => console.warn(err2));
          resolve(strikeResults.strikes + 1);
          return;
        }

        resolve(strikeResults.strikes);
      });
    });
  }

  // Authenticates the session, and injects vbuser information
  // in to the request object (req)
  authenticateSession(req, res) {
    debug('Calling authenticateSession()');

    // userid and password are set when you login using remember-me
    let userid = parseInt(req.cookies[`${this.options.cookiePrefix}userid`], 10) || 0;
    const password = req.cookies[`${this.options.cookiePrefix}password`];

    // sessionhash is set everywhere when navigating on vbulletin
    const sessionHash = req.cookies[`${this.options.cookiePrefix}sessionhash`];

    // loginType
    const loginType = VBAuth._getLoginTypeFromUserAgent(req.header('user-agent'));

    // queried sessionObj
    let sessionObj = null;

    return this.getActiveSession(sessionHash, VBAuth._fetchIdHash(req))
    .then((session) => {
      // Check if we have remember-me set
      if (userid && password && (!session || session.userid !== userid)) {
        return this.checkRememberMeCredentials(userid, password);
      }

      // store session we just queried in sessionObj
      sessionObj = session;

      // doesn't have a remember me
      return Promise.resolve(true);
    }).then((validRememberMe) => {
      if (!validRememberMe) {
        // Remember me password was wrong. Lets clear it out!
        const cookieOption = { domain: this.options.cookieDomain };
        res.clearCookie(`${this.options.cookiePrefix}userid`, cookieOption);
        res.clearCookie(`${this.options.cookiePrefix}password`, cookieOption);
        userid = 0;
      }

      // update session, or create, if user doesn't have any
      userid = sessionObj ? sessionObj.userid : userid;
      return this.updateOrCreateSession(req, res, sessionHash, userid, loginType);
    });
  }

  // Logs the user in
  _login(username, pass, rememberme, loginType, req, res) {
    const ip = VBAuth._getIp(req);
    const sessionHash = req.cookies[`${this.options.cookiePrefix}sessionhash`];
    let userid = 0;

    return new Promise((resolve, reject) => {
      if (!username || !pass || username.length === 0 || pass.length === 0) {
        resolve('failed, login and password are required');
        return;
      }

      this.verifyStrikeStatus(username, ip).then((strikes) => {
        if (strikes >= 5) {
          throw new Error('too many tries');
        }

        return this.isValidLogin(username, pass);
      }).then((authinfo) => {
        if (!authinfo) {
          this.execStrikeUser(username, ip).catch(err => console.warn(err));
          throw new Error('wrong login or password');
        }

        userid = authinfo.userid;

        this.execUnstrikeUser(username, ip);
        if (rememberme) {
          // set remember me cookies
          let hash = authinfo.password + this.options.cookieSalt;
          hash = crypto.createHash('md5')
            .update(hash)
            .digest('hex');

          const cookieAge = (365 * 24 * 60 * 60 * 1000);
          const cookieOptions = {
            maxAge: cookieAge,
            domain: this.options.cookieDomain,
            secure: this.options.secureCookies,
            httpOnly: true,
          };
          res.cookie(`${this.options.cookiePrefix}userid`, userid, cookieOptions);
          res.cookie(`${this.options.cookiePrefix}password`, hash, cookieOptions);
        }

        return this.createSession(req, res, userid, loginType);
      }).then(() => {
        // We just gave him a new session, lets delete his old one, if he had one...
        if (sessionHash && sessionHash.length > 0) {
          this.deleteSession(sessionHash, false);
        }

        return this.getUserInfo(userid);
      })
      .then((userinfo) => {
        req.vbuser = userinfo;

        resolve('success');
      })
      .catch((err) => {
        if (err.message === 'too many tries' || err.message === 'wrong login or password') {
          resolve(`failed, ${err.message}`);
          return;
        }

        reject(err);
      });
    });
  }

  // Logs you out
  logoutSession(req, res) {
    return new Promise((resolve, reject) => {
      // Clear redisCache after vBulletin logout, requires a hook
      if (req.query.hash) {
        this.deleteSession(req.query.hash, true)
          .then(() => resolve('success'))
          .catch(err => reject(err));
        return;
      }

      // Logs out from the current cookie session
      const sessionhash = req.cookies[`${this.options.cookiePrefix}sessionhash`];
      this.deleteSession(sessionhash, false).then(() => {
        req.vbuser = Object.assign({}, this.defaultUserObject);

        const cookieOptions = { domain: this.options.cookieDomain };
        res.clearCookie(`${this.options.cookiePrefix}sessionhash`, cookieOptions);
        res.clearCookie(`${this.options.cookiePrefix}userid`, cookieOptions);
        res.clearCookie(`${this.options.cookiePrefix}password`, cookieOptions);
        res.clearCookie(`${this.options.cookiePrefix}imloggedin`, cookieOptions);

        resolve('success');
      }).catch(err => reject(err));
    });
  }

  // Middleware wrapper to make mustBe user, moderator, or admin...
  _mustBeMiddleware(req, res, next, func, errorMsg = 'Invalid request', errorCode = 400) {
    const tmp = (userinfo) => {
      if (func(userinfo)) {
        next();
      } else {
        const err = new Error(errorMsg);
        err.status = errorCode;
        next(err);
      }
    };

    // This will make sure the session won't get re-authenticated
    // if you had already attached a session() middleware.
    if (!req.vbuser) {
      this.authenticateSession(req, res)
      .then(() => {
        tmp(req.vbuser);
      })
      .catch((err) => {
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

  session() {
    return (req, res, next) => {
      if (!req.cookies) {
        next(new Error('cookie-parser middleware is required for vbauth to work'));
        return;
      }

      this.authenticateSession(req, res)
      .then(() => next())
      .catch((err) => {
        if (__DEV__) {
          next(err);
          return;
        }

        console.warn(err);
        next(new Error('Database error'));
      });
    };
  }

  logout(req, res) {
    return new Promise((resolve, reject) => {
      this.logoutSession(req, res)
      .then(() => resolve())
      .catch((err) => {
        if (__DEV__) {
          reject(err);
          return;
        }

        console.warn(err);
        reject(new Error('Database error'));
      });
    });
  }

  login(username, pass, rememberme, loginType, req, res) {
    return new Promise((resolve, reject) => {
      this._login(username, pass, rememberme, loginType, req, res)
      .then(result => resolve(result))
      .catch((err) => {
        if (__DEV__) {
          reject(err);
          return;
        }

        console.warn(err);
        reject(new Error('Database error'));
      });
    });
  }

  mustBeUser() {
    return (req, res, next) => {
      this._mustBeMiddleware(req, res, next, this.isUser);
    };
  }

  mustBeAdmin() {
    return (req, res, next) => {
      this._mustBeMiddleware(req, res, next, this.isAdmin, 'Page not found', 404);
    };
  }

  mustBeModerator() {
    return (req, res, next) => {
      this._mustBeMiddleware(req, res, next, this.isModerator, 'Page not found', 404);
    };
  }

  mustBe(func) {
    return (req, res, next) => {
      this._mustBeMiddleware(req, res, next, func, 'Page not found', 404);
    };
  }
}

module.exports = VBAuth;