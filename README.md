# Node vBAuth

This module provides SSO (Single Sign-On) support for vBulletin accounts and your Node.js powered website.

## Installing
```
npm install --save vbauth
```

## Usage
### Node 6
```js
const VBAuth = require('vbauth');
const vbauth = new VBAuth(database, options);
```

### Node 4
```js
const VBAuth = require('vbauth/legacy');
const vbauth = new VBAuth(database, options);
```

More examples can be seem in the API section.

## API

### VBAuth(database, options) -> Constructor

`database` can be either a `mysql` connection or pool. Or you can pass the parameters to construct a [mysql-pool](https://github.com/mysqljs/mysql/blob/master/Readme.md#pooling-connections)

`options` can have the following properties
* `cookieSalt`: Used to salt the remember me password before setting the cookie. **This must match the value located at the file `includes/functions.php` of your vBulletin install** (Default:
  `''`)
* `cookiePrefix`: Cookie prefix used by vBulletin. (Default: `'bb_'`)
* `cookieTimeout`: How long it takes for a session to timeout in seconds. (Default: `900`)
* `cookieDomain`: The domain to install the cookie to. (Default: `''`)
* `defaultPath`: Default path, for activity refresh. Set a `url` as *string*, or `null`. `null` defaults to `req.path`. (Default: `'http://my.domain.com'`)
* `useStrikeSystem`: The strike system will block the user from trying to log in after 5 wrong tries. (Default: `true`)
* `refreshActivity`: Should it refresh activity or not? If not, it will simply attach the userinfo to the request object, and will not make any writes or updates in to the Forum database. (Default: `true`)
* `secureCookies`: Use Secure cookies for remember-me cookie. Secure cookies only gets stored if transmitted via TSL/SSL (https sites) (Default: `false`)
* `subscriptions`: Query user subscriptions? By default, it will query the subscription with id = 1. (Default: `true`)
* `subscriptionId`: Subscription id to query. (Default: `1`)
* `isUser`: function called to check whether a user is authenticated or not. (Default: `userinfo => (userinfo.usergroupid > 1 && userinfo.usergroupid !== 8 /* banned */ && userinfo.usergroupid !== 3 /* awaiting email confirmation */ && userinfo.usergroupid !== 4 /* awaiting moderation */)`)
* `isAdmin`: function called to check whether a user is an admin or not. (Default: `userinfo => userinfo.usergroupid === 6`)
* `isModerator`: function called to check whether a user is a moderator or not. (Default: `userinfo => userinfo => userinfo.usergroupid >= 5 && userinfo.usergroupid <= 7`)

Example:
```js
const VBAuth = require('vbauth');

const vbauth = new VBAuth({
  host: 'localhost',
  user: 'root',
  password: 'test',
  database: 'my_vbulletin_database',
  connectionLimit: 10,
}, {
  cookieSalt: 'My_vBulletin_cookieSalt', // this is mandatory, you must change this one
});
```

### session() -> Express-like Middleware

An Express/Connect middleware that injects information (`vbuser`) about the currently logged in user in to the `req` object.

Example:
```js
const express = require('express');
const VBAuth = require('vbauth');

const vbauth = new VBAuth(database, options);
const app = express();

app.use(vbauth.session()); // from here on, you can access the user's information by accessing req.vbuser 
```

### mustBeUser() -> Express-like Middleware

An Express/Connect middleware that will only allow users to access a route. This uses `options.isUser` function to determine whether the user is authenticated or not.

Example:
```js
const express = require('express');
const VBAuth = require('vbauth');

const vbauth = new VBAuth(database, options);
const app = express();

// anyone can access this route
app.get('/', (req, res) => {
    res.send('welcome home');
});

// only authenticated users can access the routes below
app.use(vbauth.mustBeUser());
app.get('/posts', (req, res) => {
    res.send('welcome to posts')
}) 
```

### mustBeAdmin() -> Express-like Middleware

An Express/Connect middleware that will only allow admins to access a route. This uses `options.isAdmin` function to determine whether the user is an admin or not.

### mustBeModerator() -> Express-like Middleware

An Express/Connect middleware that will only allow moderators to access a route. This uses `options.isModerator` function to determine whether the user is a moderator or not.

### login(login, password, remember, loginType, req, res) -> Promise

Tries to perform a login using `login` and `password`. You can also pass `remember` as `true`/`false` if you want a persistent session. `loginType` can be used for admin/mods login, but it's not implemented yet. `req` and `res` come from the Express Route.
The promise can return 4 values:
* `'success'`: authentication went ok.
* `failed, login and password are required`: user name and password was not specified.
* `failed, too many tries`: user typed the wrong password for 5 times in less than 15 minutes.
* `failed, wrong login or password`: incorrect user name or password.

### logout() -> Express-like Middleware

Will erase the session from the database and erase user cookies.

### req.vbuser -> Object 

This object gets injected if you attach the `session()` middleware or any of the `mustBe*` middlewares.

Properties:
* `userid`: the userid of the currently authenticated user.
* `username`: the username of the currently authenticated user.
* `usergroupid`: the usergroupid of the currently authenticated user.
* `membergroupids`: the membergroupids of the currently authenticated user.	
* `email`: the e-mail of the currently authenticated user.
* `posts`: the amount of posts made by currently authenticated user.
* `subscriptionstatus`: user's subscription status (only if `options.subscriptions` is `true`).
* `subscriptionexpirydate`:	user's subscription expiry date in unix timestamp (only if `options.subscriptions` is `true`).

## Debugging

[debug](https://www.npmjs.com/package/debug) is used to print out all the MySQL queries performed by vbauth. To enable debug you must launch your app with `DEBUG=vbauth`.

Example:
Unix
```
DEBUG=vbauth node app.js
```

Windows 
```
set DEBUG=vbauth & node app.js
```