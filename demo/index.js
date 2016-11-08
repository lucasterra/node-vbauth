const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const VBAuth = require('../index');
const exphbs = require('express-handlebars');

const app = express();
app.engine('.hbs', exphbs({ defaultLayout: 'main', layoutsDir: './demo/views/layouts/', extname: '.hbs' }));
app.set('views', './demo/views');
app.set('view engine', '.hbs');

const vb = new VBAuth({
  connectionLimit: 10,
  host: 'localhost',
  user: 'root',
  password: 'test',
  database: 'forum_db',
}, { subscriptions: true, redisCache: false, cookieSalt: null });

// Cookie parser is required for vbauth to work
app.use(cookieParser());

// Middleware to inject vbuser in exoress' req
app.use(vb.session());

// Login page
app.get('/login', (req, res) => {
  res.render('login');
});

// Posts page, only users can access this -> vb.mustBeUser()
app.get('/posts', vb.mustBeUser(), (req, res) => {
  res.render('home', { page: 'Posts' });
});

// Admin page, only admins can access this -> vb.mustBeAdmin()
app.get('/admincp', vb.mustBeAdmin(), (req, res) => {
  res.render('home', { page: 'AdminCP' });
});

// Moderators page, only mods can access this -> vb.mustBeModerator()
app.get('/modcp', vb.mustBeModerator(), (req, res) => {
  res.render('home', { page: 'ModCP' });
});

// Displays the userinfo
app.get('*', (req, res) => {
  res.render('userinfo', { vbuser: req.vbuser });
});

// Performs the login
app.post('/login', bodyParser.urlencoded({ extended: true }), (req, res) => {
  if (req.vbuser.userid > 0) {
    res.redirect('/');
    return;
  }

  vb.login(req.body.username, req.body.password, req.body.remember, null, req, res)
    .then((result) => {
      if (result !== 'success') {
        res.render('login', { error: result });
        return;
      }

      res.redirect('/');
    })
    .catch(err => res.send(err));
});

// Performs logout
app.post('/logout', (req, res) => {
  vb.logout(req, res)
    .then(() => res.redirect('/'))
    .catch((err) => res.send(err));
});

// error handler
app.use((err, req, res, next) => {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

app.listen(3000, () => {
  console.log('vBAuth Example listening on port 3000!');
});
