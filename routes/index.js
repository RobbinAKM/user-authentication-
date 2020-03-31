var express = require('express');
var router = express.Router();
var User = require('../models/user');
var mid= require('../middleware');
var async= require('async');
var nodemailer= require('nodemailer');
var crypto = require('crypto');

// GET /register
router.get('/register',mid.loggedOut, function(req, res, next) {
  return res.render('register', { title: 'Sign Up' });
});

// POST /register
router.post('/register', function(req, res, next) {
  if (req.body.email &&
    req.body.name &&
    req.body.favoriteBook &&
    req.body.password &&
    req.body.confirmPassword) {

      // confirm that user typed same password twice
      if (req.body.password !== req.body.confirmPassword) {
        var err = new Error('Passwords do not match.');
        err.status = 400;
        return next(err);
      }

      // create object with form input
      var userData = {
        email: req.body.email,
        name: req.body.name,
        favoriteBook: req.body.favoriteBook,
        password: req.body.password
      };

      // use schema's `create` method to insert document into Mongo
      User.create(userData, function (error, user) {
        if (error) {
          return next(error);
        } else {
          return res.redirect('/signupfinish');
        }
      });

    } else {
      var err = new Error('All fields required.');
      err.status = 400;
      return next(err);
    }
})

//GET sign up finished
router.get('/signupfinish',mid.loggedOut, function(req, res, next) {
  return res.render('signupfinish', { title: 'Welcome' });
});

// GET /
router.get('/', function(req, res, next) {
  return res.render('index', { title: 'Home' });
});

// GET /about
router.get('/about',mid.requiresLogin, function(req, res, next) {
  return res.render('about', { title: 'About' });
});

// GET /contact
router.get('/contact', function(req, res, next) {
  return res.render('contact', { title: 'Contact' });
});

//GET login
router.get('/login', mid.loggedOut,function(req, res, next) {
  return res.render('login', { title: 'Login' });
});

//POST login data
router.post('/login', function(req, res, next) {
if(req.body.email && req.body.password){
  User.authenticate(req.body.email , req.body.password ,function(err,user){
   if(err || !user ){
     var err = new Error('wrong email or password');
     err.status=401;
     return next(err);
   }else {
     req.session.userId = user._id;
     return res.redirect('/profile');
   }
  });
}else {
var err = new Error('Email and password must be correctly flled');
err.status=401;
 return next(err);
 }
});

//GET profile
router.get('/profile', function(req, res, next) {
  if (! req.session.userId ) {
    var err = new Error("You are not authorized to view this page.");
    err.status = 403;
    return next(err);
  }
  User.findById(req.session.userId)
      .exec(function (error, user) {
        if (error) {
          return next(error);
        } else {
          return res.render('profile', { title: 'Profile', name: user.name, favorite: user.favoriteBook });
        }
      });
});

//GET logout
router.get('/logout', function(req, res, next) {
  if(req.session){
    req.session.destroy(function(err){
      if(err){
        next(err);
      }else {
        return res.redirect('/');
      }
    });
  }
});

//GET forget Password
router.get('/forgot', function(req, res, next) {
  return res.render('forgot', { title: 'Recover Password' });
});

//POST forget Password
router.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {

        var token = buf.toString('hex');
        done(err, token);
   });

    },

    function(token, done) {

      User.findOne({ email: req.body.email }, function(err, user) {

        if (!user) {

          req.flash('error', 'No account with that email address exists.');

          return res.redirect('/forgot');

        }



        user.resetPasswordToken = token;

        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour



        user.save(function(err) {

          done(err, token, user);

        });

      });

    },

    function(token, user, done) {

      var smtpTransport = nodemailer.createTransport({
       host: 'smtp.gmail.com',

       port: 587,

      secure: false,

      requireTLS: true,

        auth: {

          user: 'codingcampfortester@gmail.com',

          pass: 'treehouse97'

        }

      });

      var mailOptions = {

        to: user.email,

        from: 'codingcampfortester@gmail.com',

        subject: 'Node.js Password Reset',

        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +

          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +

          'http://' + req.headers.host + '/reset/' + token + '\n\n' +

          'If you did not request this, please ignore this email and your password will remain unchanged.\n'

      };

      smtpTransport.sendMail(mailOptions, function(err) {

        console.log('mail sent');

        req.flash('success', 'An e-mail has been sent to ' + user.email + ' with further instructions.');

        done(err, 'done');

      });

    }

  ], function(err) {

    if (err) return next(err);

    res.redirect('/forgot');

  });

});

//GET reset
router.get('/reset/:token', function(req, res) {

  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {

    if (!user) {

      req.flash('error', 'Password reset token is invalid or has expired.');

      return res.redirect('/forgot');

    }

    res.render('reset', {token: req.params.token});

  });

});

//POST reset password
router.post('/reset/:token', function(req, res) {

  async.waterfall([

    function(done) {

      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {

        if (!user) {

          req.flash('error', 'Password reset token is invalid or has expired.');

          return res.redirect('back');

        }

        if(req.body.password === req.body.confirmPassword) {

          user.setPassword(req.body.password, function(err) {

            user.resetPasswordToken = undefined;

            user.resetPasswordExpires = undefined;



            user.save(function(err) {

              req.logIn(user, function(err) {

                done(err, user);

              });

            });

          })

        } else {

            req.flash("error", "Passwords do not match.");

            return res.redirect('back');

        }

      });

    },

    function(user, done) {

      var smtpTransport = nodemailer.createTransport({

        host: 'smtp.gmail.com',

        port: 587,

       secure: false,

       requireTLS: true,

        auth: {

          user: 'codingcampfortester@gmail.com',

          pass: 'treehouse97'

        }

      });

      var mailOptions = {

        to: user.email,

        from: 'codingcampfortester@gmail.com',

        subject: 'Your password has been changed',

        text: 'Hello,\n\n' +

          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'

      };

      smtpTransport.sendMail(mailOptions, function(err) {

        req.flash('success', 'Success! Your password has been changed.');

        done(err);

      });

    }

  ], function(err) {

    res.redirect('/profile');

  });

});
module.exports = router;
