const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { User } = require('../models/user');
const crypto = require('crypto');
require('dotenv').config();


// USING PASSPORT GOOGLE OAUTH-2.0
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:8800/auth/google/callback'
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOne({ googleId: profile.id }, function (err, user) {
      if (err) {
        return cb(err);
      }
      if (user) {
        return cb(null, user);
      } else {
        User.create({
          googleId: profile.id,
          displayName: profile.displayName,
          email: profile.emails[0].value,
          password: crypto.randomBytes(20).toString('hex')
        }, function (err, user) {
          if (err) {
            console.log('error in creating user google strategy passport', err);
            return;
          }
          return cb(null, user);
        });
      }
    });
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, false);
  }
});


app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));