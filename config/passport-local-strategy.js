const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { User } = require('../models/user');
const bcrypt = require('bcrypt');

// USING PASSPORT LOCAL STRATEGY
exports.initializingPassport = (passport) => {
    passport.use(new LocalStrategy({
        usernameField: 'email', // This tells Passport to use the 'email' field as the username
        passwordField: 'password',
        passReqToCallback: true,
    }, async (req, email, password, done) => {
        try {
            const user = await User.findOne({ email: email });

            // If no user is found, or the password is incorrect, return an error
    if (!user || !(await user.isValidPassword(password))) {
        return done(null, false, { message: 'Incorrect email or password.' });
    }

    return done(null, user);
        } catch (error) {
            return done(error, false);
        }
   
}));

    

    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: 'http://localhost:8800/auth/google/callback'
    },
    function(_accessToken, _refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }));

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
}

exports.isAuthenticated = (req, res, next) => {
    if (req.user) return next();
    console.log("not authenticated")
    res.status(401).json({ message: 'Not authenticated' });
}