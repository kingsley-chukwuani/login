// Require necessary modules and User model
const passport = require('passport');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { check, validationResult } = require('express-validator');
const { User } = require('../models/user');
const { initializingPassport, isAuthenticated } = require('../config/passport-local-strategy');

// Helper function to extract user input from the request body
function getUserInput(req) {
    return {
        displayName: req.body.displayName,
        email: req.body && req.body.email ? req.body.email.toLowerCase() : null,
        password: req.body.password,
        confirmPassword: req.body.confirmPassword
    };
}

// Render the login page with any flash error messages
module.exports.get_login = (req, res) => {
    const errors = req.flash('error') || [];
    res.json({ user: req.user, errors });
};

module.exports.post_login = (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            const message = info ? info.message : 'Authentication failed';
            return res.status(400).json({ errors: [info.message] });
        }
        req.logIn(user, function(err) {
            if (err) { 
                return next(err); 
            }
            return res.json({ user });
        });
    })(req, res, next);
};

// Handle the POST request for user signup
module.exports.post_signup = async (req, res, next) => {
    try {
        // Extract user input data from the request body
        const { displayName, email, password } = getUserInput(req);

        // Check if the email already exists in the database
        const user = await User.findOne({ email: email });
        if (user) {
            return res.status(400).json({
                user: req.user,
                errorMessage: 'User Already Exists',
                oldInput: { displayName, email, password },
                validationErrors: []
            });
        }

        // Perform validation on user input using express-validator
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log(errors.array());
            return res.status(422).json({
                user: req.user,
                errorMessage: errors.array()[0].msg,
                oldInput: { displayName, email, password },
                validationErrors: errors.array()
            });
        }

        // Generate a salt and hash the password before storing it
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // If user input is valid, create a new user object and save it to the database
        const newUser = new User({ displayName, email, password: hashedPassword });
        await newUser.save();
        console.log(newUser);
        
        // Send a JSON response after successful signup
        res.json({ message: 'Signup successful', user: newUser });
    } catch (err) {
        console.error(err);
        res.status(500).json({ errorMessage: 'Server error' });
    }
};

// Render the signup page with empty fields and no error message
module.exports.get_signup = (req, res) => {
    const { displayName, email, password, confirmPassword } = getUserInput(req);
    res.json({
        user: req.user,
        errorMessage: null,
        oldInput: { displayName, email, password, confirmPassword },
        validationErrors: []
    });
};

// Render the home page (index.ejs) with the user data (if authenticated)
module.exports.get_home_page = (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ user: req.user });
    } else {
        res.json({ user: null });
    }
};

// Render the forgot password page
module.exports.get_forgot_password = (req, res) => {
  res.json({ user: req.user });
};

// Handle the forgot password request
module.exports.post_forgot_password = async (req, res) => {
  try {
    // Generate a random token
    const buffer = await crypto.randomBytes(20);
    const token = buffer.toString('hex');

    // Find the user by email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(400).json({ message: 'No account with that email address exists.' });
    }

    // Set the password reset token and expiration
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    // Save the user
    await user.save();

    // Send an email to the user with the password reset link
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: 'your-email@gmail.com',
        pass: 'your-password'
      }
    });
    const mailOptions = {
      to: user.email,
      from: 'your-email@gmail.com',
      subject: 'Node.js Password Reset',
      text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
        'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
        'http://' + req.headers.host + '/reset/' + token + '\n\n' +
        'If you did not request this, please ignore this email and your password will remain unchanged.\n'
    };
    transporter.sendMail(mailOptions, function(err) {
      res.json({ message: 'An e-mail has been sent to ' + user.email + ' with further instructions.' });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ errorMessage: 'Server error' });
  }
};

// Render the reset password page
module.exports.get_reset_password = async (req, res) => {
  const user = await User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } });
  if (!user) {
    return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
  }
  res.json({ user: req.user });
};

// Handle the reset password request
module.exports.post_reset_password = async (req, res) => {
  try {
    const user = await User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } });
    if (!user) {
      return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
    }

    // Check if the password and confirm password fields match
    if (req.body.password !== req.body.confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match.' });
    }

    // Hash the new password and save it to the user
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    // Log the user in
    req.logIn(user, function(err) {
      if (err) { 
        return next(err); 
      }
      return res.json({ user });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ errorMessage: 'Server error' });
  }
};