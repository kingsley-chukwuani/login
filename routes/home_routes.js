const { Router } = require('express');
const homeController = require('../controllers/home_controller');
const router = Router();
const passport = require('passport');
const { initializingPassport, isAuthenticated } = require('../config/passport-local-strategy');
const { check, validationResult } = require('express-validator');

const { User } = require('../models/user');

// Initializing Passport Local Strategy
initializingPassport(passport);

// GET HOME PAGE ROUTE
router.get('/', homeController.get_home_page);

// GET AND POST SIGNUP ROUTES
router.get('/signup', homeController.get_signup);
router.post(
  '/signup',
  [
    check('email').isEmail().withMessage('Please enter a valid email'),
    check('password', 'Password length should be greater than 5').isLength({ min: 6 }),
    check('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords must match');
      }
      return true;
    }),
  ],
  homeController.post_signup
);

// GET AND POST LOGIN ROUTES
router.post('/login', homeController.post_login);

router.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
  failureFlash: true
}));

// GOOGLE AUTH ROUTES
router.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });

router.get('/auth/google', isAuthenticated, passport.authenticate('google', { scope: ['profile', 'email'] }));

// PASSWORD RESET ROUTES
router.get('/forgotpassword', homeController.get_forgot_password);
router.post('/forgotpassword', homeController.post_forgot_password);
router.get('/reset/:token', homeController.get_reset_password);
router.post('/reset/:token', homeController.post_reset_password);

// EXPORTING THE ROUTER
module.exports = router;