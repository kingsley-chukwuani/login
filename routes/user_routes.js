const { Router } = require('express');
const userController = require('../controllers/user_controller');
const router = Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');


const { isAuthenticated } = require('../config/passport-local-strategy');
const { User } = require('../models/user');

//GET AND POST CHANGE PASSWORD ROUTES
router.get('/changepassword', isAuthenticated, (req, res) => {
  res.json({ status: 'GET change password route' });
});

router.post('/changepassword', isAuthenticated, async (req, res) => {
  try {
    const { newPassword } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    req.user.password = hashedPassword;
    await req.user.save();
    res.json({ status: 'Password changed successfully' });
  } catch (err) {
    res.status(500).json({ status: 'Error changing password', error: err.message });
  }
});



// POST forgot password
router.post('/forgotpassword', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ status: 'Error', message: 'No account with that email address exists.' });
    }

    // create and set password reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    await user.save();

    // send email
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.GMAIL_ADDRESS,
        pass: process.env.GMAIL_PASSWORD,
      },
    });

    
    const mailOptions = {
      to: user.email,
      from: 'passwordreset@example.com',
      subject: 'Node.js Password Reset',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\nPlease click on the following link, or paste this into your browser to complete the process:\n\nhttp://${req.headers.host}/reset/${resetToken}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };

    transporter.sendMail(mailOptions, function(err) {
      if (err) {
        return res.status(500).json({ status: 'Error sending email', error: err.message });
      }
      res.json({ status: 'Email sent' });
    });
  } catch (err) {
    res.status(500).json({ status: 'Error', error: err.message });
  }
});

// POST reset password
router.post('/reset/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });

    if (!user) {
      return res.status(400).json({ status: 'Error', message: 'Password reset token is invalid or has expired.' });
    }

    // update password
    const { newPassword } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    res.json({ status: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ status: 'Error', error: err.message });
  }
});

//GET LOGOUT
router.get('/logout', (req, res) => {
  req.logout();
  res.json({ status: 'Logged out successfully' });
});

module.exports = router;