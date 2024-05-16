// Require necessary modules and User model
const bcrypt = require('bcryptjs');
const { isAuthenticated } = require('../config/passport-local-strategy');
const { User } = require('../models/user');

// Render the 'changepassword.ejs' view with the user data and no errors
module.exports.get_changePassword = (req, res) => {
    res.json({ user: req.user, errors: null });
};

// Handle the POST request for changing the user's password
module.exports.post_changePassword = async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'User is not authenticated' });
    }

    const { currentPassword, newPassword } = req.body;
    let email = req.user.email;

    try {
        const user = await User.findOne({ email: email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect' });
        }

        // Validate new password
        if (newPassword.length < 8) {
            return res.status(400).json({ message: 'New password must be at least 8 characters long' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        user.password = hashedPassword;
        await user.save();

        res.json({ message: 'Password changed successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
};


// Handle the GET request for user logout
module.exports.get_logout = (req, res) => {
    // Perform logout using the 'req.logout()' method provided by Passport.js
    req.logout();
    // After logout, send a JSON response
    res.json({ message: 'Logged out successfully' });
};