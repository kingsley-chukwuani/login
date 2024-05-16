const mongoose = require('mongoose');
require('dotenv').config();

exports.connectMongoose = () => {
    return mongoose.connect(process.env.MONGODB_URI)
        .then(() => {
            console.log(`Connected Successfully To Database.`);
        })
        .catch((err) => {
            console.error(`Error connecting to database`, err);
        });
}