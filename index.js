require("dotenv").config();
const express = require("express");
const app = express();
const PORT = process.env.PORT || 8800;
const flash = require("connect-flash");
const path = require("path");
const { connectMongoose } = require("./config/mongoose");
const passport = require("passport");
const { initializingPassport } = require("./config/passport-local-strategy");
const expressSession = require("express-session");

const homeRoutes = require("./routes/home_routes");
const userRoutes = require("./routes/user_routes");

// MIDDLEWARES
app.use(flash());
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  expressSession({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // Change this if you're using HTTPS in production
  })
);

app.use(passport.initialize()); // Place this before passport.session()
app.use(passport.session());

// CALLING THE FUNCTIONS (Using async IIFE)
(async () => {
  try {
    await connectMongoose();
    await initializingPassport(passport);
  } catch (err) {
    console.error(err);
    process.exit(1); // Exit the process with a failure code
  }
})();

app.use("/user", userRoutes);
app.use("/", homeRoutes);

// Default route to send a JSON response
app.use((_req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// APP LISTEN
app.listen(8800, () => {
  console.log(`Server running on port ${8800}`);
});
