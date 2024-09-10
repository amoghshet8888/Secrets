//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const findOrCreate = require("mongoose-findorcreate");
 
const app = express();

app.set('view engine', 'ejs');

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
})); 

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB") 
        .then(() => {
            console.log("Connected to mongoDB");
        })
        .catch(err => {
            console.log("Could not connect to mongoDB: " + err);
        });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id)
        .then(user => done(null, user))
        .catch(err => done(err, null));
});


passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleleapis.com/oauth2/v3/userinfo",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        console.log(profile);
      return done(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", {scope: ["profile"]})
);

app.get( "/auth/google/secrets",
    passport.authenticate( 'google', {
        successRedirect: '/auth/google/secrets',
        failureRedirect: '/auth/google/login'
}));

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    User.find({"secret": {$ne: null}})
        .then(foundUsers => {
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        })
        .catch(err => {
            console.log(err);
        });
});

app.get("/submit", (req, res) => {
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login"); 
    }
});

app.post("/submit", (req, res) => {
    submittedSecret = req.body.secret;
    User.findById(req.user.id)
        .then(foundUser => {
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save()
                .then(() => {
                    res.redirect("/secrets");
                    });
            }
        })
        .catch(err => {
            console.log(err);
        });
});

app.get('/logout', function(req, res, next){
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
        });
    }
});

});

app.listen(3000, (() => {
    console.log("Server listening on port 3000");
}));
