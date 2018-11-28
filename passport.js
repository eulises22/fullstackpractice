const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require('mongoose');
const keys = require('../config/keys')

const User = mongoose.model('users');

passport.use(
    new GoogleStrategy(
    {
        clientID: keys.googleClientID,
        clientSecret: keys.googleClientSecret,
        callbackURL: '/auth/google/callback'
    },

    (accessToken, refreshToken, profile, done) => {
        User.find0ne({ googleId: profile.id}).then((existingUser) => {
            if (existingUser) {
                //we already have a profile id
                done(null, existingUser);
            } else {
                //we dont have profile id
                new User ( { googleId: profile.id })
                    .save();
                    .then(user => done(null, user));
            }
        } );
    }
    )
);
