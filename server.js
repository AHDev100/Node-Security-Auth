const https = require('https');
const fs = require('fs');
const path = require('path'); 
const express = require('express'); 
const helmet = require('helmet'); 
const passport = require('passport'); 
const { Strategy } = require('passport-google-oauth20'); 
const cookieSession = require('cookie-session');

require('dotenv').config(); 

const PORT = 3000; 

const config = {
    CLIENT_ID: process.env.CLIENT_ID, 
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

function verifyCallback(accessToken, refreshToken, profile, done){
    console.log('Google profile ', profile); 
    done(null, profile); //Pass in null if there's an auth error, otherwise return the user profile 
}

passport.use(new Strategy ({
    callbackURL: '/auth/google/callback', 
    clientID: config.CLIENT_ID, 
    clientSecret: config.CLIENT_SECRET,
}, verifyCallback));

//Save the session to cookie
passport.serializeUser((user, done) => {
    done(null, user.id); //Use id rather than entire user object to limit amount of data transferred through the browser 
}); 

//Read the session from the cookie 
passport.deserializeUser((id, done) => {
    done(null, id); 
}); 

const app = express(); 

app.use(helmet()); 

app.use(cookieSession({
    name: 'session',
    maxAge: 24*60*60*1000,
    keys: [ config.COOKIE_KEY_1, config.COOKIE_KEY_2 ],
}));

app.use(passport.initialize()); //Middleware that sets up the Passport session 

app.use(passport.session()); //Uses the keys to authenticate the session that's being sent to server 

function checkLoggedIn(req, res, next){ //req.user => Express deserializes user data into this request object property
    const isLoggedIn = req.isAuthenticated() && req.user; 
    if (!isLoggedIn){
        return res.status(401).json({
            error: 'You must log in!',
        });
    } 
    next(); 
} 

app.get('/auth/google', 
    passport.authenticate('google', {
        scope: ['email'],
    })
); 

app.get('/auth/google/callback', 
    passport.authenticate('google', {
        failureRedirect: '/failure', 
        successRedirect: '/',
        session: true, 
    }), 
    (req, res) => {
        console.log('Google called us back!'); 
    }
);

app.get('/auth/logout', (req, res) => {
    req.logOut(); //Will clear any logged in user session (i.e., Removes req.user)
    return res.redirect('/'); //Send the user back to root route after logout 
}); 

app.get('/secret', checkLoggedIn, (req, res) => {
    res.send('Your personal secret value is 42'); 
}); 

app.get('/failure', (req, res) => {
    res.send('Failed to log in!'); 
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html')); 
}); 

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
    console.log(`Listening on port ${PORT}`); 
}); 