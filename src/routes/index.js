const express = require('express');
const router = express.Router();

const passport = require('passport');

router.get('/', (req, res, next) => {
    res.render('index')
});

router.get('/signup', (req, res, next) =>{
    res.render('signup');
});

router.post('/signup', passport.authenticate('local-signup' , {
    successRedirect: '/profile',
    failureRedirect: '/signup',
    passReqToCallback: true
}));


router.get('/signin', (req, res, next) =>{
    res.render('signin');
});

router.post('/signin', passport.authenticate('local-signin', {
    successRedirect: '/profile',
    failureRedirect: '/signin',
    passReqToCallback : true
}));


router.get('/delete', isAuthenticated, (req, res, next) =>{
    res.render('delete');
});

router.post('/delete', passport.authenticate('local-delete', {
    successRedirect: '/',
    failureRedirect: '/delete',
    passReqToCallback : true
}));

router.get('/logout', (req, res, next) => {
    req.logout();
    res.redirect('/');
});


router.get('/profile', isAuthenticated, (req, res, next) => {
    res.render('profile');
});

router.get('/forgot', (req, res, next) =>{
    res.render('forgot');
});

router.post('/forgot', (req, res) =>{
});

function isAuthenticated(req,res, next) {
    if(req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
};



module.exports = router;