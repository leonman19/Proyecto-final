const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const User = require('../models/user');

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async(id, done) => {
    const user = await User.findById(id);
    done(null, user);
});
//SIGNUP
passport.use('local-signup', new localStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, email, password, done) => {
    
    const user = await User.findOne({email: email});
    if(user){
        return done(null, false, req.flash('signupMessage', 'The Email is already taken') );
    } else {
        const newUser = new User(req.body);
        newUser.email = email;
        newUser.password = newUser.encryptPassword(password);
        await newUser.save();
        done(null, newUser);
    }
}));

//SIGNIN
passport.use('local-signin', new localStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
    }, async (req, email, password, done) => {
    const user = await User.findOne({email: email});
    if(!user){
        return done(null, false, req.flash('signinMessage', 'No user found'));    
    }
    if(!user.comparePassword(password)) {
        return done(null, false, req.flash('signinMessage','Incorrect Password'));
    }
    done(null, user);
}));

//DELETE
passport.use('local-delete', new localStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
    }, async (req, email, password, done) => {
    const user = await User.findOne({email: email});
    if(!user){
        return done(null, false, req.flash('deleteMessage', 'No user found'));    
    }
    if(!user.comparePassword(password)) {
        return done(null, false, req.flash('deleteMessage','Incorrect Password'));
    } else {
        await user.remove();
        done(null, user, req.flash('deleteMessage','The user has been remove'));
    }
}));

//FORGOT
// passport.use('local-forgot', new localStrategy({
//     usernameField: 'email',
//     passReqToCallback: true
//     }, async (req, email, token, done) => {
//     const user = await User.findOne({email: email});
//     if(!user){
//         return done(null, false, req.flash('forgotMessage', 'No user found'));
//     } else {


//         // await user.remove();
//         // done(null, user, req.flash('deleteMessage','The user has been remove'));
//     }
// }));