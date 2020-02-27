const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const passport = require('passport');
const Users = require('./models/Users');
//require('../../lib/passport');

//get all users
router.get('/', (req, res) => {
  Users.find({}).then(users=> {
    return res.status(200).json({message: 'Success', users})
  }).catch(err => res.status(500).json({message: 'Server Error'}))
})



//Validation Middleware
const myValidation = (req, res, next) => {
  // validate the inputs
  if(!req.body.name || !req.body.email || !req.body.password) {
    return res.status(403).json({message: "All Inputs Must Be Filled"})
  }
  next();
};

//register with passport
router.post('/register', myValidation, (req, res) => {
  // validate the inputs
  // if(!req.body.name || !req.body.email || !req.body.password) {
  //   return res.status(403).json({message: "All Inputs Must Be Filled"})
  // }
  // check if user exists
  Users.findOne({email: req.body.email}).then(user=> {
    //check to see if there is a user value
    if(user) {
      return res.status(400).json({message:"User already exists"})
    }
  // creat a new user from the User model
  const newUser = new Users();

  // salt password... places extra characters in password to make harder to guess
  const salt = bcrypt.genSaltSync(10);
  // hash password
  const hash = bcrypt.hashSync(req.body.password, salt);
  // set values for the user to model keys
  newUser.name = req.body.name;
  newUser.email = req.body.email;
  newUser.password = hash;
  // save the user
  newUser.save().then(user => {
    return req.login(user, (err) => {
      if(err){
        return res.status(500).json({message: "Server Error", err})
      } else {
        console.log(req.session);
        res.redirect('/users/success')
      }
    })
  }).catch(err => {
    return res.status(400).json({message: 'User not saved', err})
  })

}).catch(err => {
  return res.status(500).json({message:'User does not exists', err})
  
})

});

router.post('/login', 
  //authenticate using local login from passport file
  passport.authenticate('local-login', {
    successRedirect:'/users/success',
    failureRedirect:'/users/fail',
    failureFlash: true
  })
)

module.exports = router;
