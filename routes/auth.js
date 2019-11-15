const router = require('express').Router();
const User = require('../model/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose= require('mongoose');
const { registerValidation,loginValidation } = require('../validation');



router.post('/register', async (req,res) => {

    //LETS VALIDATE THE DATA BEFORE WE A USER
    const { error } = registerValidation(req.body);
    if(error) return res.status(400).send(error.details[0].message);
    
    //CHECKING DB CONNECTION
    const dbStatus=mongoose.connection.readyState;
    if(dbStatus!=1) return res.status(400).send('We are currently unable to sign up. Please try again later.');

    //Checking if the user is already in the database
    const emailExist = await User.findOne({email: req.body.email});
    if(emailExist) return res.status(400).send('Email already exists');

    // Hash passwords
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(req.body.password, salt);


    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword
    });
    try{
        const savedUser = await user.save();
        res.send({user: user._id});
    }
    catch(err){
        res.status(400).send(err);
    }
});

//LOGIN
router.post('/login', async (req,res) =>{

    //LETS VALIDATE THE DATA BEFORE WE A USER
    const { error } = loginValidation(req.body);
    if(error) return res.status(400).send(error.details[0].message);

    //CHECKING DB CONNECTION
    const dbStatus=mongoose.connection.readyState;
    if(dbStatus!=1) return res.status(400).send('We are unable to log in at this time. Please try again later.');

     //Checking if the email exists
    const user = await User.findOne({email: req.body.email});
    if(!user) return res.status(400).send('Email is not found');

    //PASSWORD IS CORRECT
    const validPass = await bcrypt.compare(req.body.password, user.password);
    if(!validPass) return res.status(400).send('Invalid password');
    
    //Create and assign a token
    const token = jwt.sign({_id: user._id}, process.env.TOKEN_SECRET);
    res.header('auth-token',token).send(token);
    
    const username=user.name;
    //res.send(`Logged in as '${username}'`);


});


module.exports = router;