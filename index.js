const express = require('express');
const mongoose = require('mongoose');
const morgan = require('morgan');
require('dotenv').config()

const cors = require('cors')
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors({
    origin: "*"
}));
app.use(morgan("dev"))
const mongoURI = process.env.MONGO_URI
mongoose.connect(mongoURI).then(() => {
    console.log('Connected to MongoDB');
}).catch(err =>{
    console.error("Error connecting to mongoDB:",err)

})

const User = require ('./models/user.js')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');

const secretKey = process.env.SECRETS_JWT;


app.get('/', (req,res) => {
    res.send("Hello, this is my API")
})

//TODO: Login Route

app.post('/login', async (req, res) =>{

    const {username, password} = req.body;

    try{
        const user = await User.findOne({username: username.toLowerCase()});

        if (user) {
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {

                const token = jwt.sign(
                    {userId: user._id, username: user.username, name: user.name},
                    secretKey,
                    {expiresIn: '24h'}
                );

                res.json({
                    success: true,
                    message: 'Login succesful!',
                    token,
                    user: {
                        _id: user._id,
                        username: user.username,
                        name: user.name
                    },
                });
            } else {
                res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }
        }else{
            res.status(401).json({
                success: false,
                message:'Invalid credentials'
            })
        }
    }catch(e) {
        console.error('Login error: ', e);
        res.status(500).json({
            success: false,
            message: 'An error occured during login',
            error: error.message
        });
    }
});

app.post('/logout', async (req, res) =>{
    res.json({ success: true, message: ' Logged out succesfully!' });
});

const authenticateJWT = (req, res, next) =>{
    const authHeader = req.headers.authorization;

    if (authHeader){
        const token = authHeader.split(' ')[1];

        jwt.verify(token, secretKey, (err, user) =>{
            if(err) {
                console.error("JWT Verification Error", err);
                return res.status(403).json({success: false, message: 'Invalid token'})
            }
            req.user = user;
            next()
        });
    } else{
        res.status(401).json({success: false, message: 'No token provided'});
    }
};

app.post('/register', async (req,res) =>{
    const {username, password, name } = req.body
    try {
        // check if username is taken
        const existingUser = await User.findOne({username: username.toLowerCase()});
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Username is already taken'
            });
        }

        //create newUser
        const newUser = new User({
            username: username.toLowerCase(),
            password: password,
            name: name
        });

        //save user to the database
        const savedUser = await newUser.save();

        res.status(201).json({
            sucess: true,
            message: 'User registered succesfully',
            user:{
                _id: savedUser._id,
                username: savedUser.username,
                name: savedUser.name,
                createdAt: savedUser.createdAt
            }
        });


    } catch (e){
        console.error('Registration error: ', error)
        res.status(500).json({
            success: false,
            message: 'An error occured during registration',
            error: e.message
        });
    }
});

app.get('/profile',authenticateJWT, async (req, res) =>{
    res.status(200).json({
        success: true,
        message: "Profile Data",
        user: req.user

    })
} )

app.listen(port, () =>{
    console.log('Server is running on port: ' + port);
    }
)

