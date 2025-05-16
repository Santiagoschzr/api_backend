const mongoose = require('mongoose')
const {genSalt, hash} = require("bcrypt");
const {Schema} = mongoose;

const userSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        trim: true
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

userSchema.pre('save', async function(next){
    if (this.isModified('password')){
        try{
            const salt = await genSalt(10);
            this.password = await hash(this.password,salt);
            next();
        } catch(e){
            return next(e);
        }
    }else {
        next()
    }
})

const User = mongoose.model('User', userSchema);
module.exports = User;



