const mongoose = require('mongoose')

//create blueprint for inputs into database
//word will have type string
const UserSchema = new mongoose.Schema({
    name: {type: String, default: '', trim: true, lowercase: true},
    email: {type: String, default: '', trim: true, lowercase: true, unique: true},
    password: {type: String, default: '', trim: true}

})
// we name userschema users and export the model aka class
module.exports = mongoose.model('users', UserSchema);

