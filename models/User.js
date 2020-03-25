var mongoose = require('mongoose');
const bcrypt = require('bcrypt');
// Setup schema

var userSchema = mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true,
        minlength: 5,
        maxlength: 1024,
        trim: true
    },
    role: {
        type: Number, // 1: Admin, 2: Teacher, 3: Student
        required: true
    },
    status: {
        type: Number,
        default: 1 // 1: Active, 0: InActive
    },
    profile: {
        f_name: String,
        l_name: String,
        dob: Date,
        gender: Number, // 1: Male, 2: Female
    },
    created_at: {
        type: Date,
        default: Date.now
    },
    updated_at: {
        type: Date,
        default: Date.now
    },
    created_by: String,
    updated_by: String
});


userSchema.pre('save', function(next) {
    const user = this;
    if (!user.isModified || !user.isNew) { // don't rehash if it's an old user
        next();
    } else {
        bcrypt.hash(user.password, 10, function(err, hash) {
            if (err) {
                console.log('Error hashing password for user', user.name);
                next(err);
            } else {
                user.password = hash;
                next();
            }
        });
    }
})

// Export Task model
module.exports = mongoose.model('user', userSchema);