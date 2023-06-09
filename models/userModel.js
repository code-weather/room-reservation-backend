const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Yo you gotta enter your NAME'],
    },
    email: {
      type: String,
      required: [true, 'Ya gotta put in your EMAIL'],
      unique: true,
      trim: true,
      match: [
        // Validate email
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        "Please enter an EMAIL, bc it ain't valid",
      ],
    },
    password: {
      type: String,
      minLength: [6, 'Password have to be 6 characters or more'],
      required: [true, 'HEY!! YOO!!! Enter a PASSWORD'],
    },
    phone: {
      type: Number,
      required: [true, 'Please enter a phone number'],
      trim: true,
      validate: {
        validator: function (v) {
          return /^\d{10}$/.test(v);
        },
        message: (props) =>
          `${props.value} is not a valid phone number! Please enter 10 digits only.`,
      },
    },
    role: {
      type: String,
      enum: ['Admin', 'Deacon', 'Elder', 'Pastor'],
      required: true,
    },
    approved: {
      type: Boolean,
      required: true,
    },
  },
  {
    timestamp: true,
  }
);

// Encrypt password before saving to DB
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }

  // Hash password
  const salt = await bcrypt.genSalt();
  const hashedPassword = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword;
  next();
});

const User = mongoose.model('users', userSchema);

module.exports = User;
