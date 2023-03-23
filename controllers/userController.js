const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');

// * REGISTER NEW USER
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Account validation
  if (!name || !email || !password) {
    res.status(500);
    throw new Error('Please fill in all required fields');
  }
  if (password.length <= 6) {
    throw new Error('Password gotta be 6 characters or more');
  }

  // Check if user's email already exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error('The email is already in use');
  }

  // Create new user
  const user = await User.create({ name, email, password });

  if (user) {
    const { _id, name, email } = user;
    res.status(201).json({
      _id,
      name,
      email,
    });
  } else {
    res.status(400);
    throw new Error('Invalid user data');
  }
});

module.exports = {
  registerUser,
};
