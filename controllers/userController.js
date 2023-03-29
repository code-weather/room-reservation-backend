const asyncHandler = require('express-async-handler');
const bcrypt = require('bcryptjs');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken');

// * GENERATE TOKEN
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// * REGISTER NEW USER
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Account validation
  if (!name || !email || !password) {
    res.status(500);
    throw new Error('Please fill in all required fields');
  }
  if (password.length < 6) {
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

  // Generate Token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400),
    sameSite: 'none',
    secure: true,
  });

  if (user) {
    const { _id, name, email } = user;
    res.status(201).json({
      _id,
      name,
      email,
      token,
    });
  } else {
    res.status(400);
    throw new Error('Invalid user data');
  }
});

// * LOGIN USER
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validate Request
  if (!email || !password) {
    res.status(401);
    throw new Error('Incorrect email and/or password');
  }

  // Check if user exists
  const user = await User.findOne({ email });
  if (!user) {
    throw new Error('This email do not exist');
  }

  // If user exists, check if password is correct
  const matchPassword = await bcrypt.compare(password, user.password);

  // Generate token
  const token = generateToken(user._id);

  // Send HTTP-only cookie, if password matches
  if (matchPassword) {
    res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400),
      sameSite: 'none',
      secure: true,
    });
  }

  // Display after logging in
  if (user && matchPassword) {
    const { _id, name, email } = user;
    res.status(200).json({
      _id,
      name,
      email,
      token,
    });
  } else {
    res.status(400);
    throw new Error('Invalid email and/or password');
  }
});

// * LOGOUT USER
const logout = asyncHandler(async (req, res) => {
  res.cookie('token', '', { maxAge: 0 });
  return res.status(200).json({ message: 'Successfully Logged Out' });
});

// * GET USER DATA
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email } = user;
    res.status(200).json({
      _id,
      name,
      email,
    });
  } else {
    res.status(400);
    throw new Error('User cannot be found');
  }
});

module.exports = {
  registerUser,
  loginUser,
  logout,
  getUser,
};
