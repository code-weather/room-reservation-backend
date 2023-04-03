const asyncHandler = require('express-async-handler');
const bcrypt = require('bcryptjs');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const Token = require('../models/tokenModel');
const crypto = require('crypto');
const sendEmail = require('../utilities/sendEmail');

// * GENERATE TOKEN
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// * REGISTER NEW USER
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password, phone, role } = req.body;

  // Account validation
  if (!name || !email || !password || !phone || !role) {
    res.status(500);
    throw new Error('Please fill in all required fields');
  }

  if (password.length < 6) {
    throw new Error('Password gotta be 6 characters or more');
  }

  const phoneRegex = /^[\d\+\-\(\)]{10,}$/;

  if (phone.length !== 12 && !phoneRegex.test(phone)) {
    throw new Error('Please enter a valid phone number');
  }

  // Check if user's email and/or phone already exists
  const emailExists = await User.findOne({ email });
  const phoneExists = await User.findOne({ phone });

  if (emailExists && phoneExists) {
    res.status(400);
    throw new Error('The email and phone number are already in use');
  }

  if (emailExists) {
    res.status(400);
    throw new Error('The email is already in use');
  }

  if (phoneExists) {
    res.status(400);
    throw new Error('The phone number is already in use');
  }

  // Create new user
  const approved = false; // Set approval status to false as default
  const user = await User.create({
    name,
    email,
    password,
    phone,
    role,
    approved,
  });

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
    const { _id, name, email, phone, role, approved } = user;
    res.status(201).json({
      _id,
      name,
      email,
      phone,
      approved,
      role,
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
    const { _id, name, email, phone } = user;
    res.status(200).json({
      _id,
      name,
      email,
      phone,
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
    const { _id, name, email, phone } = user;
    res.status(200).json({
      _id,
      name,
      email,
      phone,
    });
  } else {
    res.status(400);
    throw new Error('User cannot be found');
  }
});

// * LOGIN STATUS
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.json(false);
  }

  // Verify Token
  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

// * UPDATE USER
const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { name, email, phone } = user;
    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;

    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phone,
    });
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// * CHANGE PASSWORD
const changePassword = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  const { currentPassword, newPassword } = req.body;

  if (!user) {
    res.status(400);
    throw new Error('User not found');
  }

  // Validate
  if (!currentPassword || !newPassword) {
    res.status(400);
    throw new Error('Must enter your current and new password');
  }

  // Check if the current password matches password in DB
  const matchPassword = await bcrypt.compare(currentPassword, user.password);

  // Save new password
  if (user && matchPassword) {
    user.password = newPassword;
    await user.save();
    res.status(200).send('Password change successful');
  } else {
    res.status(400);
    throw new Error('Password do not match');
  }
});

// * FORGOT PASSWORD
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error('User does not exist');
  }

  // Delete token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Create Reset Token
  let resetToken = crypto.randomBytes(32).toString('hex') + user._id;

  // Hash token before saving to DB
  const hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // Save Token to DB
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 10 * (60 * 1000),
  }).save();

  // Construct Reset Url
  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;

  // Message sent to email to reset password
  const message = `
  <h2>Yo ${user.name},</h2>
  <p>Please use the url below to reset your password</p>
  <p>This reset link is valid for only 10 minutes...HURRY UP!</p>

  <a href=${resetUrl} clicktracking=off>Click here to reset password</a>

  <p>Regards,</p>
  <p>One of God's children</p>
  `;

  const subject = 'Password Reset Request';
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, send_to, sent_from);
    res.status(200).json({ success: true, message: 'Reset Email Sent' });
  } catch (error) {
    res.status(500);
    throw new Error('Email not sent, please try again');
  }
});

// * RESET PASSWORD
const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { resetToken } = req.params;

  // Hash token, then compare to token to DB
  const hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // Find Token in DB
  const userToken = await Token.findOne({
    token: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error('Invalid or Expired token');
  }

  // Find user
  const user = await User.findOne({ _id: userToken.userId });
  user.password = password;
  await user.save();
  res.status(200).json({
    message: 'Password Reset Sccessful. Please Login',
  });
});

module.exports = {
  registerUser,
  loginUser,
  logout,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
};
