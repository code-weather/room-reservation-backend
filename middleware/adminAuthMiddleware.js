/*
a. if admin
  a. authenticate them using this middleware and allow them to access to the /admin page
2. user visits /admin page
3. kick them out to homepage if they are not admin

4. in the /admin page & react component, it makes an API call to get all the registrations
  1. API can be like: GET /registrations

*/

const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');
const User = require('../models/userModel')

const authMiddleware = asyncHandler(async (req, res, next) => {
  // Check for auth token in header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Find user by id in token
      const user = await User.findById(decoded.id);

      if (user) {
        req.user = user;
        next();
      } else {
        res.status(401);
        throw new Error('Not authorized, user not found');
      }
    } catch (error) {
      res.status(401);
      throw new Error('Not authorized, invalid token');
    }
  } else {
    res.status(401);
    throw new Error('Not authorized, no token');
  }
});

module.exports = authMiddleware;
