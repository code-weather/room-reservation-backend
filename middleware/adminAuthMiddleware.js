/*

1. user visits /admin page
2. kick them out to homepage if they are not admin
3. if admin
  1. authenticate them using this middleware and allow them to access to the /admin page

4. in the /admin page & react component, it makes an API call to get all the registrations
  1. API can be like: GET /registrations

*/

const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');

const adminAuth = asyncHandler(async (req, res, next) => {
  if (req.userId) {
    // find user
    const user = await User.findById(req.userId);
    // check user's role
    if (user.role === 'admin') {
      return next();
    } else {
      // return next("/index");
    }
  } else {
    // navigate the user back to homepage
  }
});

module.exports = adminAuth;
