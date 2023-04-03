const express = require('express');
const {
  registerUser,
  loginUser,
  logout,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
} = require('../controllers/userController');
const protect = require('../middleware/authMiddleware');
const router = express.Router();

// User routes
router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/logout', logout);
router.get('/getuser', protect, getUser);
router.get('/loggedin', protect, loginStatus);
router.patch('/updateuser', protect, updateUser);
router.post('/changepassword', protect, changePassword);
router.patch('/forgotpassword', forgotPassword);
router.patch('/resetpassword', resetPassword);

// Admin routes
// router.post('/:id/approve', approveUser);
// router.delete('/:id', deleteUser);
// router.get('/registrations, getAllRegistrations)

module.exports = router;
