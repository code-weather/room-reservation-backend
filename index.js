const express = require('express');
require('dotenv').config();
const cors = require('cors');
const userRouter = require('./routes/userRoutes');
const mongoose = require('mongoose');
const errorHandler = require('./middleware/errorMiddleware');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use('/api/users', userRouter);

app.use(errorHandler);

mongoose.set('strictQuery', true);

const PORT = process.env.PORT || 8000;
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`${PORT} is FIRED UP SON! 🔥🔥🔥`);
    });
  })
  .catch((err) => console.log(err));
