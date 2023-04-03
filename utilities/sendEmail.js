const nodemailer = require('nodemailer');

const sendEmail = async (subject, message, send_to, sent_from, reply_to) => {
  // Create Email Transporter
  const transporter = nodeMailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: 587,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    // TLS is not required
    tls: {
      rejectUnauthorized: false,
    },
  });

  // Option for sending email
  const options = {
    from: sent_from,
    to: send_to,
    replyTo: reply_to,
    subject: subject,
    html: message,
  };

  // Send the email status
  transporter.sendEmail(options, function (error, info) {
    if (error) {
      console.log(error)
    } else {
      console.log(info)
    }
  })
};

module.exports = sendEmail;