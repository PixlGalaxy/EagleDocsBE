// routes.js
// TODO: Migrate to a real database instead of using an in-memory array.

const { Router } = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: generateId } = require('uuid');
const { authMiddleware } = require('./auth');

const router = Router();

// Temporary in-memory list (for demo purposes)
const registeredUsers = [];

// Nodemailer configuration
const mailTransport = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/**
 * User Registration
 * Receives { email, password } in the request body.
 * 1. Checks if any required field is missing.
 * 2. Verifies the email is not already in use.
 * 3. Hashes the password.
 * 4. Generates a verification token valid for 10 minutes.
 * 5. Sends an email with a verification link.
 */
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ message: 'Please fill out all required fields.' });
    }

    // Check if the user already exists
    const existingUser = registeredUsers.find(user => user.email === email);
    if (existingUser) {
      return res.status(400).json({ message: 'That email is already in use.' });
    }

    // Hash the password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Generate a unique verification token (UUID) and set an expiration time
    const verifyToken = generateId();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create the user object in our "temporary DB"
    const newUser = {
      userId: generateId(),
      email,
      passwordHash,
      isVerified: false,
      verificationToken: verifyToken,
      tokenExpiresAt: expiresAt,
    };

    // Store it in the array
    registeredUsers.push(newUser);

    // Build the verification URL
    const verificationUrl = `${process.env.HOST_URL}/api/verify?token=${verifyToken}`;

    // Send the verification email
    await mailTransport.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'EagleDocs - Please Verify Your Account',
      html: `
        <p>Hi! Welcome to EagleDocs.</p>
        <p>Please confirm your email by clicking the link below (or paste it into your browser):</p>
        <a href="${verificationUrl}">${verificationUrl}</a>
        <p>The link expires in 10 minutes.</p>
      `,
    });

    return res.status(200).json({
      message: 'Registration successful! Check your inbox to verify your account.',
    });
  } catch (error) {
    console.error('Error in /register:', error);
    return res.status(500).json({ message: 'An error occurred during registration.' });
  }
});

/**
 * User Verification
 * GET /api/verify?token=<token>
 * Looks for the token in the user list and checks if it has expired.
 * If valid, sets isVerified = true and clears the token.
 */
router.get('/verify', async (req, res) => {
  try {
    const { token } = req.query;

    // Ensure there's a token in the query
    if (!token) {
      return res.status(400).send('Verification token is missing.');
    }

    // Find the user with this token
    const userToVerify = registeredUsers.find(u => u.verificationToken === token);
    if (!userToVerify) {
      return res.status(400).send('Invalid token.');
    }

    // Check if the token is expired
    if (userToVerify.tokenExpiresAt < new Date()) {
      // In a real system, you might mark them as expired or remove them
      const index = registeredUsers.findIndex(u => u.verificationToken === token);
      registeredUsers.splice(index, 1);
      return res.status(400).send('The link has expired. Please register again.');
    }

    // Mark the user as verified
    userToVerify.isVerified = true;
    userToVerify.verificationToken = null;
    userToVerify.tokenExpiresAt = null;

    return res.status(200).send('Your account is now verified! You can log in.');
  } catch (error) {
    console.error('Error in /verify:', error);
    return res.status(500).send('An error occurred during verification.');
  }
});

/**
 * Login
 * POST /api/login
 * Receives { email, password }, validates credentials.
 * If isVerified = true, generates a JWT valid for 2 hours.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if fields are provided
    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide both email and password.' });
    }

    // Find the user in the array
    const foundUser = registeredUsers.find(u => u.email === email);
    if (!foundUser) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    // Check if the account is verified
    if (!foundUser.isVerified) {
      return res.status(401).json({ message: 'Please verify your account before logging in.' });
    }

    // Compare the hashed password
    const isMatch = await bcrypt.compare(password, foundUser.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    // Generate a JWT
    const token = jwt.sign(
      { userId: foundUser.userId, email: foundUser.email },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    return res.status(200).json({ token });
  } catch (error) {
    console.error('Error in /login:', error);
    return res.status(500).json({ message: 'An error occurred during login.' });
  }
});

/**
 * Example protected route
 * GET /api/chat
 * Requires a JWT in the Authorization header (Authorization: Bearer <token>)
 * authMiddleware validates the token and attaches req.user
 */
router.get('/chat', authMiddleware, (req, res) => {
  const userInfo = req.user; // Provided by authMiddleware
  return res.status(200).json({ message: `Welcome to the chat, ${userInfo.email}!` });
});

module.exports = router;
