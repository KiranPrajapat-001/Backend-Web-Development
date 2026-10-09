const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const invalidCredentials = () => {
  const error = new Error('Invalid email or password');
  error.status = 401;
  error.code = 'INVALID_CREDENTIALS';
  return error;
};

router.post('/register', async (req, res, next) => {
  try {
    // TODO: validate, hash, persist, and return a safe 201 response.
    const { name, email, password } = req.body || {};

    if (
      typeof name !== 'string' || !name.trim() ||
      typeof email !== 'string' || !email.trim() ||
      typeof password !== 'string' || !password.trim()
    ) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Name, email, and password are required' }
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    if (existingUser) {
      return res.status(409).json({
        error: { code: 'EMAIL_EXISTS', message: 'An account with this email already exists' }
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
      data: {
        name: name.trim(),
        email: normalizedEmail,
        passwordHash
      },
      select: {
        id: true,
        name: true,
        email: true
      }
    });

    return res.status(201).json({ data: user });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({
        error: { code: 'EMAIL_EXISTS', message: 'An account with this email already exists' }
      });
    }
    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    // TODO: verify credentials and return the required generic failure response.
    const { email, password } = req.body || {};

    if (
      typeof email !== 'string' || !email.trim() ||
      typeof password !== 'string' || !password.trim()
    ) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Email and password are required' }
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    if (!user) {
      return invalidCredentialsResponse(res);
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);

    if (!isValid) {
      return invalidCredentialsResponse(res);
    }

    return res.status(200).json({
      data: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    return next(error);
  }
});

function invalidCredentialsResponse(res) {
  return res.status(401).json({
    error: {
      code: 'INVALID_CREDENTIALS',
      message: 'Invalid email or password'
    }
  });
}

module.exports = router;