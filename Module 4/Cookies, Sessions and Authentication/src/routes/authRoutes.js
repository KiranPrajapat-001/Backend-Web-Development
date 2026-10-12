
const express = require('express');

const router = express.Router();

const bcrypt = require('bcrypt');
const crypto = require('crypto');

const userRepository = require('../db/userRepository');
const sessionStore = require('../session/sessionStore');

const COOKIE_SECRET = process.env.COOKIE_SECRET;

const isProduction = process.env.NODE_ENV === 'production';

const cookieOptions = {
  httpOnly: true,
  signed: true,
  sameSite: 'lax',
  secure: isProduction,
  maxAge: 1000 * 60 * 60 * 24
};

const clearCookieOptions = {
  httpOnly: true,
  signed: true,
  sameSite: 'lax',
  secure: isProduction,
  path: '/'
};

router.post('/login', async (req, res, next) => {
  // TODO: validate credentials, create a server session, and set signed `sid` cookie.
  try {
    const email =
      typeof req.body?.email === 'string'
        ? req.body.email.trim().toLowerCase()
        : '';

    const password =
      typeof req.body?.password === 'string'
        ? req.body.password
        : '';

    if (!email || !password || !COOKIE_SECRET) {
      if (!COOKIE_SECRET) {
        return res.status(500).json({
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Internal server error'
          }
        });
      }

      return res.status(400).json({
        error: {
          code: 'INVALID_INPUT',
          message: 'Email and password are required'
        }
      });
    }

    const user = await userRepository.findByEmail(email);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        }
      });
    }

    const sid = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + cookieOptions.maxAge;

    await sessionStore.create(sid, {
      userId: user.id,
      expiresAt
    });

    res.cookie('sid', sid, {
      ...cookieOptions,
      maxAge: expiresAt - Date.now()
    });

    return res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    });
  } catch (err) {
    next(err);
  }
});

router.get('/me', async (req, res, next) => {
  // TODO: resolve signed cookie through the server-side session store.
  try {
    const sid = req.signedCookies?.sid;

    if (!sid || typeof sid !== 'string') {
      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required'
        }
      });
    }

    const session = await sessionStore.get(sid);

    if (!session || Number(session.expiresAt) <= Date.now()) {
      await sessionStore.destroy(sid);

      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required'
        }
      });
    }

    const user = await userRepository.findPublicById(session.userId);

    if (!user) {
      await sessionStore.destroy(sid);

      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required'
        }
      });
    }

    return res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    });
  } catch (err) {
    next(err);
  }
});

router.post('/logout', async (req, res, next) => {
  // TODO: destroy server session and clear cookie using matching options.
  try {
    const sid = req.signedCookies?.sid;

    if (typeof sid === 'string') {
      await sessionStore.destroy(sid);
    }

    res.clearCookie('sid', clearCookieOptions);

    return res.status(204).end();
  } catch (err) {
    next(err);
  }
});

module.exports = router;
