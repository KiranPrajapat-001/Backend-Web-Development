const sessionStore = require('../session/sessionStore');
const userRepository = require('../db/userRepository');

// TODO: read req.signedCookies.sid, resolve the server session,
// attach identity to the request, and return generic 401 when invalid.
module.exports = async function requireSession(req, res, next) {
  try {
    const sid = req.signedCookies?.sid;

    if (!sid) {
      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
        },
      });
    }

    const session = await sessionStore.get(sid);

    if (!session || session.expiresAt <= Date.now()) {
      await sessionStore.destroy(sid);
      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
        },
      });
    }

    const user = await userRepository.findPublicById(session.userId);

    if (!user) {
      await sessionStore.destroy(sid);
      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
        },
      });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({
      error: {
        code: 'AUTH_REQUIRED',
        message: 'Authentication required',
      },
    });
  }
};