
const sessions = new Map();

// TODO: implement create/get/destroy around an in-memory Map.
// Store opaque session id -> { userId, expiresAt }, never credentials.
// Remove expired sessions during reads.

async function create(sid, session) {
  sessions.set(sid, {
    userId: session.userId,
    expiresAt: session.expiresAt
  });
}

async function get(sid) {
  const session = sessions.get(sid);

  if (!session) {
    return null;
  }

  if (Number(session.expiresAt) <= Date.now()) {
    sessions.delete(sid);
    return null;
  }

  return session;
}

async function destroy(sid) {
  sessions.delete(sid);
}

module.exports = {
  create,
  get,
  destroy
};
