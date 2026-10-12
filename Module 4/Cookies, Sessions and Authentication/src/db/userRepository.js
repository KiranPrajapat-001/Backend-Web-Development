
const prisma = require('./prisma');

async function findByEmail(email) {
  return prisma.user.findUnique({
    where: { email }
  });
}

async function findPublicById(id) {
  return prisma.user.findUnique({
    where: { id },
    select: {
      id: true,
      name: true,
      email: true
    }
  });
}

module.exports = {
  findByEmail,
  findPublicById
};
