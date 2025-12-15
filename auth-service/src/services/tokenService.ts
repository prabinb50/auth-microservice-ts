import prisma from "../utils/prisma";

// save refresh token to database
export const saveRefreshToken = async (userId: string, token: string, expiresAt: Date) => {
  return prisma.refreshToken.create({
    data: {
      userId,
      token,
      expiresAt,
    },
  });
};

// find refresh token in database
export const findRefreshToken = async (token: string) => {
  return prisma.refreshToken.findUnique({
    where: { token },
  });
};

// delete specific refresh token
export const deleteRefreshToken = async (token: string) => {
  return prisma.refreshToken.deleteMany({
    where: { token },
  });
};

// delete all refresh tokens for a user
export const deleteAllUserRefreshTokens = async (userId: string) => {
  return prisma.refreshToken.deleteMany({
    where: { userId },
  });
};