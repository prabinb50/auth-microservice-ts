import { PrismaClient } from "../generated/prisma";

const prisma = new PrismaClient();

export const saveRefreshToken = async (userId: number, token: string, expiresAt: Date) => {
  return prisma.refreshToken.create({
    data: {
      userId,
      token,
      expiresAt,
    },
  });
};

export const findRefreshToken = async (token: string) => {
  return prisma.refreshToken.findUnique({
    where: { token },
  });
};

export const deleteRefreshToken = async (token: string) => {
  return prisma.refreshToken.deleteMany({
    where: { token },
  });
};

export const deleteAllUserRefreshTokens = async (userId: number) => {
  return prisma.refreshToken.deleteMany({
    where: { userId },
  });
};
