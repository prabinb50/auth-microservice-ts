-- AlterTable
ALTER TABLE "User" ADD COLUMN     "accountLockedUntil" TIMESTAMP(3),
ADD COLUMN     "failedLoginAttempts" INTEGER NOT NULL DEFAULT 0;
