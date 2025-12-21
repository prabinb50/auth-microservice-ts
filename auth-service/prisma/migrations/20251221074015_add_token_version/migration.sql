-- AlterEnum
ALTER TYPE "AuditAction" ADD VALUE 'EMAIL_UPDATE_FAILED';

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "tokenVersion" INTEGER NOT NULL DEFAULT 0;

-- CreateIndex
CREATE INDEX "User_tokenVersion_idx" ON "User"("tokenVersion");
