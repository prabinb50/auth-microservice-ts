import { Router } from "express";
import { 
  signUp, 
  login, 
  getUserById, 
  refresh, 
  logout, 
  getProfile, 
  listAllUsers, 
  changeUserRole, 
  deleteUser, 
  deleteAllNonAdmins, 
  deleteAllUsersHandler 
} from "../controllers/authController";
import {
  getActiveSessions,
  revokeSpecificSession,
  logoutOtherDevices,
  logoutAllDevices,
} from "../controllers/sessionController";
import {
  handleDataExport,
  handleAccountAnonymization,
  handlePermanentDeletion,
  handleEmailUpdate,
  handleDataRetentionInfo,
} from "../controllers/gdprController";
import {
  handleMagicLinkRequest,
  handleMagicLinkLogin,
  handleGetMagicLinkStatus,
} from "../controllers/magicLinkController";
import { authenticate, requireAdmin } from "../middlewares/authMiddleware";
import { validate } from "../middlewares/validate";
import { loginSchema, registerSchema, updateRoleSchema } from "../validators/authValidators";
import { updateEmailSchema, anonymizationSchema, permanentDeletionSchema } from "../validators/gdprValidators";
import { magicLinkRequestSchema, magicLinkLoginSchema } from "../validators/magicLinkValidators";
import { loginRateLimiter, registerRateLimiter } from "../middlewares/loginRateLimiter";
import { createAuditLogHandler, getAdminActionsHandler, getAllAuditLogsHandler, getMyAuditLogs } from "../controllers/auditController";

const router = Router();

// public routes with specific rate limiting
router.post("/register", registerRateLimiter, validate(registerSchema), signUp);
router.post("/login", loginRateLimiter, validate(loginSchema), login);
router.post("/refresh", refresh);
router.post("/logout", logout);

// magic link routes (public)
router.post("/magic-link/request", loginRateLimiter, validate(magicLinkRequestSchema), handleMagicLinkRequest);
router.post("/magic-link/verify", loginRateLimiter, validate(magicLinkLoginSchema), handleMagicLinkLogin);

// internal routes (for email-service)
router.post("/internal/audit-log", createAuditLogHandler);

// protected routes (any authenticated user)
router.get("/profile", authenticate, getProfile);
router.get("/user/:id", authenticate, getUserById);

// magic link status (authenticated users)
router.get("/magic-link/status", authenticate, handleGetMagicLinkStatus);

// session management routes (authenticated users)
router.get("/sessions", authenticate, getActiveSessions);
router.delete("/sessions/:sessionId", authenticate, revokeSpecificSession);
router.post("/sessions/logout-other-devices", authenticate, logoutOtherDevices);
router.post("/sessions/logout-all-devices", authenticate, logoutAllDevices);

// audit log routes (authenticated users - own logs)
router.get("/audit/me", authenticate, getMyAuditLogs);

// gdpr routes (authenticated users)
router.get("/gdpr/export", authenticate, handleDataExport);
router.post("/gdpr/anonymize", authenticate, validate(anonymizationSchema), handleAccountAnonymization);
router.patch("/gdpr/update-email", authenticate, validate(updateEmailSchema), handleEmailUpdate);
router.get("/gdpr/retention-info", authenticate, handleDataRetentionInfo);

// admin-only routes
router.get("/admin/users", authenticate, requireAdmin, listAllUsers);
router.patch("/admin/change-role", authenticate, requireAdmin, validate(updateRoleSchema), changeUserRole);
router.delete("/admin/user/:id", authenticate, requireAdmin, deleteUser);
router.delete("/admin/users/non-admins", authenticate, requireAdmin, deleteAllNonAdmins);
router.delete("/admin/users/all", authenticate, requireAdmin, deleteAllUsersHandler);

// admin audit log routes
router.get("/admin/audit", authenticate, requireAdmin, getAllAuditLogsHandler);
router.get("/admin/audit/admin-actions", authenticate, requireAdmin, getAdminActionsHandler);

// admin gdpr routes
router.delete("/admin/gdpr/permanently-delete/:userId", authenticate, requireAdmin, validate(permanentDeletionSchema), handlePermanentDeletion);

export default router;