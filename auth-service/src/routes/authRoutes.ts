import { Router } from "express";
import { signUp, login, getUserById, refresh, logout, getProfile, listAllUsers, changeUserRole, deleteUser, deleteAllNonAdmins, deleteAllUsersHandler } from "../controllers/authController";
import { authenticate, requireAdmin } from "../middlewares/authMiddleware";
import { validate } from "../middlewares/validate";
import { loginSchema, registerSchema, updateRoleSchema } from "../validators/authValidators";
import { loginRateLimiter, registerRateLimiter } from "../middlewares/loginRateLimiter";

const router = Router();

// public routes with specific rate limiting
router.post("/register", registerRateLimiter, validate(registerSchema), signUp);
router.post("/login", loginRateLimiter, validate(loginSchema), login);
router.post("/refresh", refresh);
router.post("/logout", logout);

// protected routes (any authenticated user)
router.get("/profile", authenticate, getProfile);
router.get("/user/:id", authenticate, getUserById);

// admin-only routes
router.get("/admin/users", authenticate, requireAdmin, listAllUsers);
router.patch("/admin/change-role", authenticate, requireAdmin, validate(updateRoleSchema), changeUserRole);
router.delete("/admin/user/:id", authenticate, requireAdmin, deleteUser);
router.delete("/admin/users/non-admins", authenticate, requireAdmin, deleteAllNonAdmins);
router.delete("/admin/users/all", authenticate, requireAdmin, deleteAllUsersHandler);

export default router;