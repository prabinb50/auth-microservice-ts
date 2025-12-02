import { Router } from "express";
import { signUp, login, getUserById, refresh, logout } from "../controllers/authController";
import { authenticate } from "../middlewares/authMiddleware";
import { validate } from "../middlewares/validate";
import { loginSchema, registerSchema } from "../validators/authValidators";

const router = Router();

// public routes
router.post("/register", validate(registerSchema), signUp);
router.post("/login", validate(loginSchema), login);
router.post("/refresh", refresh);
router.post("/logout", logout);

// protected route 
router.get("/:id", authenticate, getUserById);

export default router;
