import express from "express";
import * as authController from "./auth.controller";

const router = express.Router();

router.get("/", authController.protect, authController.authorize);

router.post("/signup", authController.signup);

router.get("/confirm-email/:token", authController.confirmEmail);

router.post("/resend-confirmation-email", authController.resendConfirmationEmail);

router.post("/login", authController.login);

router.get("/logout", authController.logout);

router.post("/forgot-password", authController.forgotPassword);

router.post("/verify-otp", authController.verifyOtp);

router.patch("/reset-password", authController.resetPassword);

export default router;
