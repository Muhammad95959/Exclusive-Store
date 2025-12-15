import bcrypt from "bcryptjs";
import crypto from "crypto";
import { NextFunction, Request, Response } from "express";
import { promises as fs } from "fs";
import jwt from "jsonwebtoken";
import prisma from "../../config/db";
import createOTP from "../../utils/createOTP";
import sendEmail from "../../utils/sendEmail";
import serializeUser from "../../utils/serializeUser";
import signToken from "../../utils/signToken";

export async function protect(req: Request, res: Response, next: NextFunction) {
  try {
    const token = req.cookies.jwt;
    if (!token) return res.status(401).json({ status: "fail", message: "You are not logged in" });
    if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is not defined");
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { id, iat } = decoded as { id: string; iat: number; exp: number };
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) return res.status(401).json({ status: "fail", message: "User not found" });
    if (user.passwordChangedAt && iat * 1000 < user.passwordChangedAt.getTime())
      return res
        .status(401)
        .json({ status: "fail", message: "Password has been changed recently. Please log in again" });
    res.locals.user = user;
    next();
  } catch (err) {
    console.log(err);
    res.status(401).json({ status: "fail", message: "Invalid or expired token" });
  }
}

export async function authorize(_req: Request, res: Response) {
  res.status(200).json({ status: "success", data: { user: serializeUser(res.locals.user) } });
}

export async function signup(req: Request, res: Response) {
  try {
    const { email, password, username } = req.body;
    if (!email || !password || !username) {
      return res.status(400).json({
        status: "fail",
        message: "Email, username and password are required",
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const confirmEmailToken = crypto.randomBytes(32).toString("hex");
    const confirmEmailTokenHash = crypto.createHash("sha256").update(confirmEmailToken).digest("hex");
    await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        username,
        confirmEmailToken: confirmEmailTokenHash,
        confirmEmailExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });
    const rawMessage = await fs.readFile("public/emailConfirmationMessage.html", "utf-8");
    const message = rawMessage.replaceAll(
      "%%CONFIRMATION_LINK%%",
      `${req.protocol}://${req.get("host")}/api/v1/auth/confirm-email/${confirmEmailToken}`,
    );
    sendEmail(email, "XStore - Email Confirmation", message, true);
    res.status(201).json({
      status: "success",
      message: "Confirmation email sent. Please check your inbox to verify your email address.",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "fail", message: "Internal Server Error" });
  }
}

export async function confirmEmail(req: Request, res: Response) {
  const failHtml = await fs.readFile("public/emailVerificationFailure.html", "utf-8");
  try {
    const confirmEmailTokenHash = crypto.createHash("sha256").update(req.params.token).digest("hex");
    const user = await prisma.user.findFirst({
      where: { confirmEmailToken: confirmEmailTokenHash, confirmEmailExpires: { gt: new Date() } },
    });
    if (!user) return res.status(400).send(failHtml);
    await prisma.user.update({
      where: { id: user.id },
      data: { emailConfirmed: true, confirmEmailToken: null, confirmEmailExpires: null },
    });
    const successHtml = await fs.readFile("public/emailVerificationSuccess.html", "utf-8");
    res.status(200).send(successHtml);
  } catch (err) {
    console.log(err);
    res.status(500).send(failHtml);
  }
}

export async function resendConfirmationEmail(req: Request, res: Response) {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ status: "fail", message: "Email is required" });
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ status: "fail", message: "Email not found" });
    if (user.emailConfirmed) return res.status(400).json({ status: "fail", message: "Email already confirmed" });
    const confirmEmailToken = crypto.randomBytes(32).toString("hex");
    const confirmEmailTokenHash = crypto.createHash("sha256").update(confirmEmailToken).digest("hex");
    await prisma.user.update({
      where: { email },
      data: {
        confirmEmailToken: confirmEmailTokenHash,
        confirmEmailExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });
    const rawMessage = await fs.readFile("public/emailConfirmationMessage.html", "utf-8");
    const message = rawMessage.replaceAll(
      "%%CONFIRMATION_LINK%%",
      `${req.protocol}://${req.get("host")}/api/v1/auth/confirm-email/${confirmEmailToken}`,
    );
    sendEmail(email, "XStore - Email Confirmation", message, true);
    res.status(201).json({
      status: "success",
      message: "Confirmation email sent. Please check your inbox to verify your email address.",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "fail", message: "Internal Server Error" });
  }
}

export async function login(req: Request, res: Response) {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ status: "fail", message: "Email and password are required" });
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) return res.status(400).json({ status: "fail", message: "Invalid credentials" });
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ status: "fail", message: "Invalid credentials" });
    if (!user.emailConfirmed)
      return res.status(403).json({ status: "fail", message: "Please confirm your email first." });
    const token = signToken(user.id);
    res.cookie("jwt", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    });
    res.status(200).json({ status: "success", data: { user: serializeUser(user) } });
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "fail", message: "Internal Server Error" });
  }
}

export async function logout(_req: Request, res: Response) {
  res.clearCookie("jwt");
  res.status(200).json({ status: "success", message: "Logged out successfully" });
}

export async function forgotPassword(req: Request, res: Response) {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ status: "fail", message: "Email is required" });
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ status: "fail", message: "Email not found" });
    const otp = createOTP(6);
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetPasswordOTP: otpHash,
        resetPasswordExpires: new Date(Date.now() + 15 * 60 * 1000),
      },
    });
    const rawMessage = await fs.readFile("public/resetPasswordMessage.html", "utf-8");
    const message = rawMessage.replace("%%OTP%%", otp);
    sendEmail(email, "XStore - Password Reset", message, true);
    res.status(200).json({ status: "success", message: "OTP sent to your email. Please check your inbox" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "fail", message: "Internal Server Error" });
  }
}

export async function verifyOtp(req: Request, res: Response) {
  try {
    const { otp, email } = req.body;
    if (!otp || !email) return res.status(400).json({ status: "fail", message: "OTP and email are required" });
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ status: "fail", message: "Email not found" });
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    if (user.resetPasswordOTP !== otpHash) return res.status(400).json({ status: "fail", message: "Invalid OTP" });
    if (!user.resetPasswordExpires || user.resetPasswordExpires < new Date())
      return res.status(400).json({ status: "fail", message: "OTP has expired" });
    res.status(200).json({ status: "success", message: "OTP is valid" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "fail", message: "Internal Server Error" });
  }
}

export async function resetPassword(req: Request, res: Response) {
  try {
    const { otp, email, newPassword } = req.body;
    if (!otp || !email) return res.status(400).json({ status: "fail", message: "OTP and email are required" });
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ status: "fail", message: "Email not found" });
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    if (user.resetPasswordOTP !== otpHash) return res.status(400).json({ status: "fail", message: "Invalid OTP" });
    if (!user.resetPasswordExpires || user.resetPasswordExpires < new Date())
      return res.status(400).json({ status: "fail", message: "OTP has expired" });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetPasswordOTP: null,
        resetPasswordExpires: null,
        passwordChangedAt: new Date(),
      },
    });
    res.status(200).json({ status: "success", message: "Password reset successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "fail", message: "Internal Server Error" });
  }
}
