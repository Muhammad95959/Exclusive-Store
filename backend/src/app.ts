import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import authRouter from "./modules/auth/auth.routes";

const app = express();

app.use(cors());
app.use(express.json());
app.use(cookieParser());

app.get("/", (_req, res) => res.send("<a href='api'>API</a>"));
app.get("/api", (_req, res) => res.send("XStore API"));
app.get("/api/v1", (_req, res) => res.send("XStore API V1"));

app.use("/api/v1/auth", authRouter);

export default app;
