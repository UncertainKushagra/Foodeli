import jwt from "jsonwebtoken";
import { createError } from "../error.js";

export const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return next(createError(401, "No token provided"));

    const token = authHeader.split(" ")[1];
    if (!token) return next(createError(401, "Token is missing"));

    const decoded = jwt.verify(token, process.env.JWT);
    req.user = decoded;

    next();
  } catch (err) {
    console.error("JWT error:", err.message);
    return next(createError(403, "Invalid or expired token"));
  }
};
