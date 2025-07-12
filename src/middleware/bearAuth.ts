import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

declare global {
  namespace Express {
    interface Request {
      user?: DecodedToken;
    }
  }
}

type DecodedToken = {
  userId: number;
  email: string;
  userType: string;
  fullName: string;
  exp: number;
};

// AUTHENTICATION FUNCTION
export const verifyToken = async (token: string, secret: string) => {
  try {
    const decoded = jwt.verify(token, secret) as DecodedToken;
    return decoded;
  } catch (error) {
    return null;
  }
};

// AUTHORIZATION MIDDLEWARE
export const authMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
  requiredRoles: string
) => {
  const authHeader = req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authorization header is missing or invalid" });
  }

  const token = authHeader.split(" ")[1];
  const decodedToken = await verifyToken(token, process.env.JWT_SECRET as string);

  if (!decodedToken) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  const userType = decodedToken.userType;
  req.user = decodedToken; 

  if (requiredRoles === "both" && (userType === "admin" || userType === "member")) {
    return next();
  }

  if (userType === requiredRoles) {
    return next();
  }

  return res.status(403).json({ error: "Forbidden: You do not have permission to access this resource" });
};

// Role-specific middleware
export const adminRoleAuth = (req: Request, res: Response, next: NextFunction) => {
  authMiddleware(req, res, next, "admin").catch(next);
};

export const memberRoleAuth = (req: Request, res: Response, next: NextFunction) => {
  authMiddleware(req, res, next, "member").catch(next);
};

export const bothRoleAuth = (req: Request, res: Response, next: NextFunction) => {
  authMiddleware(req, res, next, "both").catch(next);
};

