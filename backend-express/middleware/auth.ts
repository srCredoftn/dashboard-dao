import { Request, Response, NextFunction } from "express";
import { AuthService } from "../services/authService";
import { DaoService } from "../services/daoService";
import type { AuthUser, UserRole } from "@shared/dao";

// Extend Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

// Authentication middleware with secure token verification
export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      console.log(
        `🚫 No token provided for ${req.method} ${req.originalUrl} from ${req.ip}`,
      );
      return void res.status(401).json({
        error: "Access token required",
        code: "NO_TOKEN",
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    if (!token) {
      console.log(
        `🚫 Empty token for ${req.method} ${req.originalUrl} from ${req.ip}`,
      );
      return void res.status(401).json({
        error: "Access token required",
        code: "EMPTY_TOKEN",
      });
    }

    const user = await AuthService.verifyToken(token);

    if (!user) {
      console.log(
        `🚫 Invalid token for ${req.method} ${req.originalUrl} from ${req.ip}`,
      );
      return void res.status(401).json({
        error: "Invalid or expired token",
        code: "INVALID_TOKEN",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);
    return void res.status(401).json({
      error: "Authentication failed",
      code: "AUTH_ERROR",
    });
  }
}

// Authorization middleware factory
export function authorize(roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      console.log(
        `🚫 No user context for ${req.method} ${req.originalUrl} from ${req.ip}`,
      );
      return void res.status(401).json({
        error: "Authentication required",
        code: "NO_USER_CONTEXT",
      });
    }

    if (!roles.includes(req.user.role)) {
      console.log(
        `🚫 Insufficient permissions: ${req.user.email} (${req.user.role}) tried to access ${req.originalUrl}`,
      );
      return void res.status(403).json({
        error: "Insufficient permissions",
        required: roles,
        current: req.user.role,
        code: "INSUFFICIENT_PERMISSIONS",
      });
    }

    next();
  };
}

// Admin-only middleware
export const requireAdmin = authorize(["admin"]);

// Admin or DAO team lead middleware (by DAO id in params)
export function requireDaoLeaderOrAdmin(paramKey: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return res
          .status(401)
          .json({ error: "Authentication required", code: "NO_USER_CONTEXT" });
      }
      // Admin passes immediately
      if (req.user.role === "admin") return next();

      const daoId = req.params[paramKey];
      if (!daoId) {
        return res
          .status(400)
          .json({ error: "DAO ID missing", code: "MISSING_DAO_ID" });
      }

      const dao = await DaoService.getDaoById(daoId);
      if (!dao) {
        return res
          .status(404)
          .json({ error: "DAO not found", code: "DAO_NOT_FOUND" });
      }

      const isLeader = dao.equipe.some(
        (m) => m.id === req.user!.id && m.role === "chef_equipe",
      );

      if (!isLeader) {
        return res
          .status(403)
          .json({ error: "Insufficient permissions", code: "NOT_LEADER" });
      }

      next();
    } catch (error) {
      console.error("requireDaoLeaderOrAdmin error:", error);
      return res.status(500).json({ error: "Authorization check failed", code: "AUTHZ_ERROR" });
    }
  };
}

// Admin or user middleware (excludes viewers if they exist)
export const requireUser = authorize(["admin", "user"]);

// Any authenticated user
export const requireAuth = authenticate;

// Optional authentication middleware (doesn't fail if no token)
export async function optionalAuth(
  req: Request,
  _res: Response,
  next: NextFunction,
) {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);

      if (token) {
        const user = await AuthService.verifyToken(token);
        if (user) {
          req.user = user;
        }
      }
    }

    next();
  } catch (error) {
    // Don't fail on optional auth, just continue without user
    console.log(
      "Optional auth failed, continuing without user:",
      (error as Error).message,
    );
    next();
  }
}

// Middleware to check if user owns a resource
export function requireOwnership(
  getUserIdFromRequest: (req: Request) => string,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return void res.status(401).json({
        error: "Authentication required",
        code: "NO_USER_CONTEXT",
      });
    }

    // Admin can access everything
    if (req.user.role === "admin") {
      return next();
    }

    const resourceUserId = getUserIdFromRequest(req);

    if (req.user.id !== resourceUserId) {
      console.log(
        `🚫 Ownership violation: ${req.user.email} tried to access resource owned by ${resourceUserId}`,
      );
      return void res.status(403).json({
        error: "Can only access your own resources",
        code: "OWNERSHIP_VIOLATION",
      });
    }

    next();
  };
}

// Security audit logging
export function auditLog(action: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const originalSend = res.send;

    res.send = function (body) {
      // Log the action after response
      const statusCode = res.statusCode;
      const success = statusCode < 400;

      console.log(
        `📋 AUDIT: ${action} - ${success ? "SUCCESS" : "FAILED"} - ${req.user?.email || "anonymous"} - ${req.ip} - ${statusCode}`,
      );

      if (!success) {
        console.log(
          `   Details: ${req.method} ${req.originalUrl} - Body: ${JSON.stringify(req.body).slice(0, 200)}`,
        );
      }

      return originalSend.call(this, body);
    };

    next();
  };
}

// Rate limiting for sensitive operations
export function sensitiveOperationLimit() {
  const attempts = new Map<string, { count: number; resetTime: number }>();
  const MAX_ATTEMPTS = process.env.NODE_ENV === "production" ? 5 : 20; // Plus permissif en dev
  const WINDOW_MS =
    process.env.NODE_ENV === "production" ? 60 * 1000 : 30 * 1000; // Fenêtre plus courte en dev

  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${req.ip}:${req.user?.id || "anonymous"}`;
    const now = Date.now();
    const userAttempts = attempts.get(key);

    if (!userAttempts || now > userAttempts.resetTime) {
      attempts.set(key, { count: 1, resetTime: now + WINDOW_MS });
      return next();
    }

    if (userAttempts.count >= MAX_ATTEMPTS) {
      console.log(
        `🚫 Rate limit exceeded for sensitive operation: ${req.user?.email || req.ip}`,
      );
      return void res.status(429).json({
        error: "Too many attempts, please try again later",
        retryAfter: Math.ceil((userAttempts.resetTime - now) / 1000),
        code: "RATE_LIMITED",
      });
    }

    userAttempts.count++;
    next();
  };
}
