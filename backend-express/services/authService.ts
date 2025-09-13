import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { devLog, authLog } from "../utils/devLog";
import type {
  User,
  AuthUser,
  LoginCredentials,
  AuthResponse,
  UserRole,
} from "@shared/dao";

// JWT Configuration - Securite renforcee
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "24h";

// Validation du secret JWT au démarrage
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  devLog.error("🚨 ERREUR CRITIQUE: JWT_SECRET manquant ou trop court");
  devLog.error(
    "   Veuillez définir une variable d'environnement JWT_SECRET de plus de 32 caractères",
  );
  process.exit(1);
}

// Secure in-memory user storage with hashed passwords
let users: User[] = [];
const userPasswords: Record<string, string> = {};

// Password reset tokens (in production, use Redis or database)
const resetTokens: Record<string, { email: string; expires: Date }> = {};

// Session tracking (in production, use Redis)
const activeSessions: Set<string> = new Set();

// Initialize users with hashed passwords. Behavior:
// - If SEED_USERS=true => create a set of demo users (development)
// - Else if ADMIN_EMAIL & ADMIN_PASSWORD are set => create a single admin user from env
// - Otherwise start with an empty user list (production safe)
async function initializeUsers() {
  users = [];

  const shouldSeedUsers =
    process.env.SEED_USERS === "1" || process.env.SEED_USERS === "true";

  // Empêcher le seeding en production pour des raisons de sécurité
  if (process.env.NODE_ENV === "production" && shouldSeedUsers) {
    console.error(
      "❌ SECURITY ERROR: SEED_USERS ne peut pas être activé en production",
    );
    process.exit(1);
  }

  if (shouldSeedUsers) {
    console.warn(
      "⚠️  DEVELOPMENT ONLY: Création d'utilisateurs de développement",
    );
    const defaultUsers = [
      {
        id: "1",
        name: "Admin User",
        email: "admin@2snd.fr",
        role: "admin" as UserRole,
        password: "admin123",
      },
      {
        id: "2",
        name: "Marie Dubois",
        email: "marie.dubois@2snd.fr",
        role: "user" as UserRole,
        password: "marie123",
      },
      {
        id: "3",
        name: "Pierre Martin",
        email: "pierre.martin@2snd.fr",
        role: "user" as UserRole,
        password: "pierre123",
      },
    ];

    for (const userData of defaultUsers) {
      const hashedPassword = await bcrypt.hash(userData.password, 12);
      const user: User = {
        id: userData.id,
        name: userData.name,
        email: userData.email,
        role: userData.role,
        createdAt: new Date().toISOString(),
        isActive: true,
      };
      users.push(user);
      userPasswords[userData.email] = hashedPassword;
    }

    devLog.info("🔐 AuthService initialized with seeded demo users");
    users.forEach((u) => devLog.info(`  - ${u.email} (${u.role})`));
    return;
  }

  // Try to create an admin user from environment variables if provided
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminEmail && adminPassword) {
    const hashed = await bcrypt.hash(adminPassword, 12);
    const adminUser: User = {
      id: "1",
      name: "Administrator",
      email: adminEmail,
      role: "admin" as UserRole,
      createdAt: new Date().toISOString(),
      isActive: true,
    };
    users.push(adminUser);
    userPasswords[adminEmail] = hashed;
    devLog.info(`🔐 Admin user created from environment: ${adminEmail}`);
    return;
  }

  devLog.warn(
    "⚠️ No initial users created. Set ADMIN_EMAIL + ADMIN_PASSWORD to create an admin on startup or run with SEED_USERS=true for development.",
  );
}

export class AuthService {
  // Initialize the service
  static async initialize() {
    await initializeUsers();
  }

  // Login user with secure password verification
  static async login(
    credentials: LoginCredentials,
  ): Promise<AuthResponse | null> {
    try {
      devLog.info(`🔐 Login attempt for: ${credentials.email}`);

      const user = users.find(
        (u) =>
          u.email.toLowerCase() === credentials.email.toLowerCase() &&
          u.isActive,
      );

      if (!user) {
        authLog.login(credentials.email, false);
        return null;
      }

      const hashedPassword = userPasswords[user.email];
      if (!hashedPassword) {
        authLog.login(credentials.email, false);
        return null;
      }

      const isValidPassword = await bcrypt.compare(
        credentials.password,
        hashedPassword,
      );
      if (!isValidPassword) {
        authLog.login(credentials.email, false);
        return null;
      }

      // Generate secure JWT token
      const authUser: AuthUser = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      };

      if (!JWT_SECRET) {
        throw new Error("JWT_SECRET is not configured");
      }

      const token = jwt.sign(
        authUser,
        JWT_SECRET as jwt.Secret,
        {
          expiresIn: JWT_EXPIRES_IN as any,
          issuer: "dao-management",
          audience: "dao-app",
        } as any,
      );

      // Track active session
      activeSessions.add(token);

      // Update last login
      user.lastLogin = new Date().toISOString();

      authLog.login(user.email, true);

      return {
        user: authUser,
        token,
      };
    } catch (error) {
      devLog.error("Login error:", error);
      return null;
    }
  }

  // Verify JWT token
  static async verifyToken(token: string): Promise<AuthUser | null> {
    try {
      devLog.debug(`🔍 Verifying token: ${token.substring(0, 20)}...`);
      devLog.debug(`📊 Active sessions count: ${activeSessions.size}`);

      // Premièrement, essayons de décoder et vérifier le JWT
      const decoded = jwt.verify(token, JWT_SECRET as string, {
        issuer: "dao-management",
        audience: "dao-app",
      }) as AuthUser;

      devLog.debug(`✅ Token decoded successfully for user: ${decoded.email}`);

      // Verify user still exists and is active
      const user = users.find((u) => u.id === decoded.id && u.isActive);
      if (!user) {
        devLog.warn(`❌ User not found or inactive: ${decoded.id}`);
        activeSessions.delete(token);
        return null;
      }

      // Si le token est valide mais pas dans les sessions actives (ex: après redémarrage),
      // on l'ajoute automatiquement aux sessions actives
      if (!activeSessions.has(token)) {
        devLog.debug(
          `🔄 Token valid but not in sessions, adding to active sessions`,
        );
        activeSessions.add(token);
      }

      authLog.tokenVerification(user.email, true);
      return decoded;
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        devLog.warn(`❌ JWT Error: ${error.message}`);
      } else {
        devLog.warn(`❌ Token verification error:`, error);
      }
      activeSessions.delete(token);
      return null;
    }
  }

  // List active sessions (metadata only, no raw tokens for security)
  static async listActiveSessions(): Promise<
    {
      sessionId: string;
      user: AuthUser | null;
      issuedAt?: number;
      expiresAt?: number;
    }[]
  > {
    const sessions = Array.from(activeSessions);
    const result: {
      sessionId: string;
      user: AuthUser | null;
      issuedAt?: number;
      expiresAt?: number;
    }[] = [];
    for (const token of sessions) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET as string, {
          issuer: "dao-management",
          audience: "dao-app",
        }) as AuthUser & { iat?: number; exp?: number };
        // Ne pas exposer le token brut, utiliser un hash comme ID de session
        const sessionId = require("crypto")
          .createHash("sha256")
          .update(token)
          .digest("hex")
          .substring(0, 16);
        result.push({
          sessionId,
          user: {
            id: decoded.id,
            email: decoded.email,
            role: decoded.role,
            name: decoded.name,
          },
          issuedAt: decoded.iat ? decoded.iat * 1000 : undefined,
          expiresAt: decoded.exp ? decoded.exp * 1000 : undefined,
        });
      } catch (_) {
        const sessionId = require("crypto")
          .createHash("sha256")
          .update(token)
          .digest("hex")
          .substring(0, 16);
        result.push({ sessionId, user: null });
      }
    }
    return result;
  }

  // Logout user
  static async logout(token: string): Promise<void> {
    activeSessions.delete(token);
  }

  // Get current user
  static async getCurrentUser(token: string): Promise<AuthUser | null> {
    return this.verifyToken(token);
  }

  // Get all users (admin only)
  static async getAllUsers(): Promise<User[]> {
    return users.filter((u) => u.isActive);
  }

  // Get a user by email (case-insensitive)
  static getUserByEmail(email: string): User | null {
    const e = email.toLowerCase();
    return users.find((u) => u.email.toLowerCase() === e && u.isActive) || null;
  }

  // Determine the super admin: priority to ADMIN_EMAIL if present, else earliest admin by createdAt
  static getSuperAdmin(): User | null {
    const adminEmail = process.env.ADMIN_EMAIL?.toLowerCase();
    if (adminEmail) {
      const envAdmin = users.find(
        (u) =>
          u.isActive &&
          u.role === ("admin" as UserRole) &&
          u.email.toLowerCase() === adminEmail,
      );
      if (envAdmin) return envAdmin;
    }
    const admins = users
      .filter((u) => u.isActive && u.role === ("admin" as UserRole))
      .sort((a, b) => {
        const ta = Date.parse(a.createdAt || "");
        const tb = Date.parse(b.createdAt || "");
        if (!isNaN(ta) && !isNaN(tb)) return ta - tb;
        return (a.id || "").localeCompare(b.id || "");
      });
    return admins[0] || null;
  }

  // Check if a given user id is the super admin
  static isSuperAdmin(userId: string): boolean {
    const sa = this.getSuperAdmin();
    return Boolean(sa && sa.id === userId);
  }

  // Verify password for a given email
  static async verifyPasswordByEmail(
    email: string,
    password: string,
  ): Promise<boolean> {
    const user = this.getUserByEmail(email);
    if (!user) return false;
    const hash = userPasswords[user.email];
    if (!hash) return false;
    try {
      return await bcrypt.compare(password, hash);
    } catch {
      return false;
    }
  }

  // Verify password for a given user id
  static async verifyPasswordById(
    id: string,
    password: string,
  ): Promise<boolean> {
    const user = users.find((u) => u.id === id && u.isActive);
    if (!user) return false;
    const hash = userPasswords[user.email];
    if (!hash) return false;
    try {
      return await bcrypt.compare(password, hash);
    } catch {
      return false;
    }
  }

  // Create new user with hashed password
  static async createUser(userData: {
    name: string;
    email: string;
    role: UserRole;
    password?: string;
  }): Promise<User> {
    // Normalize and validate name: title case and trimmed
    const normalizedName = (userData.name || "").trim().split(/\s+/).map((w) =>
      w.charAt(0).toUpperCase() + w.slice(1).toLowerCase(),
    ).join(" ");

    // Ensure no other active user has the same name (case-insensitive)
    const sameName = users.find(
      (u) => u.isActive && u.name.toLowerCase() === normalizedName.toLowerCase(),
    );
    if (sameName) {
      throw new Error("User name already taken");
    }

    const existingUser = users.find(
      (u) => u.email.toLowerCase() === userData.email.toLowerCase(),
    );

    if (existingUser) {
      throw new Error("User already exists");
    }

    const defaultPassword = userData.password || "changeme123";
    const hashedPassword = await bcrypt.hash(defaultPassword, 12);

    const newUser: User = {
      id: Date.now().toString(),
      name: normalizedName,
      email: userData.email.toLowerCase(),
      role: userData.role,
      createdAt: new Date().toISOString(),
      isActive: true,
    };

    users.push(newUser);
    userPasswords[newUser.email] = hashedPassword;

    devLog.info(`👤 New user created: ${newUser.email} Role: ${newUser.role}`);
    return newUser;
  }

  // Update user role
  static async updateUserRole(
    id: string,
    role: UserRole,
  ): Promise<User | null> {
    const user = users.find((u) => u.id === id);
    if (!user) {
      return null;
    }

    user.role = role;
    devLog.info(`🔄 User role updated: ${user.email} → ${role}`);
    return user;
  }

  // Deactivate user
  static async deactivateUser(id: string): Promise<boolean> {
    const user = users.find((u) => u.id === id);
    if (!user) {
      return false;
    }

    user.isActive = false;

    // Invalidate all sessions for this user
    for (const token of activeSessions) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET as string) as AuthUser;
        if (decoded.id === id) {
          activeSessions.delete(token);
        }
      } catch {
        // Token already invalid
      }
    }

    devLog.info(`🚫 User deactivated: ${user.email}`);
    return true;
  }

  // Change password
  static async changePassword(
    id: string,
    newPassword: string,
  ): Promise<boolean> {
    const user = users.find((u) => u.id === id);
    if (!user) {
      return false;
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    userPasswords[user.email] = hashedPassword;

    devLog.info(`🔑 Password changed for: ${user.email}`);
    return true;
  }

  // Update profile (email change forbidden)
  static async updateProfile(
    id: string,
    updates: { name: string; email?: string },
  ): Promise<User | null> {
    const user = users.find((u) => u.id === id);
    if (!user) {
      return null;
    }

    // Forbid email changes entirely
    if (
      updates.email &&
      updates.email.toLowerCase() !== user.email.toLowerCase()
    ) {
      throw new Error("Email change not allowed");
    }

    // Only update the name (normalize to Title Case and prevent duplicates)
    const normalizedName = (updates.name || "").trim().split(/\s+/).map((w) =>
      w.charAt(0).toUpperCase() + w.slice(1).toLowerCase(),
    ).join(" ");

    // Prevent duplicate names
    const conflict = users.find(
      (u) => u.isActive && u.id !== user.id && u.name.toLowerCase() === normalizedName.toLowerCase(),
    );
    if (conflict) throw new Error("User name already taken");

    user.name = normalizedName;

    devLog.info(`📝 Profile updated for: ${user.email}`);
    return user;
  }

  // Generate password reset token
  static async generateResetToken(email: string): Promise<string | null> {
    const user = users.find(
      (u) => u.email.toLowerCase() === email.toLowerCase() && u.isActive,
    );

    if (!user) {
      return null;
    }

    // Génération sécurisée du token de reset avec crypto
    const crypto = require("crypto");
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    resetTokens[token] = { email: user.email, expires };

    console.log(`���� Password reset token generated for: ${user.email}`);
    return token;
  }

  // Verify reset token
  static async verifyResetToken(
    token: string,
    email: string,
  ): Promise<boolean> {
    const resetData = resetTokens[token];
    if (!resetData) {
      return false;
    }

    if (resetData.email.toLowerCase() !== email.toLowerCase()) {
      return false;
    }

    if (new Date() > resetData.expires) {
      delete resetTokens[token];
      return false;
    }

    return true;
  }

  // Reset password with token
  static async resetPasswordWithToken(
    token: string,
    email: string,
    newPassword: string,
  ): Promise<boolean> {
    const isValidToken = await this.verifyResetToken(token, email);
    if (!isValidToken) {
      return false;
    }

    const user = users.find(
      (u) => u.email.toLowerCase() === email.toLowerCase() && u.isActive,
    );

    if (!user) {
      return false;
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    userPasswords[user.email] = hashedPassword;

    // Remove used token
    delete resetTokens[token];

    console.log(`🔑 Password reset successful for: ${user.email}`);
    return true;
  }

  // Get active session count
  static getActiveSessionCount(): number {
    return activeSessions.size;
  }

  // Clean expired tokens (call periodically)
  static cleanupExpiredTokens(): void {
    let cleanedCount = 0;
    for (const token of activeSessions) {
      try {
        jwt.verify(token, JWT_SECRET as string);
      } catch {
        activeSessions.delete(token);
        cleanedCount++;
      }
    }
    if (cleanedCount > 0) {
      console.log(`🧹 Cleaned ${cleanedCount} expired tokens`);
    }
  }

  // Clear all active sessions
  static async clearAllSessions(): Promise<void> {
    activeSessions.clear();
    devLog.info("🧹 All sessions cleared");
  }

  // Reinitialize users and password store to defaults
  static async reinitializeUsers(): Promise<void> {
    // Clear existing users and password store
    users = [];
    for (const k of Object.keys(userPasswords)) {
      delete userPasswords[k];
    }
    // Clear reset tokens
    for (const t of Object.keys(resetTokens)) {
      delete resetTokens[t];
    }

    await initializeUsers();
    devLog.info("🔄 Users reinitialized to defaults");
  }
}

// Initialize on startup
AuthService.initialize().catch(console.error);

// Debug: Log active sessions periodically in development
if (process.env.NODE_ENV === "development") {
  setInterval(() => {
    console.log(`📊 Active sessions: ${activeSessions.size}`);
  }, 30 * 1000); // Every 30 seconds in development
}

// Cleanup expired tokens every hour
setInterval(
  () => {
    console.log("🧹 Running token cleanup...");
    AuthService.cleanupExpiredTokens();
  },
  60 * 60 * 1000,
);
