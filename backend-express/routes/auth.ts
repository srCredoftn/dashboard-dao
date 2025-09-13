import express from "express";
import { AuthService } from "../services/authService";
import { NotificationService } from "../services/notificationService";
import { EmailService } from "../services/emailService";
import { authenticate, requireAdmin } from "../middleware/auth";
import { getIdempotency, setIdempotency } from "../utils/idempotency";
import { authLog, devLog } from "../utils/devLog";
import type { LoginCredentials } from "@shared/dao";

const router = express.Router();

// POST /api/auth/login - User login
router.post("/login", async (req, res) => {
  try {
    const credentials: LoginCredentials = req.body;

    if (!credentials.email || !credentials.password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const authResponse = await AuthService.login(credentials);
    if (!authResponse) {
      return res.status(401).json({ error: "Identifiants incorrects" });
    }

    try {
      // Send a private server notification to the logged-in user
      NotificationService.add({
        type: "system",
        title: "Connexion réussie",
        message: `Vous vous êtes connecté(e) avec succès le ${new Date().toLocaleString("fr-FR")}`,
        data: { email: authResponse.user.email },
        recipients: [authResponse.user.id],
      });

      // Email the user about the login (useful for audit/security)
      await EmailService.sendNotificationEmail(
        authResponse.user.email,
        "Connexion à votre compte",
        `Bonjour ${authResponse.user.name},\n\nUne connexion à votre compte a été effectuée le ${new Date().toLocaleString("fr-FR")}. Si ce n'est pas vous, veuillez changer votre mot de passe immédiatement.`,
      );
    } catch (_) {}

    return res.json(authResponse);
  } catch (error) {
    authLog.login(req.body.email || "unknown", false);
    return res.status(401).json({ error: "Identifiants incorrects" });
  }
});

// POST /api/auth/logout - User logout
router.post("/logout", authenticate, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.substring(7); // Remove 'Bearer ' prefix

    if (token) {
      await AuthService.logout(token);
    }

    try {
      await EmailService.sendNotificationEmail(
        req.user!.email,
        "Déconnexion de votre compte",
        `Bonjour ${req.user!.name},\n\nVous vous êtes déconnecté(e) le ${new Date().toLocaleString("fr-FR")}.`,
      );
    } catch (_) {}

    return res.json({ message: "Logged out successfully" });
  } catch (error) {
    devLog.error("Logout error:", error);
    return res.status(500).json({ error: "Logout failed" });
  }
});

// GET /api/auth/me - Get current user info
router.get("/me", authenticate, async (req, res) => {
  try {
    return res.json({ user: req.user });
  } catch (error) {
    devLog.error("Get user info error:", error);
    return res.status(500).json({ error: "Failed to get user info" });
  }
});

// GET /api/auth/users - Get all users (admin only)
router.get("/users", authenticate, requireAdmin, async (_req, res) => {
  try {
    const users = await AuthService.getAllUsers();
    const sa = AuthService.getSuperAdmin();
    const withFlag = users.map((u) => ({
      ...u,
      isSuperAdmin: sa ? sa.id === u.id : false,
    }));
    return res.json(withFlag);
  } catch (error) {
    devLog.error("Get users error:", error);
    return res.status(500).json({ error: "Failed to get users" });
  }
});

// Public registration endpoint - allows first user to self-register when no users exist, or when ALLOW_SELF_REGISTER=true
router.post("/register", async (req, res) => {
  try {
    const allowSelf =
      (process.env.ALLOW_SELF_REGISTER || "false").toLowerCase() === "true";

    const existing = await AuthService.getAllUsers();

    if (existing.length > 0 && !allowSelf) {
      return res.status(403).json({ error: "Registration disabled" });
    }

    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: "Name, email and password are required" });
    }

    const role = existing.length === 0 ? ("admin" as any) : ("user" as any);

    const newUser = await AuthService.createUser({
      name,
      email,
      role,
      password,
    });

    // Auto-login newly created user
    const authResp = await AuthService.login({ email, password });

    // Broadcast creation
    try {
      NotificationService.broadcast(
        "user_created",
        "Nouvel utilisateur",
        `${newUser.name} (${newUser.email}) a été créé`,
        { userId: newUser.id },
      );
    } catch (_) {}

    return res.status(201).json({ user: newUser, token: authResp?.token });
  } catch (error: any) {
    devLog.error("Registration error:", error);
    return res
      .status(500)
      .json({ error: error?.message || "Registration failed" });
  }
});

// POST /api/auth/users - Create new user (admin only)
router.post("/users", authenticate, requireAdmin, async (req, res) => {
  try {
    const idempKey = (req.header("x-idempotency-key") || "").trim();
    if (idempKey) {
      const cached = getIdempotency(idempKey);
      if (cached) return res.status(201).json(cached);
    }

    const userData = req.body;

    if (!userData.name || !userData.email || !userData.role) {
      return res
        .status(400)
        .json({ error: "Name, email, and role are required" });
    }

    const newUser = await AuthService.createUser({
      name: userData.name,
      email: userData.email,
      role: userData.role,
      password: userData.password, // Pass the password to the service
    });

    if (idempKey) setIdempotency(idempKey, newUser);

    // Send welcome email with credentials (do not expose password logs)
    try {
      const initialPassword = userData.password || "changeme123";
      await EmailService.sendNotificationEmail(
        newUser.email,
        "Votre compte a été créé",
        `Bonjour ${newUser.name},\n\nVotre compte a été créé sur 2SND.\nEmail: ${newUser.email}\nMot de passe temporaire: ${initialPassword}\n\nVeuillez vous connecter et changer votre mot de passe immédiatement.`,
      );
    } catch (_) {}

    // Broadcast and email all users about new user
    try {
      NotificationService.broadcast(
        "user_created",
        "Nouvel utilisateur",
        `${newUser.name} (${newUser.email}) a été créé avec le rôle "${newUser.role}"`,
        { userId: newUser.id },
      );
      const users = await AuthService.getAllUsers();
      await EmailService.sendBulkNotification(
        users.map((u) => u.email),
        "Nouvel utilisateur",
        `${newUser.name} (${newUser.email}) a rejoint la plateforme avec le rôle "${newUser.role}".`,
      );
    } catch (_) {}

    return res.status(201).json(newUser);
  } catch (error) {
    devLog.error("Create user error:", error);
    return res.status(500).json({ error: "Failed to create user" });
  }
});

// PUT /api/auth/users/:id/role - Update user role (admin only)
router.put("/users/:id/role", authenticate, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role, password } = req.body || {};

    if (!role) {
      return res.status(400).json({ error: "Role is required" });
    }

    // Only super admin can change roles and must confirm with current password
    if (!req.user || !AuthService.isSuperAdmin(req.user.id)) {
      return res.status(403).json({ error: "Forbidden: super admin required" });
    }
    const valid = await AuthService.verifyPasswordById(
      req.user.id,
      String(password || ""),
    );
    if (!valid) {
      return res
        .status(403)
        .json({ error: "Invalid password", code: "INVALID_PASSWORD" });
    }

    const updatedUser = await AuthService.updateUserRole(id, role);
    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Broadcast notification to all users
    NotificationService.broadcast(
      "role_update",
      "Mise à jour du rôle utilisateur",
      `${updatedUser.name} a maintenant le rôle \"${role}\"`,
      { userId: updatedUser.id, newRole: role },
    );

    try {
      const users = await AuthService.getAllUsers();
      await EmailService.sendBulkNotification(
        users.map((u) => u.email),
        "Mise à jour du rôle utilisateur",
        `${updatedUser.name} a maintenant le rôle \"${role}\".`,
      );
    } catch (e) {
      // log only
    }

    return res.json(updatedUser);
  } catch (error) {
    devLog.error("Update user role error:", error);
    return res.status(500).json({ error: "Failed to update user role" });
  }
});

// DELETE /api/auth/users/:id - Deactivate user (admin only)
router.delete("/users/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent admin from deactivating themselves
    if (req.user?.id === id) {
      return res
        .status(400)
        .json({ error: "Cannot deactivate your own account" });
    }

    const deactivated = await AuthService.deactivateUser(id);
    if (!deactivated) {
      return res.status(404).json({ error: "User not found" });
    }

    try {
      const usersBefore = await AuthService.getAllUsers();
      const target = usersBefore.find((u) => u.id === id);
      NotificationService.broadcast(
        "system",
        "Utilisateur désactivé",
        `${target ? `${target.name} (${target.email})` : `Utilisateur ${id}`} a été désactivé`,
        { userId: id },
      );
      const users = await AuthService.getAllUsers();
      await EmailService.sendBulkNotification(
        users.map((u) => u.email),
        "Utilisateur désactivé",
        `${target ? `${target.name} (${target.email})` : `Utilisateur ${id}`} a été désactivé.`,
      );
    } catch (_) {}

    return res.json({ message: "User deactivated successfully" });
  } catch (error) {
    devLog.error("Deactivate user error:", error);
    return res.status(500).json({ error: "Failed to deactivate user" });
  }
});

// POST /api/auth/change-password - Change password
router.post("/change-password", authenticate, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters long" });
    }

    const success = await AuthService.changePassword(req.user!.id, newPassword);
    if (!success) {
      return res.status(404).json({ error: "User not found" });
    }

    try {
      NotificationService.add({
        type: "system",
        title: "Mot de passe modifié",
        message: `Votre mot de passe a été modifié le ${new Date().toLocaleString("fr-FR")}.`,
        data: {},
        recipients: [req.user!.id],
      });
      await EmailService.sendNotificationEmail(
        req.user!.email,
        "Votre mot de passe a été modifié",
        `Bonjour ${req.user!.name},\n\nVotre mot de passe a été modifié avec succès. Si ce n'est pas vous, contactez un administrateur immédiatement.`,
      );

      // Diffusion globale + email à tous
      NotificationService.broadcast(
        "system",
        "Mot de passe modifié",
        `${req.user!.name} a modifi�� son mot de passe`,
        { userId: req.user!.id },
      );
      const usersAll = await AuthService.getAllUsers();
      await EmailService.sendBulkNotification(
        usersAll.map((u) => u.email),
        "Mot de passe modifié",
        `${req.user!.name} (${req.user!.email}) a modifié son mot de passe le ${new Date().toLocaleString("fr-FR")}.`,
      );
    } catch (_) {}

    return res.json({ message: "Password changed successfully" });
  } catch (error) {
    devLog.error("Change password error:", error);
    return res.status(500).json({ error: "Failed to change password" });
  }
});

// PUT /api/auth/profile - Update user profile (email change forbidden for all)
router.put("/profile", authenticate, async (req, res) => {
  try {
    const { name, email } = req.body || {};

    if (!name || typeof name !== "string" || name.trim().length === 0) {
      return res.status(400).json({ error: "Name is required" });
    }

    // If client tries to change email, reject explicitly
    if (email && email.toLowerCase() !== req.user!.email.toLowerCase()) {
      return res.status(403).json({ error: "Email change is not allowed" });
    }

    const updatedUser = await AuthService.updateProfile(req.user!.id, {
      name,
      email: req.user!.email,
    });
    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Notify the user by email about profile update
    try {
      await EmailService.sendNotificationEmail(
        updatedUser.email,
        "Profil mis à jour",
        `Bonjour ${updatedUser.name},\n\nVotre profil a été modifié le ${new Date().toLocaleString("fr-FR")}.`,
      );
    } catch (_) {}

    const authUser = {
      id: updatedUser.id,
      name: updatedUser.name,
      email: updatedUser.email,
      role: updatedUser.role,
    };

    return res.json(authUser);
  } catch (error) {
    devLog.error("Update profile error:", error);
    if ((error as Error).message === "Email change not allowed") {
      return res.status(403).json({ error: "Email change is not allowed" });
    }
    if ((error as Error).message === "Email already exists") {
      return res.status(400).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: "Failed to update profile" });
  }
});

// POST /api/auth/forgot-password - Request password reset
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    if (!/\S+@\S+\.\S+/.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const token = await AuthService.generateResetToken(email);

    if (!token) {
      // Don't reveal if email exists or not for security
      return res.json({
        message:
          "Si cet email existe, un code de réinitialisation a été envoyé.",
      });
    }

    // Send email with SMTP (fallbacks ensure no crash in dev)
    try {
      const { EmailService } = await import("../services/emailService");
      const result = await EmailService.sendPasswordResetEmail(email, token);
      devLog.info(
        `📧 Password reset email queued for ${email} (messageId: ${result.messageId})`,
      );
    } catch (mailErr) {
      devLog.error("SMTP send error:", mailErr);
      // Do not leak details; still respond success to avoid account enumeration and UX issues
    }

    const response: any = {
      message:
        "Un code de réinitialisation a été envoyé à votre adresse email.",
    };
    if (process.env.NODE_ENV !== "production") {
      response.developmentToken = token;
    }

    return res.json(response);
  } catch (error) {
    devLog.error("Forgot password error:", error);
    return res
      .status(500)
      .json({ error: "Failed to process password reset request" });
  }
});

// POST /api/auth/verify-reset-token - Verify reset token
router.post("/verify-reset-token", async (req, res) => {
  try {
    const { email, token } = req.body;

    if (!email || !token) {
      return res.status(400).json({ error: "Email and token are required" });
    }

    const isValid = await AuthService.verifyResetToken(token, email);

    if (!isValid) {
      return res.status(400).json({ error: "Code invalide ou expiré" });
    }

    return res.json({ message: "Code vérifié avec succès" });
  } catch (error) {
    devLog.error("Verify reset token error:", error);
    return res.status(500).json({ error: "Failed to verify reset token" });
  }
});

// POST /api/auth/reset-password - Reset password with token
router.post("/reset-password", async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
      return res.status(400).json({
        error: "Email, token, and new password are required",
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir au moins 6 caractères",
      });
    }

    const success = await AuthService.resetPasswordWithToken(
      token,
      email,
      newPassword,
    );

    if (!success) {
      return res.status(400).json({ error: "Code invalide ou expiré" });
    }

    try {
      await EmailService.sendNotificationEmail(
        email,
        "Mot de passe réinitialisé",
        `Bonjour,\n\nVotre mot de passe a été réinitialisé le ${new Date().toLocaleString("fr-FR")}. Si ce n'est pas vous, contactez un administrateur immédiatement.`,
      );
    } catch (_) {}

    return res.json({ message: "Mot de passe réinitialisé avec succès" });
  } catch (error) {
    devLog.error("Reset password error:", error);
    return res.status(500).json({ error: "Failed to reset password" });
  }
});

export default router;
