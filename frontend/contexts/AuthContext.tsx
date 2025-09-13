import {
  createContext,
  useContext,
  useState,
  useEffect,
  useMemo,
  useCallback,
  ReactNode,
} from "react";
import { authService } from "@/services/authService";
import "@/utils/auth-cleanup"; // Import auth debug tools
import type { AuthUser, LoginCredentials, UserRole } from "@shared/dao";
import { devLog } from "@/utils/devLogger";

interface AuthContextType {
  user: AuthUser | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  hasRole: (roles: UserRole[]) => boolean;
  isAdmin: () => boolean;
  canEdit: () => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    // Log pour debug mais pas d'erreur dans certain cas
    devLog.error("useAuth called outside AuthProvider");
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    initializeAuth();
  }, []);

  const initializeAuth = async () => {
    try {
      setIsLoading(true);

      // Check if user is stored locally
      const storedUser = authService.getStoredUser();
      const token = authService.getToken();

      devLog.log("🔄 Initializing auth...");
      devLog.log("📦 Stored user:", storedUser?.email || "none");
      devLog.log("🔑 Token exists:", !!token);

      if (storedUser && token) {
        try {
          devLog.log("✅ Verifying bootId with server before token verify...");
          const BOOT_KEY = "boot_id_v1";
          try {
            const bootRes = await fetch("/api/boot", {
              headers: { Accept: "application/json" },
            });
            if (bootRes.ok) {
              const bootData: { bootId?: string } = await bootRes.json();
              const serverBootId = String(bootData.bootId || "dev");
              const storedBootId = localStorage.getItem(BOOT_KEY);
              if (!storedBootId || storedBootId !== serverBootId) {
                devLog.info(
                  "🔄 BootId mismatch detected — clearing local auth to avoid invalid token verification",
                );
                authService.clearAuth();
                localStorage.setItem(BOOT_KEY, serverBootId);
                setUser(null);
                setIsLoading(false);
                return;
              }
            } else {
              devLog.warn(
                "⚠️ Boot endpoint returned non-ok status, continuing with token verification",
              );
            }
          } catch (bootErr) {
            devLog.warn(
              "⚠️ Boot check failed, continuing with token verification:",
              bootErr,
            );
          }

          devLog.log("✅ Verifying token with server...");
          // Verify with server
          const currentUser = await authService.getCurrentUser();
          setUser(currentUser);
          devLog.log("🔄 Auth restored from storage:", currentUser.email);
        } catch (error) {
          const errorMessage =
            error instanceof Error ? error.message : "Unknown error";

          // Distinguer les erreurs réseau des erreurs d'authentification
          if (
            errorMessage.includes("connexion") ||
            errorMessage.includes("réseau") ||
            errorMessage.includes("serveur") ||
            errorMessage.includes("trop de tentatives")
          ) {
            devLog.warn(
              "🌐 Network/rate-limit issue during auth verification:",
              errorMessage,
            );
            // Pour les erreurs réseau, on peut garder l'utilisateur connecté temporairement
            // mais on devra re-vérifier plus tard
            setUser(storedUser);
            devLog.log(
              "⚠️ Using cached user due to network issue, will retry later",
            );

            // Programmer une re-vérification dans 30 secondes
            setTimeout(() => {
              devLog.log("🔄 Retrying auth verification...");
              initializeAuth();
            }, 30000);
          } else {
            devLog.warn("⚠️ Auth verification failed:", errorMessage);
            devLog.log("🧹 Clearing invalid auth data...");
            // Clear auth data for authentication errors (401, invalid token, etc.)
            authService.clearAuth();
            setUser(null);
          }
        }
      } else {
        devLog.log("ℹ️ No stored credentials found");
        // Clear any partial auth data
        authService.clearAuth();
        setUser(null);
      }
    } catch (error) {
      devLog.error("❌ Auth initialization failed:", error);
      authService.clearAuth();
      setUser(null);
    } finally {
      setIsLoading(false);
      devLog.log("✅ Auth initialization complete");
    }
  };

  const login = useCallback(async (credentials: LoginCredentials) => {
    try {
      setIsLoading(true);
      const response = await authService.login(credentials);
      setUser(response.user);
      devLog.log("✅ Login successful:", response.user.email);
    } catch (error) {
      devLog.error("Login failed:", error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      setIsLoading(true);
      await authService.logout();
      setUser(null);
      devLog.log("✅ Logout successful");
    } catch (error) {
      devLog.error("Logout failed:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const hasRole = useCallback(
    (roles: UserRole[]): boolean => {
      return user ? roles.includes(user.role) : false;
    },
    [user],
  );

  const isAdmin = useCallback((): boolean => {
    return user?.role === "admin";
  }, [user]);

  const canEdit = useCallback((): boolean => {
    return hasRole(["admin", "user"]);
  }, [hasRole]);

  const value: AuthContextType = useMemo(
    () => ({
      user,
      isLoading,
      isAuthenticated: !!user,
      login,
      logout,
      hasRole,
      isAdmin,
      canEdit,
    }),
    [user, isLoading, login, logout, hasRole, isAdmin, canEdit],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
