// Auth debugging utilities
// These functions are only available in development

declare global {
  interface Window {
    clearAuth: () => void;
    showAuthDebug: () => void;
    forceLogin: () => void;
  }
}

export function setupAuthDebug() {
  if (process.env.NODE_ENV !== "development") {
    return;
  }

  // Clear all auth data
  window.clearAuth = () => {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_user");
    console.log(
      "🧹 Auth data cleared. Reload the page to see the login screen.",
    );
  };

  // Show current auth state
  window.showAuthDebug = () => {
    const token = localStorage.getItem("auth_token");
    const user = localStorage.getItem("auth_user");

    console.log("🔍 Auth Debug Info:");
    console.log("Token exists:", !!token);
    console.log(
      "Token (first 20 chars):",
      token?.substring(0, 20) + "..." || "none",
    );
    console.log("User data:", user ? JSON.parse(user) : "none");

    if (token) {
      // Try to decode JWT payload (without verification)
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        console.log("Token payload:", payload);
        console.log("Token expires:", new Date(payload.exp * 1000));
        console.log("Token expired:", Date.now() > payload.exp * 1000);
      } catch (e: any) {
        console.log("Could not decode token:", e?.message || e);
      }
    }
  };

  // Force redirect to login
  window.forceLogin = () => {
    window.clearAuth();
    window.location.href = "/login";
  };

  console.log("🛠️ Auth debug utilities loaded:");
  console.log("  - clearAuth() - Clear all auth data");
  console.log("  - showAuthDebug() - Show current auth state");
  console.log("  - forceLogin() - Clear auth and go to login");
}
