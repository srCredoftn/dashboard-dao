import type {
  LoginCredentials,
  AuthResponse,
  AuthUser,
  User,
} from "@shared/dao";
// Using native fetch with simpler timeout management

const API_BASE_URL = "/api/auth";

class AuthApiService {
  private token: string | null = null;

  constructor() {
    // Load token from localStorage on initialization
    this.token = localStorage.getItem("auth_token");
  }

  private async request<T>(endpoint: string, options?: any): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    // Add existing headers if they exist
    if (options?.headers) {
      if (options.headers instanceof Headers) {
        options.headers.forEach((value: string, key: string) => {
          headers[key] = value;
        });
      } else if (Array.isArray(options.headers)) {
        options.headers.forEach(([key, value]: [string, string]) => {
          headers[key] = value;
        });
      } else {
        Object.assign(headers, options.headers);
      }
    }

    // Support custom idempotency key passed via options.idempotencyKey
    if (options?.idempotencyKey) {
      headers["x-idempotency-key"] = options.idempotencyKey;
      // avoid sending custom prop to fetch
      delete options.idempotencyKey;
    }

    // Add authorization header if token exists
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    try {
      console.log(`🌐 Auth API request: ${url}`);

      // Utiliser fetch natif avec timeout simple
      // Use secureFetch to avoid third-party fetch interception
      const secureFetch = (await import("@/utils/secure-fetch")).default;

      // Create an AbortController to satisfy callers/tests that expect a signal
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s

      let response;
      try {
        try {
          response = await secureFetch.fetch(url, {
            ...options,
            headers,
            signal: controller.signal,
            useNativeFetch: true,
            maxRetries: 2,
            timeout: 30000,
          } as any);
        } catch (sfError) {
          // If secureFetch fails (network/TypeError), attempt a direct window.fetch fallback
          console.warn(
            "secureFetch failed, attempting native fetch fallback:",
            sfError,
          );
          try {
            const nativeOptions: any = {
              ...options,
              headers,
              signal: controller.signal,
            };
            // Ensure method is set
            if (!nativeOptions.method) nativeOptions.method = "GET";
            response = await window.fetch(url, nativeOptions as any);
          } catch (nativeErr) {
            // rethrow original secureFetch error for clearer debugging
            throw sfError;
          }
        }
      } finally {
        clearTimeout(timeoutId);
      }

      // Note: secureFetch handles its own retries/timeouts in addition to signal

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));

        // If 401, clear local storage (invalid/expired token)
        if (response.status === 401) {
          console.warn("⚠️ Auth API returned 401 - clearing auth data");
          this.clearAuth();
        }

        // Special handling for rate limiting (429)
        if (response.status === 429) {
          const retryAfter = response.headers.get("Retry-After");
          throw new Error(
            `Trop de tentatives de connexion. Veuillez réessayer dans ${retryAfter || "quelques"} secondes.`,
          );
        }

        // Message d'erreur simple pour les erreurs d'authentification
        if (response.status === 401) {
          throw new Error("Identifiants incorrects, veuillez réessayer");
        }

        throw new Error(
          errorData.error || `HTTP error! status: ${response.status}`,
        );
      }

      console.log(`�� Auth API success: ${url} (${response.status})`);
      return await response.json();
    } catch (error: any) {
      if (error?.name === "AbortError") {
        console.warn(`⏰ Request timeout for ${endpoint}`);
        throw new Error("La requête a pris trop de temps. Veuillez réessayer.");
      }

      if (
        error instanceof TypeError &&
        error.message.includes("Failed to fetch")
      ) {
        console.warn(`🌐 Network error for ${endpoint}:`, error.message);
        throw new Error(
          "Impossible de se connecter au serveur. Vérifiez votre connexion internet.",
        );
      }

      console.error(`Auth API request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // Login user
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      const response = await this.request<AuthResponse>("/login", {
        method: "POST",
        body: JSON.stringify(credentials),
      });

      // Store token in localStorage and memory
      this.token = response.token;
      localStorage.setItem("auth_token", response.token);
      localStorage.setItem("auth_user", JSON.stringify(response.user));

      console.log("🔐 User logged in:", response.user.email);
      return response;
    } catch (error) {
      console.error("Login failed:", error);

      // Message simple pour les erreurs d'authentification
      if (error instanceof Error) {
        if (
          error.message.includes("401") ||
          error.message.includes("Identifiants incorrects")
        ) {
          throw new Error("Identifiants incorrects, veuillez réessayer");
        }
      }

      throw error;
    }
  }

  // Logout user
  async logout(): Promise<void> {
    try {
      if (this.token) {
        await this.request<void>("/logout", {
          method: "POST",
        });
      }
    } catch (error) {
      console.error("Logout API call failed:", error);
      // Continue with local logout even if API call fails
    } finally {
      // Clear local storage and memory
      this.token = null;
      localStorage.removeItem("auth_token");
      localStorage.removeItem("auth_user");
      console.log("��� User logged out");
    }
  }

  // Get current user info
  async getCurrentUser(): Promise<AuthUser> {
    return this.request<{ user: AuthUser }>("/me").then((res) => res.user);
  }

  // Get stored user from localStorage
  getStoredUser(): AuthUser | null {
    try {
      const userData = localStorage.getItem("auth_user");
      return userData ? JSON.parse(userData) : null;
    } catch {
      return null;
    }
  }

  // Check if user is authenticated
  isAuthenticated(): boolean {
    return !!this.token && !!this.getStoredUser();
  }

  // Get current token
  getToken(): string | null {
    return this.token;
  }

  // Admin operations
  async getAllUsers(): Promise<User[]> {
    return this.request<User[]>("/users");
  }

  async createUser(
    userData: {
      name: string;
      email: string;
      role: string;
    },
    opts?: { idempotencyKey?: string },
  ): Promise<User> {
    const options: any = {
      method: "POST",
      body: JSON.stringify(userData),
    };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    return this.request<User>("/users", options);
  }

  // Public self-registration (used when no users exist or ALLOW_SELF_REGISTER=true)
  async register(userData: { name: string; email: string; password: string }) {
    const resp = await this.request<{ user: User; token?: string }>(
      "/register",
      {
        method: "POST",
        body: JSON.stringify(userData),
      },
    );
    if (resp.token) {
      this.token = resp.token;
      localStorage.setItem("auth_token", resp.token);
      localStorage.setItem("auth_user", JSON.stringify(resp.user));
    }
    return resp;
  }

  async updateUserRole(
    userId: string,
    role: string,
    password: string,
  ): Promise<User> {
    return this.request<User>(`/users/${userId}/role`, {
      method: "PUT",
      body: JSON.stringify({ role, password }),
    });
  }

  async deactivateUser(
    userId: string,
    opts?: { idempotencyKey?: string },
  ): Promise<void> {
    const options: any = { method: "DELETE" };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    return this.request<void>(`/users/${userId}`, options);
  }

  async changePassword(newPassword: string): Promise<void> {
    return this.request<void>("/change-password", {
      method: "POST",
      body: JSON.stringify({ newPassword }),
    });
  }

  async updateProfile(profileData: { name: string }): Promise<AuthUser> {
    return this.request<AuthUser>("/profile", {
      method: "PUT",
      body: JSON.stringify({ name: profileData.name }),
    });
  }

  // Admin: get active sessions and revoke a session
  async getActiveSessions(): Promise<
    { token: string; user: AuthUser | null }[]
  > {
    const secureFetch = (await import("@/utils/secure-fetch")).default;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const response = await secureFetch.fetch("/api/admin/sessions", {
      method: "GET",
      headers,
      useNativeFetch: true,
      timeout: 30000,
    } as any);
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return data.sessions || [];
  }

  async revokeSession(tokenToRevoke: string): Promise<void> {
    const secureFetch = (await import("@/utils/secure-fetch")).default;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const response = await secureFetch.fetch("/api/admin/revoke-session", {
      method: "POST",
      headers,
      body: JSON.stringify({ token: tokenToRevoke }),
      useNativeFetch: true,
      timeout: 30000,
    } as any);
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `HTTP error! status: ${response.status}`);
    }
    return;
  }

  // Clear authentication data (useful for expired tokens)
  clearAuth(): void {
    console.log("��� Clearing authentication data...");
    this.token = null;
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_user");
    console.log("✅ Authentication data cleared");
  }
}

export const authService = new AuthApiService();
