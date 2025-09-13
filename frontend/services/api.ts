import type { Dao } from "@shared/dao";
import { cacheService } from "./cacheService";

const API_BASE_URL = "/api";

class ApiService {
  private async request<T>(endpoint: string, options?: any): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;

    // Get token from localStorage
    const token = localStorage.getItem("auth_token");

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

    // Support idempotencyKey passed via options
    if (options?.idempotencyKey) {
      headers["x-idempotency-key"] = options.idempotencyKey;
      delete options.idempotencyKey;
    }

    // Add Authorization header if token exists
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    try {
      const secureFetch = (await import("@/utils/secure-fetch")).default;
      let response: Response | null = null;

      try {
        // Prefer a fresh native fetch path and allow a couple retries
        response = await secureFetch.fetch(url, {
          ...options,
          headers,
          useNativeFetch: true,
          maxRetries: 2,
          timeout: 15000,
        } as any);
      } catch (secureErr) {
        // Fallback to plain fetch if secure-fetch fails (realm shutdown/interceptors etc.)
        console.warn(
          "secure-fetch failed, falling back to native fetch:",
          secureErr,
        );
        response = await fetch(url, { ...(options || {}), headers });
      }

      if (!response.ok) {
        // Handle authentication errors
        if (response.status === 401) {
          // Clear invalid token
          localStorage.removeItem("auth_token");
          localStorage.removeItem("auth_user");

          // Redirect to login page if not already there
          if (!window.location.pathname.includes("/login")) {
            window.location.href = "/login";
          }

          throw new Error("Session expirée. Veuillez vous reconnecter.");
        }

        const errorData = await response.json().catch(() => ({}));
        throw new Error(
          errorData.error || `HTTP error! status: ${response.status}`,
        );
      }

      return await response.json();
    } catch (error) {
      // Handle network errors
      const msg = error instanceof Error ? error.message : String(error);
      if (
        msg.includes("Failed to fetch") ||
        msg.includes("Network request failed") ||
        msg.includes("SecureFetchError") ||
        msg.toLowerCase().includes("timeout") ||
        msg.toLowerCase().includes("abort")
      ) {
        throw new Error(
          "Erreur de connexion. Vérifiez votre connexion internet.",
        );
      }

      // For known not-found errors, avoid noisy error logs (handled by callers)
      const lower = msg.toLowerCase();
      if (lower.includes("dao not found") || lower.includes("404")) {
        // Use dev logger for less verbose output
        try {
          const { devLog } = await import("@/utils/devLogger");
          devLog.warn(`API ${endpoint} returned not-found: ${msg}`);
        } catch {
          // fallback
          console.warn(`API ${endpoint} returned not-found: ${msg}`);
        }
        throw new Error(msg);
      }

      console.error(`API request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // DAO operations
  async getAllDaos(): Promise<Dao[]> {
    // Always request server and normalize response (server may return { items, total, ... })
    const fetchAndNormalize = async (): Promise<Dao[]> => {
      const res: any = await this.request<any>("/dao");
      if (Array.isArray(res)) return res;
      if (res && Array.isArray(res.items)) return res.items;
      // If server returned an object with items nested under data or similar, try that
      if (res && Array.isArray(res.data)) return res.data;
      return [];
    };

    if (process.env.NODE_ENV !== "production") {
      const daos = await fetchAndNormalize();
      try {
        cacheService.delete("all-daos");
      } catch {}
      return daos;
    }

    return cacheService.getOrSet("all-daos", fetchAndNormalize, 2 * 60 * 1000);
  }

  async getDaoById(id: string): Promise<Dao> {
    console.log(`🌐 API: getDaoById called with ID=${id}`);
    return cacheService.getOrSet(
      `dao-${id}`,
      async () => {
        console.log(`📡 API: Making request to /dao/${id}`);
        const result = await this.request<Dao>(`/dao/${id}`);
        console.log(`📥 API: Received response for ID=${id}:`, {
          id: result.id,
          numeroListe: result.numeroListe,
          objetDossier: result.objetDossier,
        });
        return result;
      },
      3 * 60 * 1000, // Cache pendant 3 minutes
    );
  }

  async createDao(
    daoData: Omit<Dao, "id" | "createdAt" | "updatedAt">,
    opts?: { idempotencyKey?: string },
  ): Promise<Dao> {
    const headers: Record<string, string> = {};
    if (opts?.idempotencyKey)
      headers["x-idempotency-key"] = opts.idempotencyKey;
    const result = await this.request<Dao>("/dao", {
      method: "POST",
      body: JSON.stringify(daoData),
      headers,
    });

    // Invalider le cache après création
    cacheService.delete("all-daos");

    return result;
  }

  async updateDao(
    id: string,
    updates: Partial<Dao>,
    skipCacheInvalidation = false,
  ): Promise<Dao> {
    const result = await this.request<Dao>(`/dao/${id}`, {
      method: "PUT",
      body: JSON.stringify(updates),
    });

    // Invalider le cache après mise à jour (sauf si explicitement désactivé pour les mises à jour fréquentes)
    if (!skipCacheInvalidation) {
      cacheService.delete("all-daos");
      cacheService.delete(`dao-${id}`);
    } else {
      // Pour les mises à jour fréquentes, on met simplement à jour le cache
      cacheService.set(`dao-${id}`, result, 3 * 60 * 1000);
    }

    return result;
  }

  async deleteDao(id: string): Promise<void> {
    const result = await this.request<void>(`/dao/${id}`, {
      method: "DELETE",
    });

    // Invalider le cache après suppression
    cacheService.delete("all-daos");
    cacheService.delete(`dao-${id}`);

    return result;
  }

  async getNextDaoNumber(): Promise<string> {
    const response = await this.request<{ nextNumber: string }>(
      "/dao/next-number",
    );
    return response.nextNumber;
  }

  async deleteLastDao(opts: {
    idempotencyKey?: string;
    password: string;
  }): Promise<{ deletedId: string; numeroListe: string }> {
    // Require server-side verification; do not allow client-side fallbacks
    return await this.request<{ deletedId: string; numeroListe: string }>(
      "/admin/delete-last-dao",
      {
        method: "DELETE",
        idempotencyKey: opts?.idempotencyKey,
        body: JSON.stringify({ password: opts.password }),
      },
    );
  }

  async getLastDao(): Promise<{
    id: string;
    numeroListe: string;
    createdAt: string;
  }> {
    // Use listing to avoid depending on admin-only route availability
    const res: any = await this.request<any>(
      "/dao?sort=createdAt&order=desc&page=1&pageSize=1",
    );
    const items: any[] = Array.isArray(res)
      ? res
      : Array.isArray(res?.items)
        ? res.items
        : [];
    if (items.length === 0) throw new Error("No DAO available");
    const d = items[0];
    return { id: d.id, numeroListe: d.numeroListe, createdAt: d.createdAt };
  }
}

export const apiService = new ApiService();
