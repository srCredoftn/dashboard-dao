import type { TaskComment } from "@shared/dao";

const API_BASE_URL = "/api/comments";

// Simple in-memory cache to reduce burst requests (per DAO)
const daoCommentsCache = new Map<string, { data: TaskComment[]; ts: number }>();
const inFlight = new Map<string, Promise<TaskComment[]>>();
const CACHE_TTL = 60 * 1000; // 1 min

class CommentApiService {
  private async request<T>(endpoint: string, options?: any): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;

    const token = localStorage.getItem("auth_token");

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (options?.headers) {
      if (options.headers instanceof Headers) {
        options.headers.forEach((value: string, key: string) => {
          headers[key] = value as string;
        });
      } else if (Array.isArray(options.headers)) {
        options.headers.forEach(([key, value]: [string, string]) => {
          headers[key] = value as string;
        });
      } else {
        Object.assign(headers, options.headers as Record<string, string>);
      }
    }

    // Support idempotency key passed via options
    if (options?.idempotencyKey) {
      headers["x-idempotency-key"] = options.idempotencyKey;
      delete options.idempotencyKey;
    }

    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    try {
      const secureFetch = (await import("@/utils/secure-fetch")).default;
      const response = await secureFetch.fetch(url, {
        ...options,
        headers,
        useNativeFetch: false,
        maxRetries: 1,
        timeout: 15000,
      } as any);

      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem("auth_token");
          localStorage.removeItem("auth_user");
          if (!window.location.pathname.includes("/login")) {
            window.location.href = "/login";
          }
          throw new Error("Session expirée. Veuillez vous reconnecter.");
        }
        const errorData = await response.json().catch(() => ({}));
        throw new Error(
          (errorData as any).error || `HTTP error! status: ${response.status}`,
        );
      }

      return (await response.json()) as T;
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);

      // Provide clearer network error messages
      if (
        msg.includes("Failed to fetch") ||
        msg.includes("Network request failed") ||
        msg.toLowerCase().includes("aborterror") ||
        msg.toLowerCase().includes("timeout")
      ) {
        console.error(`Comment API request failed for ${endpoint}:`, error);
      } else {
        console.error(`Comment API request failed for ${endpoint}:`, error);
      }

      // As a last resort, try XHR fallback to bypass potential fetch interceptors
      try {
        const data = await new Promise<T>((resolve, reject) => {
          try {
            const xhr = new XMLHttpRequest();
            xhr.open((options?.method || "GET").toUpperCase(), url, true);
            Object.entries(headers).forEach(([k, v]) =>
              xhr.setRequestHeader(k, v),
            );
            xhr.timeout = 15000;
            xhr.withCredentials = true;
            xhr.onreadystatechange = () => {
              if (xhr.readyState === 4) {
                if (xhr.status >= 200 && xhr.status < 300) {
                  try {
                    const json = JSON.parse(xhr.responseText || "null");
                    resolve(json as T);
                  } catch (e) {
                    reject(e);
                  }
                } else if (xhr.status === 401) {
                  localStorage.removeItem("auth_token");
                  localStorage.removeItem("auth_user");
                  if (!window.location.pathname.includes("/login")) {
                    window.location.href = "/login";
                  }
                  reject(
                    new Error("Session expirée. Veuillez vous reconnecter."),
                  );
                } else {
                  reject(new Error(`HTTP error! status: ${xhr.status}`));
                }
              }
            };
            xhr.onerror = () => reject(new Error("Network error"));
            xhr.ontimeout = () => reject(new Error("Request timeout"));
            xhr.send(
              options?.body
                ? typeof options.body === "string"
                  ? options.body
                  : JSON.stringify(options.body)
                : null,
            );
          } catch (e) {
            reject(e);
          }
        });

        return data;
      } catch (fallbackError) {
        console.error("XHR fallback failed:", fallbackError);
        throw error;
      }
    }
  }

  // Get all comments for a DAO (cached)
  async getDaoComments(daoId: string): Promise<TaskComment[]> {
    const cached = daoCommentsCache.get(daoId);
    if (cached && Date.now() - cached.ts < CACHE_TTL) {
      return cached.data;
    }

    // Deduplicate concurrent calls
    const existing = inFlight.get(daoId);
    if (existing) return existing;

    const promise = (async () => {
      try {
        const data = await this.request<TaskComment[]>(`/dao/${daoId}`);
        daoCommentsCache.set(daoId, { data, ts: Date.now() });
        return data;
      } catch (e) {
        // Fallback to stale cache if available
        const stale = daoCommentsCache.get(daoId);
        if (stale) return stale.data;
        throw e;
      } finally {
        inFlight.delete(daoId);
      }
    })();

    inFlight.set(daoId, promise);
    return promise;
  }

  // Get comments for a specific task (batch via DAO endpoint when possible)
  async getTaskComments(daoId: string, taskId: number): Promise<TaskComment[]> {
    const daoComments = await this.getDaoComments(daoId);
    return daoComments.filter((c) => c.taskId === taskId);
  }

  // Add a new comment (invalidate cache)
  async addComment(
    daoId: string,
    taskId: number,
    content: string,
    opts?: { idempotencyKey?: string },
  ): Promise<TaskComment> {
    const options: any = {
      method: "POST",
      body: JSON.stringify({ daoId, taskId, content }),
    };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    const result = await this.request<TaskComment>("/", options);
    daoCommentsCache.delete(daoId);
    inFlight.delete(daoId);
    return result;
  }

  // Update a comment (invalidate cache)
  async updateComment(
    commentId: string,
    content: string,
    opts?: { idempotencyKey?: string },
  ): Promise<TaskComment> {
    const options: any = { method: "PUT", body: JSON.stringify({ content }) };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    const updated = await this.request<TaskComment>(`/${commentId}`, options);
    daoCommentsCache.clear();
    inFlight.clear();
    return updated;
  }

  // Delete a comment (invalidate cache)
  async deleteComment(
    commentId: string,
    opts?: { idempotencyKey?: string },
  ): Promise<void> {
    const options: any = { method: "DELETE" };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    await this.request<void>(`/${commentId}`, options);
    daoCommentsCache.clear();
    inFlight.clear();
  }

  // Get recent comments
  async getRecentComments(limit: number = 10): Promise<TaskComment[]> {
    return this.request<TaskComment[]>(`/recent?limit=${limit}`);
  }
}

export const commentService = new CommentApiService();
