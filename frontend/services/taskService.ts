import type { Dao } from "@shared/dao";

const API_BASE_URL = "/api/dao";

class TaskService {
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

    // Support idempotency key passed via options
    if (options?.idempotencyKey) {
      headers["x-idempotency-key"] = options.idempotencyKey;
      delete options.idempotencyKey;
    }

    // Add Authorization header if token exists
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    try {
      let response: Response | null = null;
      try {
        const secureFetch = (await import("@/utils/secure-fetch")).default;
        response = await secureFetch.fetch(url, {
          ...options,
          headers,
          useNativeFetch: true,
          maxRetries: 2,
          timeout: 15000,
        } as any);
      } catch (secureErr) {
        console.warn(
          "secure-fetch failed (taskService), falling back to native fetch:",
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

      console.error(`Task API request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // Add new task to DAO
  async addTask(
    daoId: string,
    taskData: {
      name: string;
      isApplicable: boolean;
      progress?: number | null;
      comment?: string;
      assignedTo?: string[];
    },
    opts?: { idempotencyKey?: string },
  ): Promise<Dao> {
    const options: any = { method: "POST", body: JSON.stringify(taskData) };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    return this.request<Dao>(`/${daoId}/tasks`, options);
  }

  // Update task name
  async updateTaskName(
    daoId: string,
    taskId: number,
    name: string,
    opts?: { idempotencyKey?: string },
  ): Promise<Dao> {
    const options: any = { method: "PUT", body: JSON.stringify({ name }) };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    return this.request<Dao>(`/${daoId}/tasks/${taskId}/name`, options);
  }

  // Delete task
  async deleteTask(
    daoId: string,
    taskId: number,
    opts?: { idempotencyKey?: string },
  ): Promise<{ dao: Dao; message: string }> {
    const options: any = { method: "DELETE" };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    return this.request<{ dao: Dao; message: string }>(
      `/${daoId}/tasks/${taskId}`,
      options,
    );
  }

  // Update task progress (using existing DAO service endpoint)
  async updateTask(
    daoId: string,
    taskId: number,
    updates: {
      progress?: number;
      comment?: string;
      isApplicable?: boolean;
      assignedTo?: string[];
    },
    opts?: { idempotencyKey?: string },
  ): Promise<Dao> {
    const options: any = { method: "PUT", body: JSON.stringify(updates) };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    return this.request<Dao>(`/${daoId}/tasks/${taskId}`, options);
  }

  // Reorder tasks
  async reorderTasks(
    daoId: string,
    taskIds: number[],
    opts?: { idempotencyKey?: string },
  ): Promise<Dao> {
    const options: any = { method: "PUT", body: JSON.stringify({ taskIds }) };
    if (opts?.idempotencyKey) options.idempotencyKey = opts.idempotencyKey;
    return this.request<Dao>(`/${daoId}/tasks/reorder`, options);
  }
}

export const taskService = new TaskService();
