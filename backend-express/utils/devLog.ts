/**
 * Utility for development-only logging
 * Only logs in development/test environments
 */

const isDevelopment =
  process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test";

export const devLog = {
  info: (...args: any[]) => {
    if (isDevelopment) {
      console.log(...args);
    }
  },

  warn: (...args: any[]) => {
    if (isDevelopment) {
      console.warn(...args);
    }
  },

  error: (...args: any[]) => {
    if (isDevelopment) {
      console.error(...args);
    }
  },

  debug: (...args: any[]) => {
    if (isDevelopment) {
      console.debug(...args);
    }
  },
};

// Specific logging functions for common patterns
export const authLog = {
  login: (email: string, success: boolean = true) => {
    if (isDevelopment) {
      const status = success ? "✅" : "❌";
      console.log(
        `${status} Login ${success ? "successful" : "failed"} for: ${email}`,
      );
    }
  },

  logout: (email: string) => {
    if (isDevelopment) {
      console.log(`👋 User logged out: ${email}`);
    }
  },

  tokenVerification: (email: string, success: boolean = true) => {
    if (isDevelopment) {
      const status = success ? "✅" : "❌";
      console.log(
        `${status} Token verification ${success ? "successful" : "failed"} for: ${email}`,
      );
    }
  },
};

export const apiLog = {
  request: (method: string, path: string, userId?: string) => {
    if (isDevelopment) {
      const user = userId ? ` (User: ${userId})` : "";
      console.log(`📡 ${method} ${path}${user}`);
    }
  },

  response: (
    method: string,
    path: string,
    status: number,
    duration?: number,
  ) => {
    if (isDevelopment) {
      const time = duration ? ` (${duration}ms)` : "";
      const statusEmoji = status < 300 ? "✅" : status < 400 ? "⚠️" : "❌";
      console.log(`${statusEmoji} ${method} ${path} - ${status}${time}`);
    }
  },
};
