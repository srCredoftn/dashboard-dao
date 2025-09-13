/**
 * Development logger utility
 * Only logs in development environment
 */

const isDevelopment = import.meta.env.DEV;

export const devLog = {
  log: (...args: any[]) => {
    if (isDevelopment) {
      console.log(...args);
    }
  },

  error: (...args: any[]) => {
    if (isDevelopment) {
      console.error(...args);
    }
  },

  warn: (...args: any[]) => {
    if (isDevelopment) {
      console.warn(...args);
    }
  },

  info: (...args: any[]) => {
    if (isDevelopment) {
      console.info(...args);
    }
  },

  clear: () => {
    if (isDevelopment) {
      console.clear();
    }
  },
};
