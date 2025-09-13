export function isDaoEnabled(): boolean {
  const env = import.meta.env as any;
  if (env?.VITE_DISABLE_DAO === "true") return false;
  return true;
}

export function showAdminTools(): boolean {
  const env = import.meta.env as any;
  return env?.VITE_SHOW_ADMIN_TOOLS === "true";
}
