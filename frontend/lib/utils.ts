import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Compute blinking date badge color based on progress and days until deposit date
// Rules:
// - 100% progress => gray
// - (dateDepot - today) >= 5 days => green
// - (dateDepot - today) <= 3 days => red
// - otherwise => blue
export function getBlinkingDateClasses(progress: number, dateDepot: string) {
  try {
    if (progress >= 100) return "bg-gray-400 text-white";
    const today = new Date();
    const d = new Date(dateDepot);
    // Normalize to midnight to avoid partial day issues
    const start = new Date(
      today.getFullYear(),
      today.getMonth(),
      today.getDate(),
    ).getTime();
    const target = new Date(
      d.getFullYear(),
      d.getMonth(),
      d.getDate(),
    ).getTime();
    const daysDiff = Math.ceil((target - start) / (1000 * 60 * 60 * 24));

    if (daysDiff >= 5) return "bg-emerald-600 text-white";
    if (daysDiff <= 3) return "bg-red-600 text-white";
    return "bg-blue-600 text-white";
  } catch {
    return progress >= 100
      ? "bg-gray-400 text-white"
      : "bg-blue-600 text-white";
  }
}
