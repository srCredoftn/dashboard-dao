// Avatar utilities: support locally stored profile photos with graceful fallback to DiceBear initials.

export function getStoredAvatar(userKey?: string): string | null {
  if (!userKey) return null;
  try {
    const byId = localStorage.getItem(`avatar_user_${userKey}`);
    if (byId) return byId;
  } catch {}
  return null;
}

export function setStoredAvatar(userKey: string, dataUrl: string) {
  try {
    localStorage.setItem(`avatar_user_${userKey}`, dataUrl);
    // Notify listeners within the same tab to refresh avatars immediately
    try {
      window.dispatchEvent(
        new CustomEvent("avatar-updated", { detail: { userKey } }),
      );
    } catch {}
  } catch {}
}

export function removeStoredAvatar(userKey: string) {
  try {
    localStorage.removeItem(`avatar_user_${userKey}`);
    try {
      window.dispatchEvent(
        new CustomEvent("avatar-updated", { detail: { userKey } }),
      );
    } catch {}
  } catch {}
}

// Generate a deterministic avatar URL for any user based on a stable seed (id, email, or name)
// It first checks for a stored avatar, then falls back to DiceBear initials
export function getAvatarUrl(
  userKeyOrSeed?: string,
  displayName?: string,
): string {
  const stored = getStoredAvatar(userKeyOrSeed);
  if (stored) return stored;
  const seed = (displayName || userKeyOrSeed || "user").toString();
  const params = new URLSearchParams({
    seed,
    backgroundType: "gradientLinear",
    fontSize: "40",
    radius: "50",
  });
  return `https://api.dicebear.com/7.x/initials/svg?${params.toString()}`;
}

export default getAvatarUrl;
