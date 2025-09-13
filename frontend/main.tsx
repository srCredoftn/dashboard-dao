import { createRoot } from "react-dom/client";
import App from "./App";

// Vérifier que l'élément root existe
const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Root element not found");
}

// Clean first-run local storage to avoid stale tokens/caches
try {
  const FIRST_RUN_KEY = "app_initialized_v1";
  if (!localStorage.getItem(FIRST_RUN_KEY)) {
    // Clear auth
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_user");

    // Clear notifications and misc cached items
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (
        key &&
        (key.includes("notification") ||
          key.includes("cache") ||
          key.includes("dao") ||
          key.includes("DAO") ||
          key.startsWith("avatar_user_"))
      ) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach((k) => localStorage.removeItem(k));

    localStorage.setItem(FIRST_RUN_KEY, new Date().toISOString());
    console.log("✨ First run: storage cleaned");
  }
} catch (e) {
  console.warn("First-run cleanup skipped:", e);
}

// Créer et gérer le root de manière sécurisée
let root: ReturnType<typeof createRoot> | null = null;

function renderApp() {
  if (!root) {
    root = createRoot(rootElement as HTMLElement);
  }
  root.render(<App />);
}

// Initialisation avec vérification du bootId serveur pour invalider les données locales
(async function init() {
  const BOOT_KEY = "boot_id_v1";
  try {
    const secureFetch = (await import("@/utils/secure-fetch")).default;
    const res = await secureFetch.fetch("/api/boot", {
      headers: { Accept: "application/json" },
      useNativeFetch: false,
      maxRetries: 1,
      timeout: 5000,
    } as any);
    if (res.ok) {
      const data: { bootId?: string } = await res.json();
      const serverBootId = String(data.bootId || "dev");
      const storedBootId = localStorage.getItem(BOOT_KEY);

      if (!storedBootId || storedBootId !== serverBootId) {
        // Nouveau déploiement/démarrage détecté -> nettoyer les données sensibles locales
        localStorage.removeItem("auth_token");
        localStorage.removeItem("auth_user");
        localStorage.removeItem("notifications");
        localStorage.removeItem("notification_settings");

        // Nettoyer aussi les clés associées aux caches/dao
        const keysToRemove: string[] = [];
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (
            key &&
            (key.includes("notification") ||
              key.includes("cache") ||
              key.includes("dao") ||
              key.includes("DAO") ||
              key.startsWith("avatar_user_"))
          ) {
            keysToRemove.push(key);
          }
        }
        keysToRemove.forEach((k) => localStorage.removeItem(k));

        // Sauvegarder le nouveau bootId
        localStorage.setItem(BOOT_KEY, serverBootId);
        console.log(
          "🔐 Nouveau bootId détecté, nettoyage du stockage local effectué",
        );
      }
    }
  } catch (e) {
    console.warn("Boot check failed, proceeding without cleanup:", e);
  }

  // Rendu initial
  renderApp();
})();

// Hot Module Replacement (HMR) pour le développement
if (import.meta.hot) {
  import.meta.hot.accept("./App", () => {
    console.log("🔄 HMR: App component updated");
    renderApp();
  });

  import.meta.hot.accept("./components/AppContent", () => {
    console.log("🔄 HMR: AppContent component updated");
    renderApp();
  });
}
