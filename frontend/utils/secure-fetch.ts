// Utilitaire pour créer un fetch sécurisé qui évite les interceptions de services tiers

// Utilitaire: créer un fetch natif frais via un iframe (évite les références périmées)
function createFreshNativeFetch(): typeof fetch {
  // Simpler and more reliable: prefer the browser's fetch bound to window.
  // The iframe trick caused cross-origin/contentWindow issues in some environments.
  if (typeof window === "undefined" || !window.fetch) {
    return (globalThis.fetch || fetch).bind(globalThis as any);
  }
  try {
    return window.fetch.bind(window);
  } catch (error) {
    console.warn("createFreshNativeFetch fallback to global fetch:", error);
    return (globalThis.fetch || fetch).bind(globalThis as any);
  }
}

// Référence initiale (peut devenir invalide si le realm est détruit)
const originalFetch = createFreshNativeFetch();

// Interface pour les options étendues
interface SecureFetchOptions extends RequestInit {
  useNativeFetch?: boolean;
  maxRetries?: number;
  retryDelay?: number;
  timeout?: number;
}

// Classe pour gérer les appels fetch sécurisés
export class SecureFetch {
  private static instance: SecureFetch;

  static getInstance(): SecureFetch {
    if (!SecureFetch.instance) {
      SecureFetch.instance = new SecureFetch();
    }
    return SecureFetch.instance;
  }

  // Détecter si fetch a été modifié par un service tiers
  private isNativeFetch(): boolean {
    if (typeof window === "undefined") return true;
    const fetchString = window.fetch.toString();
    const interceptorSignatures = [
      "fullstory",
      "fs.js",
      "sentry",
      "datadog",
      "bugsnag",
      "messageHandler",
    ];
    return !interceptorSignatures.some((s) =>
      fetchString.toLowerCase().includes(s.toLowerCase()),
    );
  }

  // Obtenir un fetch natif frais à la demande
  private getFreshNativeFetch(): typeof fetch {
    return createFreshNativeFetch();
  }

  // Créer un timeout pour les requêtes
  private createTimeoutSignal(timeoutMs: number): AbortSignal {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), timeoutMs);
    return controller.signal;
  }

  // Fallback XHR when fetch is intercepted by third-parties
  private xhrFallback(
    url: string,
    opts: RequestInit & { timeout?: number },
  ): Promise<Response> {
    return new Promise((resolve, reject) => {
      try {
        const xhr = new XMLHttpRequest();
        xhr.open((opts.method || "GET").toUpperCase(), url, true);
        if (opts.timeout && typeof xhr.timeout === "number") {
          xhr.timeout = opts.timeout;
        }
        const headers = opts.headers as Record<string, string> | undefined;
        if (headers) {
          for (const [k, v] of Object.entries(headers)) {
            try {
              xhr.setRequestHeader(k, String(v));
            } catch {}
          }
        }
        xhr.withCredentials = opts.credentials === "include";
        xhr.onreadystatechange = () => {
          if (xhr.readyState === 4) {
            const status = xhr.status || 0;
            const statusText = xhr.statusText || "";
            const body = xhr.responseText || "";
            const response: any = {
              ok: status >= 200 && status < 300,
              status,
              statusText,
              headers: new Headers(),
              url,
              json: async () => {
                try {
                  return body ? JSON.parse(body) : null;
                } catch (e) {
                  throw new Error("Invalid JSON in XHR response");
                }
              },
              text: async () => body,
            };
            resolve(response as Response);
          }
        };
        xhr.onerror = () => reject(new Error("XHR network error"));
        xhr.ontimeout = () => reject(new Error("XHR timeout"));
        if (opts.body instanceof FormData) {
          xhr.send(opts.body);
        } else if (typeof opts.body === "string") {
          xhr.send(opts.body);
        } else if (opts.body) {
          try {
            xhr.send(JSON.stringify(opts.body as any));
          } catch {
            xhr.send(String(opts.body));
          }
        } else {
          xhr.send();
        }
      } catch (e) {
        reject(e);
      }
    });
  }

  // Méthode principale de fetch sécurisé
  async fetch(
    url: string | URL,
    options: SecureFetchOptions = {},
  ): Promise<Response> {
    const {
      useNativeFetch = false,
      maxRetries = 2,
      retryDelay = 1000,
      timeout = 10000,
      ...fetchOptions
    } = options;

    let lastError: Error | null = null;
    // Flags
    let forceWindowFetch = false; // après realm shutdown
    let forceFreshNative = useNativeFetch; // si on veut éviter toute interception

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        console.log(
          `🌐 Secure fetch attempt ${attempt + 1}/${maxRetries + 1}: ${url}`,
        );

        // Choisir la fonction fetch �� utiliser avec validation
        let fetchFunction: typeof fetch;

        let usedFreshNative = false;
        try {
          if (forceFreshNative && !forceWindowFetch) {
            // Utiliser un fetch natif fraîchement récupéré à chaque tentative
            fetchFunction = this.getFreshNativeFetch();
            usedFreshNative = true;
          } else if (!this.isNativeFetch() && !forceWindowFetch) {
            // Si window.fetch est intercepté, utiliser natif frais
            fetchFunction = this.getFreshNativeFetch();
            usedFreshNative = true;
          } else if (!forceWindowFetch) {
            // Sinon tenter la r��f. initiale
            fetchFunction =
              typeof originalFetch === "function"
                ? (originalFetch as unknown as typeof fetch)
                : window.fetch.bind(window);
          } else {
            // Forcer window.fetch
            fetchFunction = window.fetch.bind(window);
          }
        } catch (scopeError) {
          console.warn(
            "Fetch function selection failed, using window.fetch:",
            scopeError,
          );
          fetchFunction = window.fetch.bind(window);
        }

        // Ajouter un timeout si pas déjà spécifié
        const requestOptions: any = { ...fetchOptions };
        // Do not force credentials by default; respect caller
        // Ensure there's a timeout signal if none provided (and not using fresh native fetch)
        if (!requestOptions.signal && timeout > 0 && !usedFreshNative) {
          requestOptions.signal = this.createTimeoutSignal(timeout);
        }
        // NOTE: keep any provided signal even when using fresh native fetch so tests and callers receive it

        // Toujours utiliser une URL absolue pour éviter about:blank avec le fetch d'iframe
        let finalUrl: string | URL = url;
        if (typeof window !== "undefined") {
          if (typeof url === "string") {
            const hasProtocol = /^https?:\/\//i.test(url);
            if (!hasProtocol) {
              finalUrl = url.startsWith("/")
                ? `${window.location.origin}${url}`
                : new URL(url, window.location.href).toString();
            }
          } else if (url instanceof URL) {
            // OK
          }
        }

        const response = await fetchFunction(finalUrl as any, requestOptions);

        // Log du succès
        console.log(`✅ Secure fetch successful: ${url} (${response.status})`);
        return response;
      } catch (error) {
        lastError = error as Error;
        const errorMessage = lastError.message;

        console.warn(
          `⚠️ Secure fetch attempt ${attempt + 1} failed:`,
          errorMessage,
        );

        // Vérifier si c'est une erreur de portée globale
        const isGlobalScopeError = errorMessage.includes(
          "global scope is shutting down",
        );

        // Détecter une interception FullStory/Sentry via trace
        const looksIntercepted =
          errorMessage.toLowerCase().includes("messagehandler") ||
          errorMessage.toLowerCase().includes("fs.js") ||
          errorMessage.toLowerCase().includes("fullstory");

        // Vérifier si c'est une erreur réseau temporaire
        const isRetriableError =
          errorMessage.includes("Failed to fetch") ||
          errorMessage.includes("network") ||
          errorMessage.includes("timeout") ||
          errorMessage.includes("AbortError") ||
          isGlobalScopeError ||
          looksIntercepted;

        // Realm shutdown: forcer window.fetch
        if (isGlobalScopeError && attempt < maxRetries) {
          console.log(
            "🔄 Global scope error detected, forcing window.fetch for next attempt",
          );
          forceWindowFetch = true;
          continue; // retry immédiat
        }

        // Si on détecte une interception ou un failed-to-fetch, tenter XHR immédiatement
        if (looksIntercepted || errorMessage.includes("Failed to fetch")) {
          try {
            const absoluteUrl =
              typeof url === "string"
                ? /^https?:\/\//i.test(url)
                  ? url
                  : typeof window !== "undefined"
                    ? url.startsWith("/")
                      ? `${window.location.origin}${url}`
                      : new URL(url, window.location.href).toString()
                    : url
                : (url as URL).toString();
            const xhrResponse = await this.xhrFallback(absoluteUrl, {
              ...(options as any),
              timeout: (options as any)?.timeout ?? 10000,
            });
            console.log(
              `✅ XHR fallback successful: ${absoluteUrl} (${xhrResponse.status})`,
            );
            return xhrResponse;
          } catch (xhrErr) {
            console.warn(
              "XHR fallback during retry failed:",
              (xhrErr as Error).message,
            );
          }
        }

        // Interception détectée: forcer un fetch natif frais sur la prochaine tentative
        if (looksIntercepted && attempt < maxRetries) {
          console.log(
            "🛡️ Interception detected, switching to fresh native fetch",
          );
          forceFreshNative = true;
          forceWindowFetch = false;
          continue; // retry immédiat
        }

        // Ne pas retry sur la dernière tentative ou si l'erreur n'est pas retriable
        if (attempt === maxRetries || !isRetriableError) {
          break;
        }

        // Délai avant le retry (délai exponentiel)
        const delay = retryDelay * Math.pow(2, attempt);
        console.log(`⏳ Retrying in ${delay}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    // Si toutes les tentatives ont échoué
    console.error(`❌ All secure fetch attempts failed for: ${url}`);

    // Dernière tentative: XHR direct pour contourner les interceptions (même origine requise)
    try {
      const absoluteUrl =
        typeof url === "string"
          ? /^https?:\/\//i.test(url)
            ? url
            : typeof window !== "undefined"
              ? url.startsWith("/")
                ? `${window.location.origin}${url}`
                : new URL(url, window.location.href).toString()
              : url
          : (url as URL).toString();
      const xhrResponse = await this.xhrFallback(absoluteUrl, {
        ...(options as any),
        timeout: (options as any)?.timeout ?? 10000,
      });
      return xhrResponse;
    } catch (xhrErr) {
      console.warn("XHR fallback failed:", (xhrErr as Error).message);
    }

    // Améliorer le message d'erreur
    if (lastError) {
      const enhancedError = new Error(
        `Network request failed after ${maxRetries + 1} attempts: ${lastError.message}`,
      );
      enhancedError.name = "SecureFetchError";
      enhancedError.stack = lastError.stack;
      throw enhancedError;
    }

    throw new Error("Network request failed: Unknown error");
  }

  // Méthodes utilitaires pour les types de requêtes courants
  async get(
    url: string | URL,
    options: SecureFetchOptions = {},
  ): Promise<Response> {
    return this.fetch(url, { ...options, method: "GET" });
  }

  async post(
    url: string | URL,
    data?: any,
    options: SecureFetchOptions = {},
  ): Promise<Response> {
    const postOptions: SecureFetchOptions = {
      ...options,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    };

    if (data !== undefined) {
      postOptions.body = typeof data === "string" ? data : JSON.stringify(data);
    }

    return this.fetch(url, postOptions);
  }

  async put(
    url: string | URL,
    data?: any,
    options: SecureFetchOptions = {},
  ): Promise<Response> {
    const putOptions: SecureFetchOptions = {
      ...options,
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    };

    if (data !== undefined) {
      putOptions.body = typeof data === "string" ? data : JSON.stringify(data);
    }

    return this.fetch(url, putOptions);
  }

  async delete(
    url: string | URL,
    options: SecureFetchOptions = {},
  ): Promise<Response> {
    return this.fetch(url, { ...options, method: "DELETE" });
  }

  // Diagnostic pour vérifier l'état du fetch
  diagnose(): {
    isNativeFetch: boolean;
    fetchSource: string;
    recommendations: string[];
  } {
    const isNative = this.isNativeFetch();
    const fetchString =
      typeof window !== "undefined"
        ? window.fetch.toString()
        : "N/A (server-side)";

    const recommendations: string[] = [];

    if (!isNative) {
      recommendations.push(
        "Fetch has been intercepted by a third-party service",
      );
      recommendations.push(
        "Consider using useNativeFetch: true for critical requests",
      );
      recommendations.push(
        "Check for services like FullStory, Sentry, or DataDog",
      );
    }

    return {
      isNativeFetch: isNative,
      fetchSource:
        fetchString.substring(0, 200) + (fetchString.length > 200 ? "..." : ""),
      recommendations,
    };
  }
}

// Instance singleton pour l'exportation
export const secureFetch = SecureFetch.getInstance();

// Export par défaut pour une utilisation simple
export default secureFetch;

// Fonction utilitaire pour remplacer window.fetch dans les cas critiques
export function createFetchPolyfill(): typeof fetch {
  return secureFetch.fetch.bind(secureFetch) as unknown as typeof fetch;
}

// Hook pour diagnostiquer les problèmes de fetch
export function useFetchDiagnostics() {
  return secureFetch.diagnose();
}
