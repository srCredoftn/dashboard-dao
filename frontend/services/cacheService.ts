/**
 * Simple cache service pour optimiser les performances
 * En production, utiliser Redis ou une solution similaire
 */

interface CacheItem<T> {
  data: T;
  timestamp: number;
  ttl: number; // Time to live en millisecondes
}

class CacheService {
  private cache: Map<string, CacheItem<any>> = new Map();
  private readonly DEFAULT_TTL = 5 * 60 * 1000; // 5 minutes

  /**
   * Récupère une valeur du cache
   */
  get<T>(key: string): T | null {
    const item = this.cache.get(key);

    if (!item) {
      return null;
    }

    // Vérifier si l'item a expiré
    if (Date.now() - item.timestamp > item.ttl) {
      this.cache.delete(key);
      return null;
    }

    return item.data as T;
  }

  /**
   * Stocke une valeur dans le cache
   */
  set<T>(key: string, data: T, ttl?: number): void {
    const item: CacheItem<T> = {
      data,
      timestamp: Date.now(),
      ttl: ttl || this.DEFAULT_TTL,
    };

    this.cache.set(key, item);
  }

  /**
   * Supprime une clé du cache
   */
  delete(key: string): void {
    this.cache.delete(key);
  }

  /**
   * Vide le cache
   */
  clear(): void {
    const entriesCount = this.cache.size;
    console.log(`🧹 Clearing all cache (${entriesCount} entries)`);
    this.cache.clear();
    console.log(`✅ Cache cleared successfully`);
  }

  /**
   * Force un nettoyage complet avec suppression des données persistantes
   */
  forceFullClear(): void {
    console.log("🧹 Force clearing all caches and storage...");

    // Clear in-memory cache
    this.clear();

    // Clear localStorage items related to cache or DAOs
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (
        key &&
        (key.includes("cache") || key.includes("dao") || key.includes("DAO"))
      ) {
        keysToRemove.push(key);
      }
    }

    keysToRemove.forEach((key) => {
      localStorage.removeItem(key);
      console.log(`🗑️ Removed localStorage key: ${key}`);
    });

    console.log(
      `✅ Force clear completed - removed ${keysToRemove.length} localStorage items`,
    );
  }

  /**
   * Récupère une valeur ou exécute une fonction si elle n'existe pas
   */
  async getOrSet<T>(
    key: string,
    fetchFunction: () => Promise<T>,
    ttl?: number,
  ): Promise<T> {
    const cached = this.get<T>(key);

    if (cached !== null) {
      console.log(`🎯 Cache hit for ${key}`);
      return cached;
    }

    console.log(`⚡ Cache miss for ${key}, fetching...`);
    const data = await fetchFunction();
    this.set(key, data, ttl);
    return data;
  }

  /**
   * Invalide les clés qui matchent un pattern
   */
  invalidatePattern(pattern: string): void {
    const regex = new RegExp(pattern);
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Nettoie les entrées expirées
   */
  cleanup(): void {
    const now = Date.now();
    for (const [key, item] of this.cache.entries()) {
      if (now - item.timestamp > item.ttl) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Retourne les statistiques du cache
   */
  getStats(): {
    size: number;
    keys: string[];
  } {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys()),
    };
  }
}

export const cacheService = new CacheService();

// Nettoyer le cache toutes les 10 minutes
setInterval(
  () => {
    cacheService.cleanup();
    console.log("🧹 Cache cleanup completed");
  },
  10 * 60 * 1000,
);
