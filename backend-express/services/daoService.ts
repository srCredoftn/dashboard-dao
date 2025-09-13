import DaoModel from "../models/Dao";
import { connectToDatabase } from "../config/database";
import { daoStorage } from "../data/daoStorage";
import type { Dao } from "@shared/dao";

let useInMemory = false;
let connectionAttempted = false;
// Monotonic per-year sequence tracker to avoid reusing numbers after deletions
const lastIssuedSeqByYear: Record<string, number> = {};

async function tryConnect(): Promise<boolean> {
  if (connectionAttempted) return !useInMemory;
  connectionAttempted = true;
  try {
    await connectToDatabase();
    useInMemory = false;
    return true;
  } catch (e) {
    console.warn("⚠️ MongoDB not available, falling back to in-memory storage");
    useInMemory = true;
    return false;
  }
}

export class DaoService {
  private static async ensureConnection() {
    await tryConnect();
  }

  // Get all DAOs
  static async getAllDaos(): Promise<Dao[]> {
    await this.ensureConnection();
    if (useInMemory) {
      return daoStorage
        .getAll()
        .slice()
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    }
    const daos = await DaoModel.find().sort({ updatedAt: -1 });
    return daos.map((dao) => dao.toObject());
  }

  // Get last created DAO
  static async getLastCreatedDao(): Promise<Dao | null> {
    await this.ensureConnection();
    if (useInMemory) {
      const list = daoStorage.getAll().slice();
      if (list.length === 0) return null;
      list.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return list[0];
    }
    const doc = await DaoModel.findOne().sort({ createdAt: -1 });
    return doc ? (doc.toObject() as Dao) : null;
  }

  // Delete last created DAO and return it
  static async deleteLastCreatedDao(): Promise<Dao | null> {
    await this.ensureConnection();
    const last = await this.getLastCreatedDao();
    if (!last) return null;
    const ok = await this.deleteDao(last.id);
    return ok ? last : null;
  }

  /**
   * Get DAOs with optional server-side filtering, sorting and pagination.
   * Options:
   * - search: text search over numeroListe, objetDossier, reference
   * - autorite: filter by autoriteContractante exact match
   * - sort: field to sort by (default: updatedAt)
   * - order: asc|desc
   * - page, pageSize: pagination (1-based page)
   */
  static async getDaos(opts: {
    search?: string;
    autorite?: string;
    dateFrom?: string; // inclusive yyyy-mm-dd or ISO
    dateTo?: string; // inclusive
    sort?: string;
    order?: "asc" | "desc";
    page?: number;
    pageSize?: number;
  }): Promise<{ items: Dao[]; total: number }> {
    await this.ensureConnection();
    const {
      search,
      autorite,
      dateFrom,
      dateTo,
      sort = "updatedAt",
      order = "desc",
      page = 1,
      pageSize = 20,
    } = opts || {};

    if (useInMemory) {
      let list = daoStorage.getAll().slice();

      if (search && search.trim()) {
        const q = search.toLowerCase().trim();
        list = list.filter((d) => {
          return (
            (d.numeroListe && d.numeroListe.toLowerCase().includes(q)) ||
            (d.objetDossier && d.objetDossier.toLowerCase().includes(q)) ||
            (d.reference && d.reference.toLowerCase().includes(q)) ||
            (d.autoriteContractante &&
              d.autoriteContractante.toLowerCase().includes(q))
          );
        });
      }

      if (autorite && autorite.trim()) {
        const a = autorite.trim();
        list = list.filter((d) => d.autoriteContractante === a);
      }

      // Date range filter on dateDepot (inclusive)
      if (dateFrom || dateTo) {
        let fromTs = dateFrom ? Date.parse(dateFrom) : -Infinity;
        let toTs = dateTo ? Date.parse(dateTo) : Infinity;
        if (isNaN(fromTs)) fromTs = -Infinity;
        if (isNaN(toTs)) toTs = Infinity;
        list = list.filter((d) => {
          const t = d.dateDepot ? Date.parse(d.dateDepot) : NaN;
          if (isNaN(t)) return false;
          return t >= fromTs && t <= toTs;
        });
      }

      const direction = order === "asc" ? 1 : -1;
      list.sort((a: any, b: any) => {
        const av = (a as any)[sort] || "";
        const bv = (b as any)[sort] || "";
        if (typeof av === "string" && typeof bv === "string")
          return direction * av.localeCompare(bv);
        if (av < bv) return -1 * direction;
        if (av > bv) return 1 * direction;
        return 0;
      });

      const total = list.length;
      const start = (Math.max(1, page) - 1) * pageSize;
      const items = list.slice(start, start + pageSize);
      return { items, total };
    }

    // Build mongoose query
    const query: any = {};
    if (search && search.trim()) {
      const q = search.trim();
      const regex = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      query.$or = [
        { numeroListe: regex },
        { objetDossier: regex },
        { reference: regex },
        { autoriteContractante: regex },
      ];
    }
    if (autorite && autorite.trim()) {
      query.autoriteContractante = autorite.trim();
    }

    // Date range filter for dateDepot (inclusive) - expect ISO or yyyy-mm-dd
    if (dateFrom || dateTo) {
      const range: any = {};
      if (dateFrom) {
        const from = new Date(dateFrom);
        if (!isNaN(from.getTime())) range.$gte = from.toISOString();
      }
      if (dateTo) {
        const to = new Date(dateTo);
        if (!isNaN(to.getTime())) {
          // include entire day by setting to end of day
          to.setHours(23, 59, 59, 999);
          range.$lte = to.toISOString();
        }
      }
      if (Object.keys(range).length > 0) {
        query.dateDepot = range;
      }
    }

    const total = await DaoModel.countDocuments(query);
    const sortObj: any = {};
    sortObj[sort] = order === "asc" ? 1 : -1;

    const skip = Math.max(0, (Math.max(1, page) - 1) * pageSize);
    const docs = await DaoModel.find(query)
      .sort(sortObj)
      .skip(skip)
      .limit(pageSize);
    return { items: docs.map((d: any) => d.toObject()), total };
  }

  // Get DAO by ID
  static async getDaoById(id: string): Promise<Dao | null> {
    await this.ensureConnection();
    console.log(`🔎 DaoService: Looking for DAO with ID=${id}`);
    if (useInMemory) {
      const result = daoStorage.findById(id) || null;
      if (result) {
        console.log(`✅ DaoService: Found DAO ${id} -> ${result.numeroListe}`);
      } else {
        console.log(`❌ DaoService: DAO ${id} not found in storage`);
      }
      return result;
    }
    const dao = await DaoModel.findOne({ id });
    return dao ? dao.toObject() : null;
  }

  // Generate next DAO number (mutating: advances baseline for creations)
  static async generateNextDaoNumber(): Promise<string> {
    await this.ensureConnection();
    const year = new Date().getFullYear();

    const computeMaxSeq = (list: { numeroListe: string }[]) => {
      const nums = list
        .map((d) => d.numeroListe.match(/DAO-(\d{4})-(\d{3})/))
        .filter((m): m is RegExpMatchArray => !!m && m[1] === String(year))
        .map((m) => parseInt(m[2], 10))
        .filter((n) => !isNaN(n));
      return nums.length > 0 ? Math.max(...nums) : 0;
    };

    if (useInMemory) {
      const all = daoStorage.getAll();
      const maxSeq = computeMaxSeq(all);
      const baseline = Math.max(lastIssuedSeqByYear[String(year)] || 0, maxSeq);
      const nextSeq = baseline + 1;
      lastIssuedSeqByYear[String(year)] = nextSeq; // advance baseline only on generate (creation)
      return `DAO-${year}-${nextSeq.toString().padStart(3, "0")}`;
    }

    const existingDaos = await DaoModel.find({
      numeroListe: { $regex: `^DAO-${year}-` },
    });
    const maxSeq = computeMaxSeq(existingDaos as any);
    const baseline = Math.max(lastIssuedSeqByYear[String(year)] || 0, maxSeq);
    const nextSeq = baseline + 1;
    lastIssuedSeqByYear[String(year)] = nextSeq; // advance baseline only on generate (creation)
    return `DAO-${year}-${nextSeq.toString().padStart(3, "0")}`;
  }

  // Peek next DAO number (non-mutating; safe for UI checks)
  static async peekNextDaoNumber(): Promise<string> {
    await this.ensureConnection();
    const year = new Date().getFullYear();

    const computeMaxSeq = (list: { numeroListe: string }[]) => {
      const nums = list
        .map((d) => d.numeroListe.match(/DAO-(\d{4})-(\d{3})/))
        .filter((m): m is RegExpMatchArray => !!m && m[1] === String(year))
        .map((m) => parseInt(m[2], 10))
        .filter((n) => !isNaN(n));
      return nums.length > 0 ? Math.max(...nums) : 0;
    };

    if (useInMemory) {
      const all = daoStorage.getAll();
      const maxSeq = computeMaxSeq(all);
      const baseline = Math.max(lastIssuedSeqByYear[String(year)] || 0, maxSeq);
      const nextSeq = baseline + 1;
      return `DAO-${year}-${nextSeq.toString().padStart(3, "0")}`;
    }

    const existingDaos = await DaoModel.find({
      numeroListe: { $regex: `^DAO-${year}-` },
    });
    const maxSeq = computeMaxSeq(existingDaos as any);
    const baseline = Math.max(lastIssuedSeqByYear[String(year)] || 0, maxSeq);
    const nextSeq = baseline + 1;
    return `DAO-${year}-${nextSeq.toString().padStart(3, "0")}`;
  }

  // Create new DAO
  static async createDao(
    daoData: Omit<Dao, "id" | "createdAt" | "updatedAt">,
  ): Promise<Dao> {
    await this.ensureConnection();
    const id = Date.now().toString();
    const now = new Date().toISOString();

    // Always generate server-side to avoid duplicates, ignore client-provided numeroListe
    let numeroListe = await this.generateNextDaoNumber();

    if (useInMemory) {
      // Ensure uniqueness in memory, retry if collision (extremely rare)
      const existingNumbers = new Set(
        daoStorage.getAll().map((d) => d.numeroListe),
      );
      while (existingNumbers.has(numeroListe)) {
        numeroListe = await this.generateNextDaoNumber();
      }
      const newDao: Dao = {
        ...daoData,
        numeroListe,
        id,
        createdAt: now,
        updatedAt: now,
      } as Dao;
      daoStorage.add(newDao);
      return newDao;
    }

    // DB path: handle possible duplicate key race with small retry loop
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const dao = new DaoModel({
          ...daoData,
          numeroListe,
          id,
          createdAt: now,
          updatedAt: now,
        });
        const savedDao = await dao.save();
        return savedDao.toObject();
      } catch (e: any) {
        const msg = String((e && e.message) || e);
        if (msg.includes("E11000") || msg.toLowerCase().includes("duplicate")) {
          // Generate a new number and retry
          numeroListe = await this.generateNextDaoNumber();
          continue;
        }
        throw e;
      }
    }
    // Final attempt failed due to persistent duplicates
    throw new Error(
      "Failed to create DAO due to concurrent numbering conflicts",
    );
  }

  // Update DAO
  static async updateDao(
    id: string,
    updates: Partial<Dao>,
  ): Promise<Dao | null> {
    await this.ensureConnection();
    if (useInMemory) {
      const index = daoStorage.findIndexById(id);
      if (index === -1) return null;
      const existing = daoStorage.findById(id)!;
      const updated: Dao = {
        ...existing,
        ...updates,
        updatedAt: new Date().toISOString(),
      } as Dao;
      daoStorage.updateAtIndex(index, updated);
      return updated;
    }
    const updatedDao = await DaoModel.findOneAndUpdate(
      { id },
      { ...updates, updatedAt: new Date().toISOString() },
      { new: true },
    );
    return updatedDao ? updatedDao.toObject() : null;
  }

  // Delete DAO
  static async deleteDao(id: string): Promise<boolean> {
    await this.ensureConnection();
    if (useInMemory) {
      // Find DAO to adjust sequence if needed
      const existing = daoStorage.findById(id);
      const ok = daoStorage.deleteById(id);
      if (ok && existing?.numeroListe) {
        const m = existing.numeroListe.match(/DAO-(\d{4})-(\d{3})/);
        if (m) {
          const year = m[1];
          const maxSeq = daoStorage
            .getAll()
            .filter((d) => d.numeroListe.startsWith(`DAO-${year}-`))
            .map((d) =>
              parseInt(
                d.numeroListe.match(/DAO-\d{4}-(\d{3})/)?.[1] || "0",
                10,
              ),
            )
            .filter((n) => !isNaN(n))
            .reduce((a, b) => Math.max(a, b), 0);
          lastIssuedSeqByYear[year] = maxSeq;
        }
      }
      return ok;
    }
    const doc = await DaoModel.findOne({ id });
    const result = await DaoModel.deleteOne({ id });
    if (result.deletedCount && doc?.numeroListe) {
      const m = doc.numeroListe.match(/DAO-(\d{4})-(\d{3})/);
      if (m) {
        const year = m[1];
        const remaining = await DaoModel.find({
          numeroListe: { $regex: `^DAO-${year}-` },
        });
        const nums = remaining
          .map((d: any) =>
            parseInt(d.numeroListe.match(/DAO-\d{4}-(\d{3})/)?.[1] || "0", 10),
          )
          .filter((n: number) => !isNaN(n));
        lastIssuedSeqByYear[year] = nums.length ? Math.max(...nums) : 0;
      }
    }
    return result.deletedCount > 0;
  }

  // Initialize with sample data if empty
  static async initializeSampleData(sampleDaos: Dao[]): Promise<void> {
    await this.ensureConnection();
    if (useInMemory) {
      // already seeded via daoStorage
      return;
    }
    const count = await DaoModel.countDocuments();
    if (count === 0) {
      console.log("🌱 Initializing database with sample data...");
      await DaoModel.insertMany(sampleDaos);
      console.log("✅ Sample data initialized");
    }
  }

  // Clear all DAOs (DB or in-memory)
  static async clearAll(): Promise<void> {
    await this.ensureConnection();
    // Reset sequence baselines for all years to avoid starting at a higher number after purge
    for (const k of Object.keys(lastIssuedSeqByYear))
      delete lastIssuedSeqByYear[k];

    if (useInMemory) {
      daoStorage.clearAll(false);
      return;
    }
    try {
      await DaoModel.deleteMany({});
      console.log("🧹 All DAOs removed from database");
    } catch (e) {
      console.error("❌ Failed to clear DAOs from database:", e);
      throw e;
    }
  }
}
