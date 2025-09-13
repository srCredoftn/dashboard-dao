export interface TeamMember {
  id: string;
  name: string;
  role: "chef_equipe" | "membre_equipe";
  email?: string;
}

export interface DaoTask {
  id: number;
  name: string;
  progress: number | null; // null for n/a
  comment?: string; // Legacy single comment
  comments?: TaskComment[]; // New comments system
  isApplicable: boolean;
  assignedTo?: string[]; // Member IDs assigned to this task (multi-assignment)
  lastUpdatedBy?: string;
  lastUpdatedAt?: string;
}

export interface Dao {
  id: string;
  numeroListe: string;
  objetDossier: string;
  reference: string;
  autoriteContractante: string;
  dateDepot: string; // ISO string
  equipe: TeamMember[];
  tasks: DaoTask[];
  createdAt: string;
  updatedAt: string;
}

export interface DaoStats {
  totalDaos: number;
  daoEnCours: number;
  daoTermines: number;
  daoArisque: number; // < 3 days to deadline
  progressionGlobale: number; // Average progress of all active DAOs
}

export interface TaskGlobalProgress {
  taskId: number;
  taskName: string;
  globalProgress: number;
  applicableDaosCount: number;
}

export interface DaoFilters {
  dateRange?: {
    start: string;
    end: string;
  };
  autoriteContractante?: string;
  statut?: "en_cours" | "termine" | "a_risque";
  equipe?: string;
}

export type DaoStatus = "completed" | "urgent" | "safe" | "default";

// User roles and authentication
export type UserRole = "admin" | "user" | "viewer";

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  createdAt: string;
  lastLogin?: string;
  isActive: boolean;
  isSuperAdmin?: boolean;
}

// Comment system
export interface TaskComment {
  id: string;
  taskId: number;
  daoId: string;
  userId: string;
  userName: string;
  content: string;
  createdAt: string;
}

// Authentication context
export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatarUrl?: string; // optional profile photo stored client-side or provided by backend
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface AuthResponse {
  user: AuthUser;
  token: string;
}

export const DEFAULT_TASKS: Omit<
  DaoTask,
  "progress" | "comment" | "assignedTo"
>[] = [
  {
    id: 1,
    name: "Résumé sommaire DAO et Création du drive",
    isApplicable: true,
  },
  { id: 2, name: "Demande de caution et garanties", isApplicable: true },
  {
    id: 3,
    name: "Identification et renseignement des profils dans le drive",
    isApplicable: true,
  },
  {
    id: 4,
    name: "Identification et renseignement des ABE dans le drive",
    isApplicable: true,
  },
  {
    id: 5,
    name: "Légalisation des ABE, diplômes, certificats, attestations et pièces administratives requis",
    isApplicable: true,
  },
  {
    id: 6,
    name: "Indication directive d'élaboration de l'offre financier",
    isApplicable: true,
  },
  { id: 7, name: "Elaboration de la méthodologie", isApplicable: true },
  { id: 8, name: "Planification prévisionnelle", isApplicable: true },
  {
    id: 9,
    name: "Identification des références précises des équipements et matériels",
    isApplicable: true,
  },
  { id: 10, name: "Demande de cotation", isApplicable: true },
  { id: 11, name: "Elaboration du squelette des offres", isApplicable: true },
  { id: 12, name: "Rédaction du contenu des OF et OT", isApplicable: true },
  { id: 13, name: "Contrôle et validation des offres", isApplicable: true },
  {
    id: 14,
    name: "Impression et présentation des offres (Valider l'étiquette)",
    isApplicable: true,
  },
  { id: 15, name: "Dépôt des offres et clôture", isApplicable: true },
];

export function calculateDaoStatus(
  dateDepot: string,
  progress: number,
): DaoStatus {
  const today = new Date();
  const depotDate = new Date(dateDepot);
  const daysDiff = Math.ceil(
    (depotDate.getTime() - today.getTime()) / (1000 * 60 * 60 * 24),
  );

  // Priority logic as specified
  if (progress >= 100) return "completed";
  if (daysDiff >= 5) return "safe";
  if (daysDiff <= 3) return "urgent";
  return "default";
}

export function calculateDaoProgress(tasks: DaoTask[]): number {
  // Only consider applicable tasks
  const applicableTasks = tasks.filter((task) => task.isApplicable);
  if (applicableTasks.length === 0) return 0;

  // Sum up all progress (null progress is treated as 0)
  const totalProgress = applicableTasks.reduce((sum, task) => {
    return sum + (task.progress ?? 0);
  }, 0);

  // Calculate average and round to nearest integer
  const averageProgress = totalProgress / applicableTasks.length;
  return Math.round(averageProgress);
}
