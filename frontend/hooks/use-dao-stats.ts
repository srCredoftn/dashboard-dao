import { useMemo } from "react";
import { Dao, calculateDaoProgress, calculateDaoStatus } from "@shared/dao";

interface DaoStats {
  total: number;
  active: number;
  completed: number;
  urgent: number;
  globalProgress: number;
}

export function useDaoStats(daos: Dao[]): DaoStats {
  return useMemo(() => {
    // Calculate progress once per DAO to avoid multiple recalculations
    const daoWithProgress = daos.map((dao) => {
      const progress = calculateDaoProgress(dao.tasks);
      const status = calculateDaoStatus(dao.dateDepot, progress);
      return { dao, progress, status };
    });

    const activeDaos = daoWithProgress.filter(({ progress }) => progress < 100);
    const completedDaos = daoWithProgress.filter(
      ({ progress }) => progress >= 100,
    );
    const urgentDaos = daoWithProgress.filter(
      ({ status }) => status === "urgent",
    );

    const globalProgress =
      activeDaos.length > 0
        ? Math.round(
            activeDaos.reduce((sum, { progress }) => sum + progress, 0) /
              activeDaos.length,
          )
        : 0;

    return {
      total: daos.length,
      active: activeDaos.length,
      completed: completedDaos.length,
      urgent: urgentDaos.length,
      globalProgress,
    };
  }, [daos]);
}
