import { useState, useEffect, useCallback, useRef } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { ArrowLeft, FileText, Download, Edit3 } from "lucide-react";
// jsPDF import dynamique pour réduire la taille du bundle initial
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { devLog } from "@/utils/devLogger";
import { cn, getBlinkingDateClasses } from "@/lib/utils";
import { apiService } from "@/services/api";
import { taskService } from "@/services/taskService";
import {
  calculateDaoProgress,
  type Dao,
  type DaoTask,
  type TeamMember,
} from "@shared/dao";
import TeamEditDialog from "@/components/TeamEditDialog";
import DeleteLastDaoButton from "@/components/DeleteLastDaoButton";
import { TaskRow } from "@/components/TaskRow";
import ExportFilterDialog, {
  type ExportOptions,
} from "@/components/ExportFilterDialog";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";

export default function DaoDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const [dao, setDao] = useState<Dao | null>(null);
  const [isLastDao, setIsLastDao] = useState(false);
  const { toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isEditingAuthority, setIsEditingAuthority] = useState(false);
  const [tempAuthority, setTempAuthority] = useState("");
  const [isEditingReference, setIsEditingReference] = useState(false);
  const [tempReference, setTempReference] = useState("");
  const [isEditingObjet, setIsEditingObjet] = useState(false);
  const [tempObjet, setTempObjet] = useState("");

  // Debouncing pour optimiser les performances
  const saveTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const debouncedSave = useCallback(async (daoToSave: Dao) => {
    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }

    saveTimeoutRef.current = setTimeout(async () => {
      try {
        await apiService.updateDao(daoToSave.id, daoToSave, true); // Skip cache invalidation pour optimiser
        devLog.log(`✅ DAO ${daoToSave.id} saved successfully`);
      } catch (error) {
        devLog.error("Error saving DAO:", error);
      }
    }, 150);
  }, []);

  // Load DAO from API
  useEffect(() => {
    const loadDao = async () => {
      if (!id) {
        setError("ID du DAO manquant");
        setLoading(false);
        return;
      }

      console.log(`🔍 DaoDetail: Loading DAO with ID=${id} from URL`);

      try {
        setLoading(true);
        setError(null);
        const fetchedDao = await apiService.getDaoById(id);
        console.log(`📦 DaoDetail: Received DAO:`, {
          id: fetchedDao.id,
          numeroListe: fetchedDao.numeroListe,
          objetDossier: fetchedDao.objetDossier,
        });
        setDao(fetchedDao);
        // Check if this is the last created DAO (admin-only feature)
        try {
          const next = await apiService.getNextDaoNumber(); // e.g., DAO-2025-005
          const m = next.match(/^DAO-(\d{4})-(\d{3})$/i);
          if (m) {
            const year = m[1];
            const seq = Math.max(1, parseInt(m[2], 10) - 1)
              .toString()
              .padStart(3, "0");
            const expectedLast = `DAO-${year}-${seq}`;
            setIsLastDao(fetchedDao.numeroListe === expectedLast);
          } else {
            setIsLastDao(false);
          }
        } catch (_) {
          setIsLastDao(false);
        }
      } catch (err) {
        const errorMessage =
          err instanceof Error ? err.message : "��chec du chargement du DAO";

        // Si le DAO n'est pas trouvé, rediriger vers la liste des DAOs (sans log d'erreur bruyant)
        if (
          /not\s*found/i.test(errorMessage) ||
          /\b404\b/.test(errorMessage) ||
          /HTTP error! status:\s*404/i.test(errorMessage)
        ) {
          devLog.log("DAO not found, redirecting to DAO list...");
          toast({
            title: "DAO introuvable",
            description: "Le dossier a été supprimé ou n'existe plus.",
          });
          navigate("/", { replace: true });
          return;
        }

        devLog.error("Error loading DAO:", err);
        setError(errorMessage);
      } finally {
        setLoading(false);
      }
    };

    loadDao();
  }, [id]);

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
    };
  }, []);

  // Loading state - optimisé pour être plus léger
  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <h2 className="text-lg font-semibold text-foreground mb-2">
            Chargement de la page
          </h2>
          <p className="text-muted-foreground">Veuillez patienter...</p>
        </div>
      </div>
    );
  }

  // Error or not found state
  if (error || !dao) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle>DAO introuvable</CardTitle>
            <CardDescription>
              {error || "Le dossier demandé n'existe pas ou a été supprimé."}
            </CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <Button asChild>
              <Link to="/">Retour au tableau de bord</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const progress = calculateDaoProgress(dao.tasks);

  const handleTaskProgressChange = (
    taskId: number,
    newProgress: number | null,
  ) => {
    if (!dao) return;

    const updatedDao = {
      ...dao,
      tasks: dao.tasks.map((task) =>
        task.id === taskId ? { ...task, progress: newProgress } : task,
      ),
    };

    // Mise à jour optimiste immédiate
    setDao(updatedDao);

    // Sauvegarde différée pour éviter trop d'appels API
    debouncedSave(updatedDao);

    devLog.log(
      `📝 Task ${taskId} progress changed to ${newProgress}% (saving...)`,
    );
  };

  const handleTaskCommentChange = (taskId: number, newComment: string) => {
    setDao((prev) =>
      prev
        ? {
            ...prev,
            tasks: prev.tasks.map((task) =>
              task.id === taskId ? { ...task, comment: newComment } : task,
            ),
          }
        : null,
    );
  };

  const handleTaskApplicableChange = (taskId: number, applicable: boolean) => {
    if (!dao) return;

    // Utiliser la fonction unifiée handleTaskUpdate pour éviter les conflits
    const updates = { isApplicable: applicable };

    // Mise à jour optimiste immédiate
    setDao((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        tasks: prev.tasks.map((task) =>
          task.id === taskId ? { ...task, ...updates } : task,
        ),
      };
    });

    // Sauvegarde différée pour éviter trop d'appels API
    debouncedSave({
      ...dao,
      tasks: dao.tasks.map((task) =>
        task.id === taskId ? { ...task, ...updates } : task,
      ),
    });

    devLog.log(
      `📝 Task ${taskId} applicability changed to ${applicable} (saving...)`,
    );
  };

  const handleTeamUpdate = (newTeam: TeamMember[]) => {
    setDao((prev) =>
      prev
        ? {
            ...prev,
            equipe: newTeam,
          }
        : null,
    );
    // Persist immediately so server can broadcast role updates and emails
    if (dao) {
      const nextDao = { ...dao, equipe: newTeam } as Dao;
      debouncedSave(nextDao);
    }
  };

  // Task management functions - add disabled (button hidden)

  const handleTaskUpdate = async (
    taskId: number,
    updates: Partial<DaoTask>,
  ) => {
    if (!dao) return;

    try {
      // Mise à jour optimiste locale d'abord
      setDao((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          tasks: prev.tasks.map((task) =>
            task.id === taskId
              ? { ...task, ...updates, lastUpdatedAt: new Date().toISOString() }
              : task,
          ),
        };
      });

      if (updates.name !== undefined) {
        // Update task name
        await taskService.updateTaskName(dao.id, taskId, updates.name);
      } else {
        // Update other task properties
        await taskService.updateTask(dao.id, taskId, {
          progress:
            typeof updates.progress === "number" ? updates.progress : undefined,
          comment: updates.comment,
          isApplicable: updates.isApplicable,
          assignedTo: updates.assignedTo,
        });
      }

      // Note: On évite de faire setDao ici pour ne pas conflicter avec les mises à jour optimistes debounced
      // La cohérence sera assurée par le prochain chargement de page
      devLog.log(`✅ Task ${taskId} updated successfully on server`);
    } catch (error) {
      devLog.error("Error updating task:", error);
      setError("Erreur lors de la mise à jour de la tâche");

      // Recharger les données en cas d'erreur pour annuler la mise à jour optimiste
      try {
        const freshDao = await apiService.getDaoById(dao.id);
        setDao(freshDao);
      } catch (reloadError) {
        devLog.error("Error reloading DAO after failed update:", reloadError);
      }
    }
  };

  const handleTaskAssignmentChange = async (
    taskId: number,
    memberIds: string[],
  ) => {
    if (!dao) return;

    // Optimistic update
    setDao((prev) =>
      prev
        ? {
            ...prev,
            tasks: prev.tasks.map((t) =>
              t.id === taskId ? { ...t, assignedTo: memberIds } : t,
            ),
          }
        : prev,
    );

    try {
      await taskService.updateTask(dao.id, taskId, { assignedTo: memberIds });
    } catch (error) {
      devLog.error("Error updating task assignment:", error);
      setError("Failed to update task assignment");
      try {
        const fresh = await apiService.getDaoById(dao.id);
        setDao(fresh);
      } catch (reloadErr) {
        devLog.error(
          "Error reloading DAO after assignment failure:",
          reloadErr,
        );
      }
    }
  };

  const handleExportWithOptions = (options: ExportOptions) => {
    if (!dao) return;

    // Include all tasks by default, but allow filtering
    let filteredTasks = dao.tasks.filter((task) => {
      if (!task.isApplicable && !options.includeNotApplicable) return false;
      if (task.isApplicable) {
        const progress = task.progress || 0;
        if (progress === 0 && !options.includeTodos) return false;
        if (progress > 0 && progress < 100 && !options.includeInProgress)
          return false;
        if (progress >= 100 && !options.includeCompleted) return false;
      }
      return true;
    });

    // If all options are selected, export ALL tasks including custom ones
    if (
      options.includeTodos &&
      options.includeInProgress &&
      options.includeCompleted &&
      options.includeNotApplicable
    ) {
      filteredTasks = dao.tasks; // Include all tasks including added ones
    }

    if (options.format === "PDF") {
      handleExportPDF(filteredTasks);
    } else {
      handleExportCSV(filteredTasks);
    }
  };

  const handleExportPDF = async (tasks: DaoTask[]) => {
    const { default: jsPDF } = await import("jspdf");
    const pdf = new jsPDF();
    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();
    const margin = 14;
    let y = margin;

    // Header utilities
    const LOGO_URL =
      "https://cdn.builder.io/api/v1/image/assets%2F376e9389c66d473f975258354bf70209%2F9d870cba39fd46d3bb0ed8d14c652440?format=webp&width=800";
    const loadImageAsPngDataUrl = (url: string) =>
      new Promise<{ dataUrl: string; width: number; height: number }>(
        (resolve, reject) => {
          const img = new Image();
          img.crossOrigin = "anonymous";
          img.onload = () => {
            const canvas = document.createElement("canvas");
            canvas.width = img.naturalWidth;
            canvas.height = img.naturalHeight;
            const ctx = canvas.getContext("2d");
            if (!ctx) return reject(new Error("Canvas context not available"));
            ctx.drawImage(img, 0, 0);
            resolve({
              dataUrl: canvas.toDataURL("image/png"),
              width: img.naturalWidth,
              height: img.naturalHeight,
            });
          };
          img.onerror = () => reject(new Error("Failed to load logo"));
          img.src = url;
        },
      );

    const logo = await loadImageAsPngDataUrl(LOGO_URL).catch(() => null);

    const drawTopHeader = (isFirstPage: boolean) => {
      if (!isFirstPage) {
        return;
      }

      // Logo
      if (logo) {
        const logoW = 28;
        const ratio = logo.height && logo.width ? logo.height / logo.width : 1;
        const logoH = logoW * ratio;
        pdf.addImage(
          logo.dataUrl,
          "PNG",
          pageWidth / 2 - logoW / 2,
          y,
          logoW,
          logoH,
        );
        y += logoH + 6;
      }

      // Title
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(16);
      pdf.text("Rapport DAO", pageWidth / 2, y, { align: "center" });
      y += 6;
      // Small subtitle (company)
      pdf.setFontSize(10);
      pdf.setFont("helvetica", "normal");
      pdf.text("2SND Technologies", pageWidth / 2, y, { align: "center" });
      y += 6;

      // Info block (clean two-column layout)
      const headerBlockPadding = 8;
      const columnGap = 10;
      const startY = y;
      const contentWidth = pageWidth - margin * 2;
      const halfWidth = (contentWidth - columnGap) / 2;
      const lineH = 5; // line height for wrapped text
      const rowSpacing = 4; // uniform spacing between rows/sections
      const singleLine = 5; // approximate height for single text line

      // Measure label widths (for inline rows)
      pdf.setFontSize(11);
      const labelWidth = (t: string) => {
        pdf.setFont("helvetica", "bold");
        const w = pdf.getTextWidth(`${t}: `);
        pdf.setFont("helvetica", "normal");
        return w;
      };

      const leftColWidth = halfWidth - headerBlockPadding * 2;
      const rightColWidth = halfWidth - headerBlockPadding * 2;

      const objetLines = pdf.splitTextToSize(
        dao?.objetDossier || "",
        leftColWidth,
      );
      const autoriteLines = pdf.splitTextToSize(
        dao?.autoriteContractante || "",
        rightColWidth,
      );

      const refLines = pdf.splitTextToSize(
        dao?.reference || "",
        rightColWidth - labelWidth("Référence"),
      );

      const leftHeight =
        singleLine + // DAO line
        rowSpacing + // space before label "Objet"
        objetLines.length * lineH + // value lines
        rowSpacing + // space before date
        singleLine; // date line
      const rightHeight =
        refLines.length * lineH + // Référence wrapped lines
        rowSpacing + // space before label "Autorité Contractante"
        autoriteLines.length * lineH + // value lines
        rowSpacing + // space before progression
        singleLine; // progression line

      const blockHeight =
        headerBlockPadding * 2 + Math.max(leftHeight, rightHeight);

      // Background with subtle border and vertical divider
      pdf.setFillColor(232, 240, 254);
      pdf.rect(margin, startY, contentWidth, blockHeight, "F");
      pdf.setDrawColor(210, 225, 250);
      pdf.rect(margin, startY, contentWidth, blockHeight, "S");

      // Vertical divider
      const dividerX = margin + contentWidth / 2;
      pdf.setDrawColor(210, 225, 250);
      pdf.line(dividerX, startY, dividerX, startY + blockHeight);

      // Left column
      let hx = margin + headerBlockPadding;
      let hy = startY + headerBlockPadding + 2;
      pdf.setFont("helvetica", "bold");
      pdf.text(`DAO: ${dao?.numeroListe || ""}`, hx, hy);

      const objetLabelY = hy + rowSpacing + singleLine;
      pdf.text("Objet:", hx, objetLabelY);
      pdf.setFont("helvetica", "normal");
      const objetStartY = objetLabelY + lineH;
      objetLines.forEach((ln: string, idx: number) => {
        pdf.text(ln, hx, objetStartY + idx * lineH);
      });

      const dateY = objetStartY + objetLines.length * lineH + rowSpacing;
      pdf.setFont("helvetica", "bold");
      pdf.text("Date de dépôt:", hx, dateY);
      pdf.setFont("helvetica", "normal");
      pdf.text(dao?.dateDepot || "", hx + labelWidth("Date de dépôt"), dateY);

      // Right column
      const col2X = dividerX + headerBlockPadding;
      hy = startY + headerBlockPadding + 2;
      // Référence (wrapped inline like others)
      const refLabel = "Référence";
      const refLabelW = labelWidth(refLabel);
      pdf.setFont("helvetica", "bold");
      pdf.text(`${refLabel}:`, col2X, hy);
      pdf.setFont("helvetica", "normal");
      const refValue = dao?.reference || "";
      const refLinesDraw = pdf.splitTextToSize(
        refValue,
        rightColWidth - refLabelW,
      );
      pdf.text(refLinesDraw[0] || "", col2X + refLabelW, hy);
      for (let i = 1; i < (refLinesDraw as string[]).length; i++) {
        pdf.text(
          (refLinesDraw as string[])[i],
          col2X + refLabelW,
          hy + i * lineH,
        );
      }

      const autoriteLabelY = hy + refLinesDraw.length * lineH + rowSpacing;
      pdf.setFont("helvetica", "bold");
      pdf.text("Autorité Contractante:", col2X, autoriteLabelY);
      pdf.setFont("helvetica", "normal");
      const autoriteStartY = autoriteLabelY + lineH;
      autoriteLines.forEach((ln: string, idx: number) => {
        pdf.text(ln, col2X, autoriteStartY + idx * lineH);
      });

      const progY = autoriteStartY + autoriteLines.length * lineH + rowSpacing;
      pdf.setFont("helvetica", "bold");
      pdf.text("Progression globale:", col2X, progY);
      pdf.setFont("helvetica", "normal");
      pdf.text(
        `${progress}%`,
        col2X + labelWidth("Progression globale"),
        progY,
      );

      y = startY + blockHeight + 8;
    };

    drawTopHeader(true);

    // Team small list
    if (dao?.equipe?.length) {
      pdf.setFont("helvetica", "bold");
      pdf.text("Équipe", margin, y);
      y += 6;
      pdf.setFont("helvetica", "normal");
      const team = dao.equipe
        .map(
          (m) => `${m.name} (${m.role === "chef_equipe" ? "Chef" : "Membre"})`,
        )
        .join(", ");
      const teamLines = pdf.splitTextToSize(team, pageWidth - margin * 2);
      for (const line of teamLines as string[]) {
        if (y > pageHeight - margin) {
          pdf.addPage();
          y = margin;
          drawTopHeader(false);
        }
        pdf.text(line, margin + 2, y);
        y += 6;
      }
      y += 2;
    }

    // Tasks table
    y += 4;

    // Table columns (sum should be <= content width)
    const contentWidth = pageWidth - margin * 2;
    const columns = [
      { header: "Tâches", width: Math.round(contentWidth * 0.44) },
      { header: "Applicable", width: Math.round(contentWidth * 0.14) },
      { header: "Progression", width: Math.round(contentWidth * 0.16) },
      { header: "Assigné à", width: Math.round(contentWidth * 0.26) },
    ];

    const drawTableHeader = () => {
      pdf.setFontSize(10);
      pdf.setFont("helvetica", "bold");
      let x = margin;
      const h = 9;
      pdf.setFillColor(232, 240, 254);
      pdf.rect(x, y, contentWidth, h, "F");
      columns.forEach((col) => {
        pdf.rect(x, y, col.width, h, "S");
        const textY = y + 6;
        pdf.text(col.header, x + 2, textY);
        x += col.width;
      });
      y += h;
      pdf.setFont("helvetica", "normal");
    };

    const ensureSpace = (rowHeight: number) => {
      if (y + rowHeight > pageHeight - margin) {
        pdf.addPage();
        y = margin;
        drawTopHeader(false);
        drawTableHeader();
      }
    };

    drawTableHeader();

    const lineHeight = 5;
    let rowIndex = 0;
    for (const task of tasks) {
      const progressValue = task.progress || 0;
      const progressText = task.isApplicable ? `${progressValue}%` : "N/A";
      const applicableText = task.isApplicable ? "Oui" : "Non";
      const assignee =
        task.assignedTo && task.assignedTo.length
          ? task.assignedTo
              .map(
                (id) => dao?.equipe.find((m) => m.id === id)?.name || "Inconnu",
              )
              .join(", ")
          : "Non assigné";
      const row = [task.name, applicableText, progressText, assignee];

      // Compute wrapped text per cell
      const wrapped = row.map((cell, i) =>
        pdf.splitTextToSize(String(cell), columns[i].width - 4),
      );
      const rowHeight =
        Math.max(...wrapped.map((w) => w.length)) * lineHeight + 4;
      ensureSpace(rowHeight);

      // Zebra background
      if (rowIndex % 2 === 0) {
        pdf.setFillColor(249, 251, 255); // very light blue/gray
        pdf.rect(margin, y, contentWidth, rowHeight, "F");
      }

      let x = margin;
      for (let i = 0; i < columns.length; i++) {
        const col = columns[i];
        pdf.rect(x, y, col.width, rowHeight, "S");
        const lines = wrapped[i] as string[];
        let ty = y + 3.5;

        // Color for specific columns
        if (i === 1) {
          // Applicable
          if (task.isApplicable)
            pdf.setTextColor(16, 121, 63); // soft green
          else pdf.setTextColor(176, 38, 38); // soft red
        } else if (i === 2) {
          // Progression
          if (!task.isApplicable) pdf.setTextColor(102, 102, 102);
          else if (progressValue >= 100) pdf.setTextColor(16, 121, 63);
          else if (progressValue >= 50) pdf.setTextColor(23, 92, 211);
          else pdf.setTextColor(178, 105, 0);
        } else {
          pdf.setTextColor(0, 0, 0);
        }

        lines.forEach((ln) => {
          pdf.text(ln, x + 2, ty + 3);
          ty += lineHeight;
        });
        // Reset color after each cell
        pdf.setTextColor(0, 0, 0);
        x += col.width;
      }
      y += rowHeight;
      rowIndex++;
    }

    // Footer stats
    if (y > pageHeight - margin - 24) {
      pdf.addPage();
      y = margin;
      drawTopHeader(false);
    }
    pdf.setFont("helvetica", "bold");
    pdf.text("Statistiques", margin, y + 8);
    pdf.setFont("helvetica", "normal");
    const stats = [
      `Tâches exportées: ${tasks.length}`,
      `Terminées: ${tasks.filter((t) => t.isApplicable && (t.progress || 0) >= 100).length}`,
      `En cours: ${tasks.filter((t) => t.isApplicable && (t.progress || 0) > 0 && (t.progress || 0) < 100).length}`,
      `À faire: ${tasks.filter((t) => t.isApplicable && (t.progress || 0) === 0).length}`,
    ];
    let sy = y + 14;
    for (const s of stats) {
      if (sy > pageHeight - margin) {
        pdf.addPage();
        sy = margin;
        drawTopHeader(false);
        pdf.setFont("helvetica", "bold");
        pdf.text("Statistiques", margin, sy + 8);
        pdf.setFont("helvetica", "normal");
        sy += 14;
      }
      pdf.text(`• ${s}`, margin, sy);
      sy += 6;
    }

    // Footer page numbers (bottom-right)
    const totalPages = pdf.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      pdf.setPage(i);
      const pw = pdf.internal.pageSize.getWidth();
      const ph = pdf.internal.pageSize.getHeight();
      pdf.setFontSize(10);
      // Left footer text on pages > 1
      if (i > 1) {
        pdf.setFont("helvetica", "normal");
        pdf.setTextColor(120, 162, 224);
        pdf.text(`Rapport ${dao?.numeroListe || ""}`, margin, ph - 8, {
          align: "left",
        });
        pdf.setTextColor(0, 0, 0);
      }
      pdf.setFont("helvetica", "normal");
      pdf.text(`${i} / ${totalPages}`, pw - margin, ph - 8, { align: "right" });
    }

    pdf.save(`${dao?.numeroListe}_export.pdf`);
  };

  const handleExportCSV = (tasks: DaoTask[]) => {
    const csvContent = [
      ["Tâche", "Applicable", "Progression (%)", "Commentaire", "Assigné à"],
      ...tasks.map((task) => [
        task.name,
        task.isApplicable ? "Oui" : "Non",
        task.isApplicable ? (task.progress || 0).toString() : "N/A",
        task.comment || "",
        task.assignedTo && task.assignedTo.length
          ? task.assignedTo
              .map(
                (id) => dao?.equipe.find((m) => m.id === id)?.name || "Inconnu",
              )
              .join(", ")
          : "Non assigné",
      ]),
    ]
      .map((row) => row.map((cell) => `"${cell}"`).join(","))
      .join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${dao?.numeroListe}_tasks.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleStartEditingAuthority = () => {
    setTempAuthority(dao?.autoriteContractante || "");
    setIsEditingAuthority(true);
  };

  const handleSaveAuthority = async () => {
    const next = tempAuthority.trim();
    if (!dao || !next) return;
    try {
      const updated = await apiService.updateDao(dao.id, {
        autoriteContractante: next,
      });
      setDao(updated);
      setIsEditingAuthority(false);
    } catch (e) {
      devLog.error("Failed to save authority:", e);
    }
  };

  const handleCancelEditingAuthority = () => {
    setTempAuthority("");
    setIsEditingAuthority(false);
  };

  const handleStartEditingReference = () => {
    setTempReference(dao?.reference || "");
    setIsEditingReference(true);
  };

  const handleSaveReference = async () => {
    const next = tempReference.trim();
    if (!dao || !next) return;
    try {
      const updated = await apiService.updateDao(dao.id, { reference: next });
      setDao(updated);
      setIsEditingReference(false);
    } catch (e) {
      devLog.error("Failed to save reference:", e);
    }
  };

  const handleCancelEditingReference = () => {
    setTempReference("");
    setIsEditingReference(false);
  };

  // Objet du dossier editing (admin only)
  const handleStartEditingObjet = () => {
    setTempObjet(dao?.objetDossier || "");
    setIsEditingObjet(true);
  };

  const handleSaveObjet = async () => {
    const next = tempObjet.trim();
    if (!dao || !next) return;
    try {
      const updated = await apiService.updateDao(dao.id, { objetDossier: next });
      setDao(updated);
      setIsEditingObjet(false);
    } catch (e) {
      devLog.error("Failed to save objet du dossier:", e);
    }
  };

  const handleCancelEditingObjet = () => {
    setTempObjet("");
    setIsEditingObjet(false);
  };

  // handleTaskAssignmentChange is already defined above - removed duplicate

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const today = new Date();
    const daysDiff = Math.ceil(
      (date.getTime() - today.getTime()) / (1000 * 60 * 60 * 24),
    );
    const formattedDate = date.toLocaleDateString("fr-FR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
    });

    return {
      date: formattedDate,
      daysDiff: daysDiff, // Gardons le signe pour la logique conditionnelle
      daysDiffAbs: Math.abs(daysDiff), // Version absolue pour l'affichage
      isOverdue: daysDiff < 0,
    };
  };

  const dateInfo = formatDate(dao.dateDepot);
  const completedTasks = dao.tasks.filter(
    (task) => task.isApplicable && (task.progress || 0) >= 100,
  ).length;
  const inProgressTasks = dao.tasks.filter(
    (task) =>
      task.isApplicable &&
      (task.progress || 0) > 0 &&
      (task.progress || 0) < 100,
  ).length;
  const todoTasks = dao.tasks.filter(
    (task) => task.isApplicable && (task.progress || 0) === 0,
  ).length;
  const applicableTasks = dao.tasks.filter((task) => task.isApplicable).length;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b">
        <div className="container mx-auto px-2 sm:px-4 py-3 sm:py-4">
          {/* Mobile & Tablet Layout */}
          <div className="block lg:hidden">
            {/* Ligne haute: Retour • Exporter • % */}
            <div className="flex items-center justify-between gap-2 mb-2">
              <Button
                variant="ghost"
                size="sm"
                asChild
                className="flex-shrink-0"
              >
                <Link to="/">
                  <ArrowLeft className="h-4 w-4" />
                  <span className="ml-1 text-sm">Retour</span>
                </Link>
              </Button>
              <div className="flex items-center gap-2">
                <Badge variant="destructive" className="text-xs font-bold">
                  {progress}% terminé
                </Badge>
                <ExportFilterDialog
                  tasks={dao.tasks}
                  onExport={handleExportWithOptions}
                >
                  <Button variant="outline" size="sm" className="px-3 h-8">
                    <Download className="h-4 w-4 mr-1" />
                    <span className="text-sm">Exporter</span>
                  </Button>
                </ExportFilterDialog>
              </div>
            </div>

            {/* Ligne basse: Titre + référence */}
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0">
                <FileText className="h-4 w-4 text-blue-600" />
              </div>
              <div className="min-w-0">
                <h1 className="text-base font-bold truncate">Détails DAO</h1>
                <p className="text-xs text-muted-foreground truncate">
                  {dao.numeroListe} • {dao.reference}
                </p>
              </div>
            </div>
          </div>

          {/* Desktop Layout */}
          <div className="hidden lg:block">
            {/* Ligne haute: Retour • Exporter • % */}
            <div className="flex items-center justify-between mb-2">
              <Button variant="ghost" size="sm" asChild>
                <Link to="/">
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Retour
                </Link>
              </Button>
              <div className="flex items-center gap-3">
                <Badge variant="destructive" className="text-sm font-bold">
                  {progress}% terminé
                </Badge>
                <ExportFilterDialog
                  tasks={dao.tasks}
                  onExport={handleExportWithOptions}
                >
                  <Button variant="outline" size="sm">
                    <Download className="h-4 w-4 mr-2" />
                    Exporter
                  </Button>
                </ExportFilterDialog>
              </div>
            </div>
            {/* Ligne basse: Titre + référence */}
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                <FileText className="h-5 w-5 text-blue-600" />
              </div>
              <div>
                <h1 className="text-lg lg:text-xl font-bold">Détails DAO</h1>
                <p className="text-sm text-muted-foreground">
                  {dao.numeroListe} • {dao.reference}
                </p>
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-2 sm:px-4 py-4 sm:py-6">
        {/* DAO Information */}
        <Card className="mb-6 sm:mb-8">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex-1">
                {isEditingObjet ? (
                  <div className="space-y-2">
                    <Input
                      value={tempObjet}
                      onChange={(e) => setTempObjet(e.target.value)}
                      placeholder="Saisir l'objet du dossier..."
                      className="font-medium"
                    />
                    <div className="flex gap-2">
                      <Button size="sm" onClick={handleSaveObjet}>
                        Sauvegarder
                      </Button>
                      <Button size="sm" variant="outline" onClick={handleCancelEditingObjet}>
                        Annuler
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-start gap-3">
                    <CardTitle className="text-lg md:text-xl">{dao.objetDossier}</CardTitle>
                    {isAdmin() && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0"
                        onClick={handleStartEditingObjet}
                        aria-label="Modifier l'objet du dossier"
                      >
                        <Edit3 className="h-3 w-3" />
                      </Button>
                    )}
                  </div>
                )}
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm text-muted-foreground">
                    Référence
                  </Label>
                  {!isEditingReference && isAdmin() && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0"
                      onClick={handleStartEditingReference}
                    >
                      <Edit3 className="h-3 w-3" />
                    </Button>
                  )}
                </div>
                {isEditingReference ? (
                  <div className="space-y-2">
                    <Input
                      value={tempReference}
                      onChange={(e) => setTempReference(e.target.value)}
                      placeholder="Saisir la référence..."
                      className="font-medium"
                    />
                    <div className="flex gap-2">
                      <Button size="sm" onClick={handleSaveReference}>
                        Sauvegarder
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={handleCancelEditingReference}
                      >
                        Annuler
                      </Button>
                    </div>
                  </div>
                ) : (
                  <p className="font-medium break-words">{dao.reference}</p>
                )}
              </div>

              <div className="space-y-2">
                <Label className="text-sm text-muted-foreground">
                  Date de dépôt
                </Label>
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "px-2 py-1 rounded text-sm font-medium blink-attention",
                      getBlinkingDateClasses(progress, dao.dateDepot),
                    )}
                  >
                    {dateInfo.date} ({dateInfo.daysDiffAbs}j{" "}
                    {dateInfo.isOverdue ? "dépassé" : "restants"})
                  </span>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm text-muted-foreground">
                    Autorité contractante
                  </Label>
                  {!isEditingAuthority && isAdmin() && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0"
                      onClick={handleStartEditingAuthority}
                    >
                      <Edit3 className="h-3 w-3" />
                    </Button>
                  )}
                </div>
                {isEditingAuthority ? (
                  <div className="space-y-2">
                    <Input
                      value={tempAuthority}
                      onChange={(e) => setTempAuthority(e.target.value)}
                      placeholder="Saisir l'autorité contractante..."
                      className="font-medium"
                    />
                    <div className="flex gap-2">
                      <Button size="sm" onClick={handleSaveAuthority}>
                        Sauvegarder
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={handleCancelEditingAuthority}
                      >
                        Annuler
                      </Button>
                    </div>
                  </div>
                ) : (
                  <p className="font-medium">{dao.autoriteContractante}</p>
                )}
              </div>
            </div>

            <Separator className="my-6" />

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Avancement global</span>
                <span className="text-2xl font-bold">{progress}%</span>
              </div>
              <Progress
                value={progress}
                className={cn(
                  "h-4",
                  progress === 100 ? "[&>*]:bg-gray-400" : "",
                )}
              />

              <div className="grid grid-cols-3 gap-2 sm:gap-4 text-center">
                <div>
                  <div className="text-xl md:text-2xl font-bold text-green-600">
                    {completedTasks}
                  </div>
                  <div className="text-xs text-muted-foreground">Terminées</div>
                </div>
                <div>
                  <div className="text-xl md:text-2xl font-bold text-blue-600">
                    {inProgressTasks}
                  </div>
                  <div className="text-xs text-muted-foreground">En cours</div>
                </div>
                <div>
                  <div className="text-xl md:text-2xl font-bold text-gray-600">
                    {todoTasks}
                  </div>
                  <div className="text-xs text-muted-foreground">À faire</div>
                </div>
              </div>
            </div>

            <Separator className="my-6" />

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium">Chef d'équipe</Label>
                {isAdmin() && (
                  <TeamEditDialog
                    currentTeam={dao.equipe}
                    onTeamUpdate={handleTeamUpdate}
                    type="both"
                  />
                )}
              </div>
              <p className="font-medium break-words">
                {dao.equipe.find((m) => m.role === "chef_equipe")?.name ||
                  "Non assigné"}
              </p>

              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium">Membres d'équipe</Label>
              </div>
              <div className="space-y-2">
                {dao.equipe
                  .filter((m) => m.role === "membre_equipe")
                  .map((member) => (
                    <div
                      key={member.id}
                      className="flex flex-col sm:flex-row sm:items-center gap-2"
                    >
                      <span className="font-medium break-words">
                        {member.name}
                      </span>
                    </div>
                  ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Tasks Detail */}
        <Card>
          <CardHeader>
            <CardTitle>Détail des tâches</CardTitle>
          </CardHeader>
          <CardContent className="px-3 sm:px-6">
            <div className="space-y-3 sm:space-y-4">
              {dao.tasks.map((task, index) => {
                // Calculer la numérotation dynamique basée sur les tâches réellement affichées
                const displayIndex = index + 1;

                return (
                  <TaskRow
                    key={task.id}
                    task={task}
                    daoId={dao.id}
                    onProgressChange={handleTaskProgressChange}
                    onCommentChange={handleTaskCommentChange}
                    onApplicableChange={handleTaskApplicableChange}
                    onAssignmentChange={handleTaskAssignmentChange}
                    onTaskUpdate={handleTaskUpdate}
                    availableMembers={dao.equipe}
                    daysDiff={dateInfo.daysDiff}
                    taskIndex={displayIndex}
                  />
                );
              })}
            </div>

            {/* Total applicable tasks count */}
            <div className="flex justify-center pt-4 mt-4 border-t border-gray-200">
              <div className="flex items-center gap-2 px-4 py-2 bg-gray-50 rounded-lg">
                <span className="text-sm font-medium text-gray-700">
                  Total :
                </span>
                <span className="text-sm font-bold text-primary">
                  {applicableTasks} tâches applicables
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        {isAdmin() && isLastDao && (
          <div className="mt-8 flex justify-center">
            <DeleteLastDaoButton
              hasDaos={true}
              onDeleted={() => {
                navigate("/");
              }}
            />
          </div>
        )}
      </main>
    </div>
  );
}

function Label({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <label className={className}>{children}</label>;
}
