import { useState } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ConfirmationDialog } from "@/components/ui/confirmation-dialog";
import { useAuth } from "@/contexts/AuthContext";
import { apiService } from "@/services/api";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface DeleteLastDaoButtonProps {
  onDeleted: (deletedId: string) => void;
  disabled?: boolean;
  hasDaos: boolean;
}

export default function DeleteLastDaoButton({
  onDeleted,
  disabled,
  hasDaos,
}: DeleteLastDaoButtonProps) {
  const { isAdmin } = useAuth();
  const [open, setOpen] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  if (!isAdmin()) return null;

  const handleConfirm = async () => {
    setProcessing(true);
    setError(null);
    const idempotencyKey = `delete-last-dao:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
    try {
      const result = await apiService.deleteLastDao({
        idempotencyKey,
        password,
      });
      onDeleted(result.deletedId);
      setPassword("");
      return true;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (
        msg.toLowerCase().includes("invalid password") ||
        msg.includes("INVALID_PASSWORD")
      ) {
        setError("Mot de passe incorrect, Veuillez réessayer");
        return false;
      }
      console.error("Suppression échouée:", e);
      setError("Erreur lors de la suppression. Réessayez plus tard.");
      return false;
    } finally {
      setProcessing(false);
    }
  };

  return (
    <ConfirmationDialog
      trigger={
        <Button
          variant="destructive"
          size="sm"
          className="w-full xs:w-auto lg:w-28"
          disabled={disabled || processing || !hasDaos}
          onClick={() => setOpen(true)}
        >
          <Trash2 className="h-4 w-4 mr-2" />
          Supprimer
        </Button>
      }
      title="Supprimer ?"
      description={
        hasDaos
          ? "Cette action supprimera définitivement ce DAO. Opération irréversible.\n\nPour confirmer, entrez le mot de passe du Super Admin."
          : "Aucun DAO à supprimer."
      }
      confirmText={processing ? "En cours..." : "Supprimer"}
      cancelText="Annuler"
      onConfirm={handleConfirm}
      variant="destructive"
      icon="trash"
      open={open}
      onOpenChange={setOpen}
      disabled={!hasDaos || password.length === 0}
    >
      <div className="mt-4 space-y-2">
        <Label htmlFor="confirm-password">Mot de passe Super Admin</Label>
        <Input
          id="confirm-password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Entrez le mot de passe"
        />
        {error && <p className="text-sm text-red-600">{error}</p>}
      </div>
    </ConfirmationDialog>
  );
}
