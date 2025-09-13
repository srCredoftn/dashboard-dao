import { useState } from "react";
import { AppHeader } from "@/components/AppHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useAuth } from "@/contexts/AuthContext";

export default function AdminHealth() {
  const { isAdmin } = useAuth();
  const [smtpStatus, setSmtpStatus] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);

  const checkSmtp = async () => {
    setLoading(true);
    setSmtpStatus("");
    try {
      const res = await fetch("/api/health/smtp");
      const data = await res.json();
      if (res.ok && data.ok) setSmtpStatus("SMTP OK");
      else setSmtpStatus(`Erreur SMTP: ${data.error || "inconnue"}`);
    } catch (e) {
      setSmtpStatus(`Erreur: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  };

  const sendTest = async () => {
    setSending(true);
    try {
      const res = await fetch("/api/notifications/test-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const data = await res.json();
      if (res.ok && data.ok) alert("Email de test envoyé.");
      else alert(`Echec envoi: ${data.error || "inconnu"}`);
    } catch (e) {
      alert(`Erreur: ${(e as Error).message}`);
    } finally {
      setSending(false);
    }
  };

  if (!isAdmin()) return null;

  return (
    <div className="min-h-screen bg-background">
      <AppHeader title="Santé du système" />
      <main className="container mx-auto px-4 py-8">
        <Card className="max-w-xl mx-auto">
          <CardHeader>
            <CardTitle>Vérifications</CardTitle>
            <CardDescription>Outils de diagnostic</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3">
              <Button onClick={checkSmtp} disabled={loading}>
                {loading ? "Vérification..." : "Vérifier SMTP"}
              </Button>
              <span className="text-sm">{smtpStatus}</span>
            </div>
            <div>
              <Button variant="outline" onClick={sendTest} disabled={sending}>
                {sending ? "Envoi..." : "Envoyer un email de test"}
              </Button>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
