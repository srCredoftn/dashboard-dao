import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Mail, ArrowLeft, Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";

export default function ForgotPassword() {
  const navigate = useNavigate();
  const { toast } = useToast();

  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [emailSent, setEmailSent] = useState(false);
  const [error, setError] = useState("");

  const validateEmail = (email: string): boolean => {
    return /\S+@\S+\.\S+/.test(email);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!email.trim()) {
      setError("L'email est requis");
      return;
    }

    if (!validateEmail(email)) {
      setError("Format d'email invalide");
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Une erreur est survenue");
      }

      setEmailSent(true);

      // For development - show the token
      if (data.developmentToken) {
        toast({
          title: "Code de développement",
          description: `Code généré: ${data.developmentToken}`,
          duration: 10000,
        });
      }

      toast({
        title: "Email envoyé",
        description:
          "Vérifiez votre boîte email pour le code de réinitialisation.",
      });

      // Redirect to reset password page with email
      setTimeout(() => {
        navigate(`/reset-password?email=${encodeURIComponent(email)}`);
      }, 2000);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Une erreur est survenue",
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex items-center justify-center space-x-2 mb-4">
            <img
              src="https://cdn.builder.io/api/v1/image/assets%2F376e9389c66d473f975258354bf70209%2F9d870cba39fd46d3bb0ed8d14c652440?format=webp&width=800"
              alt="2SND Technologies"
              className="w-16 h-16 object-contain"
            />
          </div>
          <CardTitle className="flex items-center justify-center gap-2">
            <Mail className="h-5 w-5" />
            Mot de passe oublié
          </CardTitle>
          <CardDescription>
            Entrez votre adresse email pour recevoir un code de réinitialisation
          </CardDescription>
        </CardHeader>

        <CardContent>
          {emailSent ? (
            <div className="text-center space-y-4">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto">
                <Send className="h-8 w-8 text-green-600" />
              </div>
              <div className="space-y-2">
                <h3 className="font-medium">Email envoyé !</h3>
                <p className="text-sm text-muted-foreground">
                  Un code de réinitialisation a été envoyé à{" "}
                  <strong>{email}</strong>. Vérifiez votre boîte email et suivez
                  les instructions.
                </p>
              </div>
              <div className="flex flex-col gap-2">
                <Button
                  onClick={() =>
                    navigate(
                      `/reset-password?email=${encodeURIComponent(email)}`,
                    )
                  }
                  className="w-full"
                >
                  Saisir le code reçu
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setEmailSent(false)}
                  className="w-full"
                >
                  Renvoyer un code
                </Button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <div className="space-y-2">
                <Label htmlFor="email">Adresse email</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="votre.email@exemple.com"
                  disabled={isLoading}
                  className={error ? "border-red-500" : ""}
                />
              </div>

              <Button type="submit" disabled={isLoading} className="w-full">
                <Mail className="h-4 w-4 mr-2" />
                {isLoading ? "Envoi en cours..." : "Envoyer le code"}
              </Button>

              <div className="text-center">
                <Button variant="ghost" asChild>
                  <Link to="/login">
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Retour à la connexion
                  </Link>
                </Button>
              </div>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
