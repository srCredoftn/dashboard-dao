import { useState, useEffect } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import type { FormEvent } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Eye, EyeOff } from "lucide-react";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [passwordTouched, setPasswordTouched] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const idle = (cb: () => void) => {
      if (typeof (window as any).requestIdleCallback === "function") {
        (window as any).requestIdleCallback(cb, { timeout: 2000 });
      } else {
        setTimeout(cb, 300);
      }
    };
    idle(() => {
      import("@/pages/Index");
      import("@/pages/DaoDetail");
    });
  }, []);

  // Get the intended destination or default to home
  const from = location.state?.from?.pathname || "/";

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    if (!email || !password) {
      setError("Veuillez saisir votre email et votre mot de passe");
      return;
    }
    if (password.length < 6) {
      setError("Le mot de passe doit contenir au moins 6 caractères");
      setPasswordTouched(true);
      return;
    }

    try {
      setIsLoading(true);
      setError("");

      await login({ email, password });

      // Redirect to intended page or home
      navigate(from, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Échec de la connexion");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">
        {/* Header */}
        <div className="text-center">
          <div className="flex justify-center mb-4">
            <img
              src="https://cdn.builder.io/api/v1/image/assets%2F376e9389c66d473f975258354bf70209%2F9d870cba39fd46d3bb0ed8d14c652440?format=webp&width=256"
              alt="2SND Technologies"
              className="w-32 h-32 object-contain"
              width="128"
              height="128"
              loading="eager"
              decoding="async"
            />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 -mt-10">
            Gestion des DAO
          </h1>
          <p className="text-gray-600">Connectez-vous à votre compte</p>
        </div>

        {/* Login Form */}
        <Card>
          <CardHeader>
            <CardTitle>Connexion</CardTitle>
            <CardDescription>
              Saisissez vos identifiants pour accéder à la plateforme
            </CardDescription>
          </CardHeader>

          <form onSubmit={handleSubmit}>
            <CardContent className="space-y-4">
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="votre.email@2snd.fr"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={isLoading}
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Mot de passe</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Votre mot de passe"
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      setPasswordTouched(true);
                    }}
                    onBlur={() => setPasswordTouched(true)}
                    disabled={isLoading}
                    required
                    className={
                      passwordTouched &&
                      password.length > 0 &&
                      password.length < 6
                        ? "border-red-500"
                        : passwordTouched && password.length >= 6
                          ? "border-green-500"
                          : ""
                    }
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                    onClick={() => setShowPassword(!showPassword)}
                    disabled={isLoading}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
                {passwordTouched && (
                  <div className="mt-1 text-xs">
                    {password.length === 0 ? (
                      <p className="text-red-600">Le mot de passe est requis</p>
                    ) : password.length < 6 ? (
                      <p className="text-red-600">
                        Au moins 6 caractères requis
                      </p>
                    ) : (
                      <p className="text-green-600">
                        Format de mot de passe valide
                      </p>
                    )}
                  </div>
                )}
              </div>
            </CardContent>

            <CardFooter className="flex flex-col space-y-4">
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Connexion...
                  </>
                ) : (
                  "Se connecter"
                )}
              </Button>

              <div className="text-center">
                <Link
                  to="/forgot-password"
                  className="text-sm text-blue-600 hover:text-blue-800 hover:underline"
                  onMouseEnter={() => import("@/pages/ForgotPassword")}
                  onFocus={() => import("@/pages/ForgotPassword")}
                >
                  Mot de passe oublié ?
                </Link>
              </div>
            </CardFooter>
          </form>
        </Card>
      </div>
    </div>
  );
}
