import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  Users,
  Plus,
  Trash2,
  Mail,
  Calendar,
  Shield,
  AlertCircle,
  Eye,
  EyeOff,
} from "lucide-react";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useAuth } from "@/contexts/AuthContext";
import { authService } from "@/services/authService";
import { useToast } from "@/hooks/use-toast";
import type { User, UserRole } from "@shared/dao";
import { ConfirmationDialog } from "@/components/ui/confirmation-dialog";

interface NewUserForm {
  name: string;
  email: string;
  role: UserRole;
  password: string;
}

export default function UserManagement() {
  const navigate = useNavigate();
  const { user, isAdmin } = useAuth();
  const { toast } = useToast();

  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const [newUserForm, setNewUserForm] = useState<NewUserForm>({
    name: "",
    email: "",
    role: "user",
    password: "",
  });

  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!isAdmin()) {
      navigate("/");
      return;
    }
    loadUsers();
  }, [isAdmin, navigate]);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const usersData = await authService.getAllUsers();
      // Dedupe by id/email to prevent duplicate rows and key collisions
      const unique = Array.from(
        new Map(
          usersData.map((u) => [
            u.id || u.email || `${u.name}-${u.createdAt}`,
            u,
          ]),
        ).values(),
      );
      setUsers(unique);
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de charger la liste des utilisateurs.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const generatePassword = () => {
    const charset =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let password = "";
    for (let i = 0; i < 12; i++) {
      password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    setNewUserForm({ ...newUserForm, password });
  };

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    const trimmedName = newUserForm.name.trim();
    if (!trimmedName) {
      newErrors.name = "Le nom est requis";
    } else {
      // Must start with uppercase letter (support accented uppercase)
      // Use Unicode property for uppercase letters when available
      let matchesUpper = false;
      try {
        matchesUpper = /^\p{Lu}/u.test(trimmedName);
      } catch (_) {
        // Fallback: simple ASCII uppercase check
        matchesUpper = /^[A-Z]/.test(trimmedName);
      }
      if (!matchesUpper) {
        newErrors.name = "Commence par une lettre majuscule";
      }
    }

    if (!newUserForm.email.trim()) {
      newErrors.email = "L'email est requis";
    } else if (!/\S+@\S+\.\S+/.test(newUserForm.email)) {
      newErrors.email = "Format d'email invalide";
    }

    if (!newUserForm.password) {
      newErrors.password = "Le mot de passe est requis";
    } else if (newUserForm.password.length < 6) {
      newErrors.password =
        "Le mot de passe doit contenir au moins 6 caractères";
    }

    // Check if email already exists
    if (users.some((u) => u.email === newUserForm.email)) {
      newErrors.email = "Cet email est déjà utilisé";
    }

    // Check if name already exists (case-insensitive)
    if (trimmedName && users.some((u) => u.name.toLowerCase() === trimmedName.toLowerCase())) {
      newErrors.name = newErrors.name || "Ce nom est déjà utilisé";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleCreateUser = async () => {
    if (!validateForm()) return;

    setIsCreating(true);
    const idempotencyKey = `create-user:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
    try {
      const newUser = await authService.createUser(newUserForm, {
        idempotencyKey,
      });
      setUsers([...users, newUser]);
      setNewUserForm({
        name: "",
        email: "",
        role: "user",
        password: "",
      });
      setIsCreateDialogOpen(false);
      toast({
        title: "Utilisateur créé",
        description: `L'utilisateur ${newUser.name} a été créé avec succès.`,
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de créer l'utilisateur.",
        variant: "destructive",
      });
    } finally {
      setIsCreating(false);
    }
  };

  const handleDeleteUser = async (userId: string, userName: string) => {
    if (userId === user?.id) {
      toast({
        title: "Action impossible",
        description: "Vous ne pouvez pas supprimer votre propre compte.",
        variant: "destructive",
      });
      return;
    }

    try {
      const idempotencyKey = `deactivate-user:${userId}:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
      await authService.deactivateUser(userId, { idempotencyKey });
      setUsers(users.filter((u) => u.id !== userId));
      toast({
        title: "Utilisateur supprimé",
        description: `L'utilisateur ${userName} a été supprimé.`,
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de supprimer l'utilisateur.",
        variant: "destructive",
      });
    }
  };

  const getRoleBadgeColor = (role: UserRole) => {
    switch (role) {
      case "admin":
        return "bg-red-100 text-red-800";
      case "user":
        return "bg-blue-100 text-blue-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const getRoleLabel = (role: UserRole, isSuperAdmin?: boolean) => {
    switch (role) {
      case "admin":
        return isSuperAdmin ? "Administrateur Principal" : "Administrateur";
      case "user":
        return "Utilisateur";
      default:
        return "Inconnu";
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("fr-FR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  if (!isAdmin()) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle>Accès non autorisé</CardTitle>
            <CardDescription>
              Vous devez être administrateur pour accéder à cette page.
            </CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <Button onClick={() => navigate("/")}>
              Retour au tableau de bord
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b">
        <div className="container mx-auto px-2 sm:px-4 py-3 sm:py-4">
          {/* Mobile Layout */}
          <div className="block sm:hidden">
            {/* First Row: Back button and title */}
            <div className="flex items-center space-x-2 mb-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate("/")}
                className="flex-shrink-0"
              >
                <ArrowLeft className="h-4 w-4" />
                <span className="ml-1 text-sm">Retour</span>
              </Button>
              <div className="flex items-center space-x-2 flex-1 min-w-0">
                <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0">
                  <Users className="h-4 w-4 text-blue-600" />
                </div>
                <div className="min-w-0 flex-1">
                  <h1 className="text-base font-bold truncate">
                    Gestion des utilisateurs
                  </h1>
                  <p className="text-xs text-muted-foreground truncate">
                    Gérez les comptes utilisateurs
                  </p>
                </div>
              </div>
            </div>

            {/* Second Row: Action button for mobile */}
            <div className="flex justify-center">
              <Button
                className="w-full sm:w-auto"
                onClick={() => setIsCreateDialogOpen(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                Nouvel utilisateur
              </Button>
            </div>
          </div>

          {/* Desktop Layout */}
          <div className="hidden sm:flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Button variant="ghost" size="sm" onClick={() => navigate("/")}>
                <ArrowLeft className="h-4 w-4 mr-2" />
                Retour au tableau de bord
              </Button>

              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                  <Users className="h-5 w-5 text-blue-600" />
                </div>
                <div>
                  <h1 className="text-xl font-bold">
                    Gestion des utilisateurs
                  </h1>
                  <p className="text-sm text-muted-foreground">
                    Gérez les comptes utilisateurs de l'application
                  </p>
                </div>
              </div>
            </div>

            <Dialog
              open={isCreateDialogOpen}
              onOpenChange={setIsCreateDialogOpen}
            >
              <DialogTrigger asChild>
                <Button className="w-full sm:w-auto">
                  <Plus className="h-4 w-4 mr-2" />
                  Nouvel utilisateur
                </Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-md">
                <DialogHeader>
                  <DialogTitle>Créer un nouvel utilisateur</DialogTitle>
                  <DialogDescription>
                    Ajoutez un nouveau membre à l'équipe avec les informations
                    ci-dessous.
                  </DialogDescription>
                </DialogHeader>

                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">Nom complet</Label>
                    <Input
                      id="name"
                      value={newUserForm.name}
                      onChange={(e) =>
                        setNewUserForm({ ...newUserForm, name: e.target.value })
                      }
                      className={errors.name ? "border-red-500" : ""}
                    />
                    {errors.name && (
                      <p className="text-sm text-red-600">{errors.name}</p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="email">Email</Label>
                    <Input
                      id="email"
                      type="email"
                      value={newUserForm.email}
                      onChange={(e) =>
                        setNewUserForm({
                          ...newUserForm,
                          email: e.target.value,
                        })
                      }
                      className={errors.email ? "border-red-500" : ""}
                    />
                    {errors.email && (
                      <p className="text-sm text-red-600">{errors.email}</p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="role">Rôle</Label>
                    <Select
                      value={newUserForm.role}
                      onValueChange={(value: UserRole) =>
                        setNewUserForm({ ...newUserForm, role: value })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="user">Utilisateur</SelectItem>
                        <SelectItem value="admin">Administrateur</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="password">Mot de passe</Label>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={generatePassword}
                      >
                        Générer
                      </Button>
                    </div>
                    <div className="relative">
                      <Input
                        id="password"
                        type={showPassword ? "text" : "password"}
                        value={newUserForm.password}
                        onChange={(e) =>
                          setNewUserForm({
                            ...newUserForm,
                            password: e.target.value,
                          })
                        }
                        className={errors.password ? "border-red-500" : ""}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-2 top-1/2 -translate-y-1/2 h-6 w-6 p-0"
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? (
                          <EyeOff className="h-4 w-4" />
                        ) : (
                          <Eye className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                    {errors.password && (
                      <p className="text-sm text-red-600">{errors.password}</p>
                    )}
                  </div>

                  <Alert>
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      L'utilisateur devra changer son mot de passe lors de sa
                      première connexion.
                    </AlertDescription>
                  </Alert>
                </div>

                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => setIsCreateDialogOpen(false)}
                  >
                    Annuler
                  </Button>
                  <Button onClick={handleCreateUser} disabled={isCreating}>
                    {isCreating ? "Création..." : "Créer l'utilisateur"}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Utilisateurs ({users.length})
            </CardTitle>
            <CardDescription>
              Liste de tous les utilisateurs avec leurs rôles et statuts
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center py-8">
                <div className="animate-pulse text-muted-foreground">
                  Chargement des utilisateurs...
                </div>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Utilisateur</TableHead>
                    <TableHead>Rôle</TableHead>
                    <TableHead>Dernière connexion</TableHead>
                    <TableHead>Créé le</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((userData, idx) => (
                    <TableRow key={userData.id || `${userData.email}-${idx}`}>
                      <TableCell>
                        <div className="flex flex-col">
                          <span className="font-medium">{userData.name}</span>
                          <span className="text-sm text-muted-foreground flex items-center">
                            <Mail className="h-3 w-3 mr-1" />
                            {userData.email}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={getRoleBadgeColor(userData.role)}>
                          <Shield className="h-3 w-3 mr-1" />
                          {getRoleLabel(
                            userData.role,
                            (userData as any).isSuperAdmin,
                          )}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {userData.lastLogin ? (
                          <span className="text-sm flex items-center">
                            <Calendar className="h-3 w-3 mr-1" />
                            {formatDate(userData.lastLogin)}
                          </span>
                        ) : (
                          <span className="text-sm text-muted-foreground">
                            Jamais connecté
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="text-sm flex items-center">
                          <Calendar className="h-3 w-3 mr-1" />
                          {formatDate(userData.createdAt)}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-2">
                          <ConfirmationDialog
                            trigger={
                              <Button
                                variant="ghost"
                                size="sm"
                                disabled={userData.id === user?.id}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            }
                            title="Supprimer l'utilisateur"
                            description={`Êtes-vous sûr de vouloir supprimer l'utilisateur "${userData.name}" ? Cette action est irréversible.`}
                            confirmText="Supprimer"
                            onConfirm={() =>
                              handleDeleteUser(userData.id, userData.name)
                            }
                            disabled={userData.id === user?.id}
                            icon="trash"
                          />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
