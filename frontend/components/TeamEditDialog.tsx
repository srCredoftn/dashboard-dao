import { useState, useEffect } from "react";
import { Edit3, Users, X, ChevronDown } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
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
  Popover,
  PopoverTrigger,
  PopoverContent,
} from "@/components/ui/popover";
import {
  Command,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
import { Checkbox } from "@/components/ui/checkbox";
import { type TeamMember, type User } from "@shared/dao";
import { authService } from "@/services/authService";
import { ConfirmationDialog } from "@/components/ui/confirmation-dialog";

// Helper to convert users to team members
const convertUserToTeamMember = (
  user: User,
  role: "chef_equipe" | "membre_equipe" = "membre_equipe",
): TeamMember => ({
  id: user.id,
  name: user.name,
  email: user.email,
  role,
});

interface TeamEditDialogProps {
  currentTeam: TeamMember[];
  onTeamUpdate: (newTeam: TeamMember[]) => void;
  type: "chef" | "membres" | "both";
}

export default function TeamEditDialog({
  currentTeam,
  onTeamUpdate,
  type,
}: TeamEditDialogProps) {
  const [open, setOpen] = useState(false);
  const [tempTeam, setTempTeam] = useState<TeamMember[]>(currentTeam);

  // Keep tempTeam in sync when opening the dialog or when currentTeam changes
  useEffect(() => {
    if (open) setTempTeam(currentTeam);
  }, [open, currentTeam]);
  const [availableUsers, setAvailableUsers] = useState<User[]>([]);
  const [isLoadingUsers, setIsLoadingUsers] = useState(false);

  // Fetch users when dialog opens
  useEffect(() => {
    if (open) {
      const fetchUsers = async () => {
        setIsLoadingUsers(true);
        try {
          const users = await authService.getAllUsers();
          // Dedupe by id/email to avoid duplicates in lists (prevents key collisions)
          const unique = Array.from(
            new Map(
              users.map((u) => [
                u.id || u.email || `${u.name}-${u.createdAt}`,
                u,
              ]),
            ).values(),
          );
          setAvailableUsers(unique);
        } catch (error) {
          console.error("Failed to fetch users:", error);
        } finally {
          setIsLoadingUsers(false);
        }
      };
      fetchUsers();
    }
  }, [open]);

  // Convert users to available members format (default to membre) and ensure uniqueness by id
  const availableMembers: TeamMember[] = Array.from(
    new Map(
      availableUsers
        .map((user) => convertUserToTeamMember(user, "membre_equipe"))
        .map((m) => [m.id, m]),
    ).values(),
  );

  const handleSave = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    // Merge the current team with the edited members
    let newTeam: TeamMember[] = [];

    if (type === "chef") {
      // For chef editing: keep all existing membres, replace chef
      const existingMembers = currentTeam.filter(
        (m) => m.role === "membre_equipe",
      );
      const newChef = tempTeam.find((m) => m.role === "chef_equipe");
      newTeam = newChef ? [...existingMembers, newChef] : existingMembers;
    } else if (type === "membres") {
      // For membres editing: keep existing chef, replace membres
      const existingChef = currentTeam.find((m) => m.role === "chef_equipe");
      const newMembers = tempTeam.filter((m) => m.role === "membre_equipe");
      newTeam = existingChef ? [existingChef, ...newMembers] : newMembers;
    } else {
      // both: build chef + members from tempTeam
      const newChef = tempTeam.find((m) => m.role === "chef_equipe");
      const newMembers = tempTeam.filter((m) => m.role === "membre_equipe");

      // Ensure a user is not both chef and membre: remove duplicates from members
      const memberIds = new Set(newMembers.map((m) => m.id));
      if (newChef && memberIds.has(newChef.id)) {
        // remove chef id from members
        newTeam = [newChef, ...newMembers.filter((m) => m.id !== newChef.id)];
      } else if (newChef) {
        newTeam = [newChef, ...newMembers];
      } else {
        newTeam = newMembers;
      }
    }

    // Final dedupe: ensure unique ids
    const unique: Record<string, TeamMember> = {};
    for (const m of newTeam) unique[m.id] = m;
    const finalTeam = Object.values(unique);

    onTeamUpdate(finalTeam);
    setOpen(false);
  };

  const handleCancel = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setTempTeam(currentTeam);
    setOpen(false);
  };

  const addExistingMember = (
    member: TeamMember,
    roleOverride?: "chef_equipe" | "membre_equipe",
  ) => {
    const roleToUse =
      roleOverride || (type === "chef" ? "chef_equipe" : "membre_equipe");
    if (roleToUse === "chef_equipe") {
      // For chef, replace the current chef and remove same user from members if present
      const newTeam = tempTeam.filter(
        (m) => m.role !== "chef_equipe" && m.id !== member.id,
      );
      setTempTeam([...newTeam, { ...member, role: "chef_equipe" }]);
    } else {
      // For membres, add if not already in team (as member or chef)
      if (!tempTeam.find((m) => m.id === member.id)) {
        setTempTeam([...tempTeam, { ...member, role: "membre_equipe" }]);
      }
    }
  };

  const removeMember = (memberId: string, e?: React.MouseEvent) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    setTempTeam(tempTeam.filter((m) => m.id !== memberId));
  };

  const currentChef = tempTeam.filter((m) => m.role === "chef_equipe");
  const currentMembersList = tempTeam.filter((m) => m.role === "membre_equipe");

  // For selection lists we want to show all available users (like NewDaoDialog)
  // and handle dedupe when adding to the tempTeam.
  const availableToAdd = availableMembers;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
          <Edit3 className="h-3 w-3" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Users className="h-4 w-4" />
            Modifier
            {type === "chef"
              ? " le chef d'équipe"
              : type === "membres"
                ? " les membres d'équipe"
                : " l'équipe"}
          </DialogTitle>
          <DialogDescription>
            {type === "chef"
              ? "Sélectionnez un chef d'équipe parmi les utilisateurs existants"
              : type === "membres"
                ? "Gérez les membres de l'équipe à partir des utilisateurs existants"
                : "Modifiez le chef et les membres de l'équipe"}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Chef Section (for chef and both) */}
          {(type === "chef" || type === "both") && (
            <div className="space-y-2">
              <Label className="text-sm font-medium">Chef actuel</Label>
              {currentChef.length > 0 ? (
                <div className="space-y-2">
                  {currentChef.map((member) => (
                    <div
                      key={member.id}
                      className="flex items-center justify-between p-2 border rounded"
                    >
                      <div>
                        <span className="font-medium">{member.name}</span>
                        {member.email && (
                          <p className="text-xs text-muted-foreground">
                            {member.email}
                          </p>
                        )}
                      </div>
                      <ConfirmationDialog
                        trigger={
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 w-6 p-0 text-red-500 hover:text-red-700"
                          >
                            <X className="h-3 w-3" />
                          </Button>
                        }
                        title={`Retirer le chef d'équipe`}
                        description={`Êtes-vous sûr de vouloir retirer ${member.name} de l'équipe ?`}
                        confirmText="Retirer"
                        onConfirm={() => removeMember(member.id)}
                        icon="warning"
                      />
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  Aucun chef assigné
                </p>
              )}

              <div className="mt-2">
                <Label className="text-sm font-medium">
                  Sélectionner un chef existant
                </Label>
                <Select
                  onValueChange={(value) => {
                    const member = availableMembers.find((m) => m.id === value);
                    if (member) addExistingMember(member, "chef_equipe");
                  }}
                >
                  <SelectTrigger>
                    <SelectValue
                      placeholder={
                        isLoadingUsers ? "Chargement..." : "Sélectionner..."
                      }
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {Array.from(
                      new Map(availableToAdd.map((m) => [m.id, m])).values(),
                    ).map((member, idx) => (
                      <SelectItem key={`${member.id}-${idx}`} value={member.id}>
                        {member.name} {member.email && `(${member.email})`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          {/* Members Section (for membres and both) */}
          {(type === "membres" || type === "both") && (
            <div className="space-y-2">
              <Label className="text-sm font-medium">Membres actuels</Label>
              {currentMembersList.length > 0 ? (
                <div className="space-y-2">
                  {currentMembersList.map((member) => (
                    <div
                      key={member.id}
                      className="flex items-center justify-between p-2 border rounded"
                    >
                      <div>
                        <span className="font-medium">{member.name}</span>
                        {member.email && (
                          <p className="text-xs text-muted-foreground">
                            {member.email}
                          </p>
                        )}
                      </div>
                      <ConfirmationDialog
                        trigger={
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 w-6 p-0 text-red-500 hover:text-red-700"
                          >
                            <X className="h-3 w-3" />
                          </Button>
                        }
                        title={`Retirer le membre`}
                        description={`Êtes-vous sûr de vouloir retirer ${member.name} de l'équipe ?`}
                        confirmText="Retirer"
                        onConfirm={() => removeMember(member.id)}
                        icon="warning"
                      />
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  Aucun membre assigné
                </p>
              )}

              <div className="mt-2">
                <Label className="text-sm font-medium">
                  Ajouter un membre existant
                </Label>
                <Popover>
                  <PopoverTrigger asChild>
                    <Button
                      variant="outline"
                      className="justify-between w-full"
                    >
                      <span>
                        {isLoadingUsers
                          ? "Chargement..."
                          : currentMembersList.length > 0
                            ? `${currentMembersList.length} membre(s) sélectionné(s)`
                            : "Sélectionner des membres..."}
                      </span>
                      <ChevronDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
                    </Button>
                  </PopoverTrigger>

                  <PopoverContent className="w-[350px] p-0">
                    <Command>
                      <CommandInput placeholder="Rechercher un membre..." />
                      <CommandList>
                        <CommandEmpty>Aucun membre trouvé.</CommandEmpty>
                        <CommandGroup>
                          {availableMembers
                            .filter((member) => {
                              // do not include current chef
                              const chef = tempTeam.find(
                                (m) => m.role === "chef_equipe",
                              );
                              return !chef || chef.id !== member.id;
                            })
                            .map((member, idx) => {
                              const isSelected = tempTeam.find(
                                (m) =>
                                  m.id === member.id &&
                                  m.role === "membre_equipe",
                              );
                              return (
                                <CommandItem
                                  key={member.id || `${member.email}-${idx}`}
                                  onSelect={() => {
                                    if (isSelected) {
                                      // remove
                                      setTempTeam((prev) =>
                                        prev.filter((m) => m.id !== member.id),
                                      );
                                    } else {
                                      addExistingMember(
                                        member,
                                        "membre_equipe",
                                      );
                                    }
                                  }}
                                >
                                  <div className="flex items-center space-x-2 flex-1">
                                    <Checkbox
                                      checked={!!isSelected}
                                      onCheckedChange={() => {}}
                                    />
                                    <span>{member.name}</span>
                                    {member.email && (
                                      <span className="text-xs text-muted-foreground">
                                        ({member.email})
                                      </span>
                                    )}
                                  </div>
                                </CommandItem>
                              );
                            })}
                        </CommandGroup>
                      </CommandList>
                    </Command>
                  </PopoverContent>
                </Popover>
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={handleCancel}>
            Annuler
          </Button>
          <Button
            onClick={handleSave}
            disabled={
              !(
                tempTeam.some((m) => m.role === "chef_equipe") &&
                tempTeam.some((m) => m.role === "membre_equipe")
              )
            }
          >
            Sauvegarder
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
