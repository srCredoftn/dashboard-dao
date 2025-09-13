import { useState, useEffect } from "react";
import {
  MessageSquare,
  Send,
  Trash2,
  Calendar,
  ChevronRight,
  ChevronDown,
} from "lucide-react";
import { ConfirmationDialog } from "@/components/ui/confirmation-dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { commentService } from "@/services/commentService";
import { useAuth } from "@/contexts/AuthContext";
import { useNotifications } from "@/contexts/NotificationContext";
import { TaskComment, TeamMember } from "@shared/dao";
import { getAvatarUrl } from "@/utils/avatar";

interface TaskCommentsProps {
  daoId: string;
  taskId: number;
  taskName: string;
  availableMembers: TeamMember[];
  showAddInput?: boolean;
}

export default function TaskComments({
  daoId,
  taskId,
  taskName,
  availableMembers,
  showAddInput = true,
}: TaskCommentsProps) {
  const [comments, setComments] = useState<TaskComment[]>([]);
  const [newComment, setNewComment] = useState("");
  const [loading, setLoading] = useState(false);
  const [submitLoading, setSubmitLoading] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [mentionQuery, setMentionQuery] = useState("");
  const [cursorPosition, setCursorPosition] = useState(0);
  const { user } = useAuth();
  const { addNotification, refresh: refreshNotifications } = useNotifications();

  // Prefetch comments once on mount and whenever DAO/task changes
  useEffect(() => {
    loadComments();
    // load on dao/task change
  }, [daoId, taskId]);

  // Refresh when expanded
  useEffect(() => {
    if (isExpanded) {
      loadComments();
    }
  }, [isExpanded]);

  const uniqueById = (arr: TaskComment[]) => {
    const seen = new Set<string>();
    const res: TaskComment[] = [];
    for (const c of arr) {
      if (!seen.has(c.id)) {
        seen.add(c.id);
        res.push(c);
      }
    }
    return res;
  };

  const loadComments = async () => {
    try {
      setLoading(true);
      const taskComments = await commentService.getTaskComments(daoId, taskId);
      const sorted = taskComments.sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
      setComments(uniqueById(sorted));
    } catch (error) {
      console.error("Error loading comments:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitComment = async () => {
    if (!newComment.trim() || !user) return;

    const content = newComment.trim();
    const tempId = `temp-${Date.now()}`;
    const optimisticComment: TaskComment = {
      id: tempId,
      taskId,
      daoId,
      userId: user.id,
      userName: user.name,
      content,
      createdAt: new Date().toISOString(),
    };

    // Optimistic UI update
    setComments((prev) => [optimisticComment, ...prev]);
    setNewComment("");
    setShowSuggestions(false);
    setSubmitLoading(true);

    const idempotencyKey = `comment:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;

    try {
      const saved = await commentService.addComment(daoId, taskId, content, {
        idempotencyKey,
      });

      // Replace optimistic comment with saved one
      setComments((prev) => {
        const next = prev.map((c) => (c.id === tempId ? saved : c));
        const seen = new Set<string>();
        const dedup: TaskComment[] = [];
        for (const c of next) {
          if (!seen.has(c.id)) {
            seen.add(c.id);
            dedup.push(c);
          }
        }
        return dedup;
      });

      // Ensure state is in sync with server
      await loadComments();

      // Detect mentions and send notifications (non-blocking)
      const mentionRegex = /@(\w+)/g;
      const mentions = [...content.matchAll(mentionRegex)];

      for (const mention of mentions) {
        const mentionedUsername = mention[1];
        const mentionedMember = availableMembers.find((member) =>
          member.name.toLowerCase().includes(mentionedUsername.toLowerCase()),
        );

        if (mentionedMember && mentionedMember.id !== user.id) {
          addNotification({
            type: "mention",
            title: `Mention dans ${taskName}`,
            message: `${user.name} vous a mentionné dans un commentaire : "${content.slice(0, 50)}${content.length > 50 ? "..." : ""}"`,
            taskId,
            daoId,
            data: { fromUser: user.name, priority: "high" },
          });
        }
      }

      if (availableMembers.length > 1) {
        addNotification({
          type: "task_update",
          title: `Nouveau commentaire sur ${taskName}`,
          message: `${user.name} a ajouté un commentaire : "${content.slice(0, 50)}${content.length > 50 ? "..." : ""}"`,
          taskId,
          daoId,
          data: { fromUser: user.name, priority: "normal" },
        });
      }
      await refreshNotifications();
    } catch (error) {
      // Rollback optimistic update on failure
      setComments((prev) => prev.filter((c) => c.id !== tempId));
      console.error("Error adding comment:", error);
      alert("Erreur lors de l'ajout du commentaire");
    } finally {
      setSubmitLoading(false);
    }
  };

  const handleDeleteComment = async (commentId: string) => {
    try {
      const idempotencyKey = `delete-comment:${commentId}:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
      await commentService.deleteComment(commentId, { idempotencyKey });
      setComments((prev) => prev.filter((c) => c.id !== commentId));
      await refreshNotifications();
    } catch (error) {
      console.error("Error deleting comment:", error);
      alert("Erreur lors de la suppression du commentaire");
    }
  };

  const handleTextareaChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    const position = e.target.selectionStart;

    setNewComment(value);
    setCursorPosition(position);

    // Detect @ mentions
    const textBeforeCursor = value.substring(0, position);
    const mentionMatch = textBeforeCursor.match(/@(\w*)$/);

    if (mentionMatch) {
      setMentionQuery(mentionMatch[1]);
      setShowSuggestions(true);
    } else {
      setShowSuggestions(false);
      setMentionQuery("");
    }
  };

  const handleMentionSelect = (memberName: string) => {
    const textBeforeCursor = newComment.substring(0, cursorPosition);
    const textAfterCursor = newComment.substring(cursorPosition);
    const mentionMatch = textBeforeCursor.match(/@(\w*)$/);

    if (mentionMatch) {
      const beforeMention = textBeforeCursor.substring(0, mentionMatch.index);
      const newText = beforeMention + `@${memberName} ` + textAfterCursor;
      setNewComment(newText);
      setShowSuggestions(false);
    }
  };

  const getFilteredMembers = () => {
    if (!mentionQuery) return availableMembers;
    return availableMembers.filter((member) =>
      member.name.toLowerCase().includes(mentionQuery.toLowerCase()),
    );
  };

  // Refresh avatars immediately if a profile photo was updated elsewhere
  useEffect(() => {
    const onAvatarUpdate = () => {
      // Trigger rerender; the getAvatarUrl reads localStorage so a rerender is enough
      setComments((prev) => [...prev]);
    };
    window.addEventListener("avatar-updated", onAvatarUpdate as EventListener);
    return () =>
      window.removeEventListener(
        "avatar-updated",
        onAvatarUpdate as EventListener,
      );
  }, []);

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours =
      Math.abs(now.getTime() - date.getTime()) / (1000 * 60 * 60);

    if (diffInHours < 1) {
      const diffInMinutes = Math.floor(diffInHours * 60);
      return `Il y a ${diffInMinutes} minute${diffInMinutes > 1 ? "s" : ""}`;
    } else if (diffInHours < 24) {
      const hours = Math.floor(diffInHours);
      return `Il y a ${hours} heure${hours > 1 ? "s" : ""}`;
    } else {
      return date.toLocaleDateString("fr-FR", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    }
  };

  if (!isExpanded) {
    // Build unique commenters list by latest comment order
    const seenUsers = new Set<string>();
    const uniqueCommenters = comments.filter((c) => {
      if (!c.userId) return false;
      if (seenUsers.has(c.userId)) return false;
      seenUsers.add(c.userId);
      return true;
    });
    const visible = uniqueCommenters.slice(0, 3);
    const extra = Math.max(uniqueCommenters.length - visible.length, 0);

    return (
      <div className="flex items-center justify-between">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            setIsExpanded(true);
            if (!comments.length) loadComments();
          }}
          onMouseEnter={() => {
            if (!isExpanded && !loading && !comments.length) loadComments();
          }}
          className="p-0 h-auto flex items-center"
        >
          <div className="flex items-center gap-2">
            <MessageSquare className="h-4 w-4 text-blue-600" />
            <span className="text-sm text-blue-600 hover:text-blue-700">
              {comments.length > 0
                ? extra > 0
                  ? `+${extra} commentaire${extra > 1 ? "s" : ""}`
                  : `${comments.length} commentaire${comments.length > 1 ? "s" : ""}`
                : "Commentaires"}
            </span>
            <div className="flex -space-x-2">
              {visible.map((c, idx) => (
                <Avatar
                  key={(c.userId || c.userName || String(idx)) + idx}
                  className="h-6 w-6 ring-2 ring-white dark:ring-gray-900 -ml-2 first:ml-0"
                >
                  <AvatarImage
                    src={getAvatarUrl(c.userId || c.userName, c.userName)}
                    alt={c.userName || "Utilisateur"}
                  />
                  <AvatarFallback className="text-[10px] bg-blue-100 text-blue-700">
                    {(c.userName?.charAt(0) || "?").toUpperCase()}
                  </AvatarFallback>
                </Avatar>
              ))}
            </div>
          </div>
        </Button>
        <div className="w-8 flex justify-center">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setIsExpanded(true);
              if (!comments.length) loadComments();
            }}
            onMouseEnter={() => {
              if (!isExpanded && !loading && !comments.length) loadComments();
            }}
            className="p-0 h-auto w-8 justify-center"
            aria-label="Ouvrir les commentaires"
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    );
  }

  return (
    <Card className="mt-3">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">
            <MessageSquare className="h-4 w-4 mr-2 inline" />
            Commentaires
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsExpanded(false)}
            className="h-6 w-6 p-0"
            aria-label="Replier les commentaires"
          >
            <ChevronDown className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Add new comment (hidden when showAddInput=false) */}
        {showAddInput && user && user.role !== "viewer" && (
          <div className="space-y-3">
            <div className="relative">
              <Textarea
                value={newComment}
                onChange={handleTextareaChange}
                placeholder="Ajouter un commentaire ou une observation... (utilisez @nom pour mentionner)"
                className="resize-none"
                rows={3}
              />
              {showSuggestions && getFilteredMembers().length > 0 && (
                <div className="absolute z-10 w-full mt-1 bg-white border rounded-md shadow-lg max-h-32 overflow-y-auto">
                  {getFilteredMembers()
                    .slice(0, 5)
                    .map((member) => (
                      <button
                        key={member.id}
                        onClick={() => handleMentionSelect(member.name)}
                        className="w-full px-3 py-2 text-left hover:bg-gray-100 focus:bg-gray-100 border-b last:border-b-0"
                      >
                        <div className="flex items-center space-x-2">
                          <Avatar className="h-6 w-6">
                            <AvatarImage
                              src={getAvatarUrl(
                                member.id || member.name,
                                member.name,
                              )}
                              alt={member.name}
                            />
                            <AvatarFallback className="text-[10px] bg-blue-100 text-blue-700">
                              {member.name.charAt(0)}
                            </AvatarFallback>
                          </Avatar>
                          <span className="text-sm">{member.name}</span>
                          <Badge variant="outline" className="text-xs">
                            {member.role === "chef_equipe" ? "Chef" : "Membre"}
                          </Badge>
                        </div>
                      </button>
                    ))}
                </div>
              )}
            </div>
            <div className="flex justify-between items-center">
              <p className="text-xs text-muted-foreground">
                Tapez @ pour mentionner un membre de l'équipe
              </p>
              <Button
                onClick={handleSubmitComment}
                disabled={!newComment.trim() || submitLoading}
                size="sm"
                className="bg-blue-600 hover:bg-blue-700"
              >
                <Send className="h-4 w-4 mr-2" />
                {submitLoading ? "Envoi..." : "Publier"}
              </Button>
            </div>
          </div>
        )}

        {loading ? (
          <div className="text-center py-4">
            <div className="animate-pulse">
              <div className="h-4 bg-gray-200 rounded mb-2"></div>
              <div className="h-4 bg-gray-200 rounded w-3/4 mx-auto"></div>
            </div>
            <p className="text-sm text-muted-foreground mt-2">
              Chargement des commentaires...
            </p>
          </div>
        ) : comments.length === 0 ? (
          <div className="text-center py-6">
            <MessageSquare className="h-8 w-8 text-gray-400 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">
              Aucun commentaire pour le moment.
            </p>
            {user && user.role === "viewer" && (
              <p className="text-xs text-muted-foreground mt-1">
                Vous n'avez pas l'autorisation d'ajouter des commentaires.
              </p>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            <Separator />
            <div className="flex items-center justify-between">
                <div />
              <Badge variant="secondary" className="text-xs">
                {comments.length} commentaire{comments.length > 1 ? "s" : ""}
              </Badge>
            </div>

            <div className="space-y-3 max-h-80 overflow-y-auto">
              {comments.map((comment) => (
                <div
                  key={comment.id}
                  className="border rounded-lg p-3 bg-gray-50"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Avatar className="h-6 w-6">
                          <AvatarImage
                            src={getAvatarUrl(
                              comment.userId || comment.userName,
                              comment.userName,
                            )}
                            alt={comment.userName || "Utilisateur"}
                          />
                          <AvatarFallback className="text-xs">
                            {comment.userName?.charAt(0) || "?"}
                          </AvatarFallback>
                        </Avatar>
                        <span className="text-sm font-medium text-gray-900">
                          {comment.userName}
                        </span>
                        <span className="text-xs text-gray-500 flex items-center">
                          <Calendar className="h-3 w-3 mr-1" />
                          {formatDate(comment.createdAt)}
                        </span>
                      </div>
                      <p className="text-sm text-gray-700 whitespace-pre-wrap">
                        {comment.content}
                      </p>
                    </div>
                    {user &&
                      (user.id === comment.userId || user.role === "admin") && (
                        <ConfirmationDialog
                          trigger={
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0 text-red-500 hover:text-red-700 hover:bg-red-50"
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          }
                          title="Supprimer le commentaire"
                          description="Êtes-vous sûr de vouloir supprimer ce commentaire ? Cette action est irréversible."
                          confirmText="Supprimer"
                          onConfirm={() => handleDeleteComment(comment.id)}
                          icon="trash"
                        />
                      )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
