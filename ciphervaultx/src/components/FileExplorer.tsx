import * as React from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import {
  AlertTriangle,
  ArrowUp,
  Download,
  ExternalLink,
  Eye,
  FileArchive,
  FileText,
  Folder,
  FolderPlus,
  FolderUp,
  HardDrive,
  Lock,
  Pencil,
  Search,
  Trash2,
  Upload,
} from "lucide-react";
import {
  backend,
  isTauriRuntime,
  type MountInfo,
  type PreviewPayload,
  type VaultEntry,
  type VaultInfo,
} from "@/lib/api";
import { formatBytes, formatDate, joinPath, parentPath } from "@/lib/format";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Progress } from "./ui/progress";

type FilterKind = "all" | "images" | "documents";

interface TransferState {
  operation: string;
  done: number;
  total: number;
}

interface FileExplorerProps {
  vault: VaultInfo;
  transfer: TransferState | null;
  onLock: (vaultId: string) => void;
}

const IMAGE_EXTS = [".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"];
const DOC_EXTS = [".pdf", ".txt", ".md", ".doc", ".docx", ".csv", ".json"];

function matchesFilter(entry: VaultEntry, filter: FilterKind): boolean {
  if (filter === "all" || entry.kind !== "file") return true;
  const lower = entry.name.toLowerCase();
  if (filter === "images") return IMAGE_EXTS.some((e) => lower.endsWith(e));
  return DOC_EXTS.some((e) => lower.endsWith(e));
}

export const FileExplorer: React.FC<FileExplorerProps> = ({
  vault,
  transfer,
  onLock,
}) => {
  const [cwd, setCwd] = React.useState("/");
  const [entries, setEntries] = React.useState<VaultEntry[]>([]);
  const [searchQuery, setSearchQuery] = React.useState("");
  const [filter, setFilter] = React.useState<FilterKind>("all");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [preview, setPreview] = React.useState<{
    name: string;
    payload: PreviewPayload;
  } | null>(null);
  const [mountInfo, setMountInfo] = React.useState<MountInfo | null>(null);
  const [mounting, setMounting] = React.useState(false);
  const [dragActive, setDragActive] = React.useState(false);

  // Native React modals (100% compatible with iOS WKWebView & Android WebView — no window.prompt/confirm)
  const [newFolderOpen, setNewFolderOpen] = React.useState(false);
  const [newFolderName, setNewFolderName] = React.useState("");
  const [renameTarget, setRenameTarget] = React.useState<VaultEntry | null>(null);
  const [renameValue, setRenameValue] = React.useState("");
  const [deleteTarget, setDeleteTarget] = React.useState<VaultEntry | null>(null);
  const [modalBusy, setModalBusy] = React.useState(false);

  const loadDirectory = React.useCallback(
    async (targetPath: string) => {
      setLoading(true);
      setError(null);
      try {
        const list = await backend.listDir(vault.id, targetPath);
        setEntries(list);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(false);
      }
    },
    [vault.id]
  );

  React.useEffect(() => {
    setCwd("/");
    setSearchQuery("");
    setNotice(null);
    void backend.getMountInfo(vault.id).then(setMountInfo).catch(() => setMountInfo(null));
  }, [vault.id]);

  // Native Tauri 2 drag-and-drop for files and entire folders.
  React.useEffect(() => {
    if (!isTauriRuntime()) return;
    let unlisten: (() => void) | undefined;
    void getCurrentWebview()
      .onDragDropEvent(async (event) => {
        if (event.payload.type === "enter" || event.payload.type === "over") {
          setDragActive(true);
        } else if (event.payload.type === "leave") {
          setDragActive(false);
        } else if (event.payload.type === "drop") {
          setDragActive(false);
          const droppedPaths = event.payload.paths;
          if (!droppedPaths || droppedPaths.length === 0) return;
          setError(null);
          setNotice(null);
          try {
            await backend.importPaths(vault.id, droppedPaths, cwd);
            await loadDirectory(cwd);
          } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
          }
        }
      })
      .then((fn) => {
        unlisten = fn;
      });
    return () => {
      unlisten?.();
    };
  }, [vault.id, cwd, loadDirectory]);

  const handleMount = async () => {
    setMounting(true);
    setError(null);
    try {
      const info = await backend.mountVault(vault.id);
      setMountInfo(info);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setMounting(false);
    }
  };

  const handleUnmount = async () => {
    setError(null);
    try {
      await backend.unmountVault(vault.id);
      setMountInfo(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleRevealMount = async () => {
    setError(null);
    try {
      await backend.revealMount(vault.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  React.useEffect(() => {
    if (searchQuery.trim()) {
      let cancelled = false;
      setLoading(true);
      backend
        .searchVault(vault.id, searchQuery.trim())
        .then((res) => {
          if (!cancelled) setEntries(res);
        })
        .catch((err) => {
          if (!cancelled) setError(err instanceof Error ? err.message : String(err));
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
      return () => {
        cancelled = true;
      };
    }
    void loadDirectory(cwd);
    return undefined;
  }, [vault.id, cwd, searchQuery, loadDirectory]);

  const submitNewFolder = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newFolderName.trim();
    if (!trimmed) return;
    setModalBusy(true);
    setError(null);
    setNotice(null);
    try {
      await backend.createDir(vault.id, joinPath(cwd, trimmed));
      setNewFolderOpen(false);
      setNewFolderName("");
      await loadDirectory(cwd);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setModalBusy(false);
    }
  };

  const handleImportFiles = async () => {
    setError(null);
    setNotice(null);
    const paths = await backend.pickFilesToImport();
    if (paths.length === 0) return;
    try {
      const bytes = await backend.importPaths(vault.id, paths, cwd);
      setNotice(`Encrypted and imported ${paths.length} item(s) (${formatBytes(bytes)}).`);
      await loadDirectory(cwd);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleImportFolder = async () => {
    setError(null);
    setNotice(null);
    const folder = await backend.pickFolder("Select folder to encrypt into vault");
    if (!folder) return;
    try {
      const bytes = await backend.importPaths(vault.id, [folder], cwd);
      setNotice(`Encrypted and imported folder (${formatBytes(bytes)}).`);
      await loadDirectory(cwd);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleExport = async (entry: VaultEntry) => {
    setError(null);
    setNotice(null);
    const dst = await backend.pickExportDestination(entry.name);
    if (!dst) return;
    try {
      const bytes = await backend.exportFile(vault.id, entry.path, dst);
      setNotice(`Exported "${entry.name}" (${formatBytes(bytes)}) to ${dst}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleExportDir = async (entry: VaultEntry) => {
    setError(null);
    setNotice(null);
    const dstParent = await backend.pickFolder(`Select destination folder for "${entry.name}"`);
    if (!dstParent) return;
    try {
      const bytes = await backend.exportDir(vault.id, entry.path, dstParent);
      setNotice(`Exported folder "${entry.name}" (${formatBytes(bytes)}) into ${dstParent}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleExportDirZip = async (entry: VaultEntry) => {
    setError(null);
    setNotice(null);
    const dstZip = await backend.pickExportDestination(`${entry.name}.zip`);
    if (!dstZip) return;
    try {
      const res = await backend.exportDirAsZip(vault.id, entry.path, dstZip);
      setNotice(
        `Exported "${entry.name}" as ZIP (${res.entries} entries, ${formatBytes(res.bytes)}) to ${res.path}`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handlePreview = async (entry: VaultEntry) => {
    setError(null);
    try {
      const payload = await backend.previewFile(vault.id, entry.path);
      setPreview({ name: entry.name, payload });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const openRenameModal = (entry: VaultEntry) => {
    setRenameTarget(entry);
    setRenameValue(entry.name);
  };

  const submitRename = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!renameTarget) return;
    const next = renameValue.trim();
    if (!next || next === renameTarget.name) {
      setRenameTarget(null);
      return;
    }
    setModalBusy(true);
    setError(null);
    setNotice(null);
    try {
      await backend.renameEntry(vault.id, renameTarget.path, next);
      setRenameTarget(null);
      await loadDirectory(cwd);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setModalBusy(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setModalBusy(true);
    setError(null);
    setNotice(null);
    try {
      await backend.deleteEntry(vault.id, deleteTarget.path);
      setDeleteTarget(null);
      await loadDirectory(cwd);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setModalBusy(false);
    }
  };

  const crumbs = cwd.split("/").filter(Boolean);
  const visibleEntries = entries.filter((e) => matchesFilter(e, filter));
  const transferPct =
    transfer && transfer.total > 0
      ? Math.round((transfer.done / transfer.total) * 100)
      : 0;

  return (
    <div className="relative flex h-full flex-col">
      {dragActive && (
        <div className="pointer-events-none absolute inset-0 z-40 flex items-center justify-center bg-background/85 backdrop-blur-sm">
          <div className="rounded-xl border-2 border-dashed border-primary bg-card px-10 py-8 text-center shadow-lg">
            <Upload className="mx-auto mb-3 h-8 w-8 text-primary" />
            <p className="text-base font-semibold">Drop files or folders to encrypt</p>
            <p className="mt-1 font-mono text-xs text-muted-foreground">Destination: {cwd}</p>
          </div>
        </div>
      )}

      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3.5 md:px-6 md:py-4">
        <div className="min-w-0 space-y-0.5">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="truncate text-lg font-semibold tracking-tight">{vault.name}</h1>
            {vault.summary && <Badge variant="outline">{vault.summary.suite}</Badge>}
          </div>
          <nav
            className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground"
            aria-label="Breadcrumb"
          >
            <button
              type="button"
              className="hover:text-foreground"
              onClick={() => {
                setSearchQuery("");
                setCwd("/");
              }}
            >
              Root
            </button>
            {crumbs.map((part, idx) => {
              const pathTo = `/${crumbs.slice(0, idx + 1).join("/")}`;
              return (
                <React.Fragment key={pathTo}>
                  <span>/</span>
                  <button
                    type="button"
                    className="hover:text-foreground"
                    onClick={() => {
                      setSearchQuery("");
                      setCwd(pathTo);
                    }}
                  >
                    {part}
                  </button>
                </React.Fragment>
              );
            })}
          </nav>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
          {cwd !== "/" && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCwd(parentPath(cwd))}
              aria-label="Go to parent directory"
            >
              <ArrowUp className="h-4 w-4" />
              Up
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setNewFolderName("");
              setNewFolderOpen(true);
            }}
          >
            <FolderPlus className="h-4 w-4" />
            New Folder
          </Button>
          <Button variant="outline" size="sm" onClick={() => void handleImportFolder()}>
            <FolderUp className="h-4 w-4" />
            Import Folder
          </Button>
          <Button size="sm" onClick={() => void handleImportFiles()}>
            <Upload className="h-4 w-4" />
            Import Files
          </Button>
          <Button variant="secondary" size="sm" onClick={() => onLock(vault.id)}>
            <Lock className="h-4 w-4" />
            Lock
          </Button>
        </div>
      </header>

      <div className="hidden flex-wrap items-center justify-between gap-3 border-b border-border bg-card/70 px-6 py-2.5 text-xs md:flex">
        <div className="flex min-w-0 items-center gap-2">
          <HardDrive className="h-4 w-4 shrink-0 text-primary" />
          {mountInfo ? (
            <div className="flex min-w-0 items-center gap-2">
              <span className="font-medium text-foreground">Virtual Drive:</span>
              <code className="truncate rounded bg-background px-2 py-0.5 font-mono text-foreground">
                {mountInfo.mount_point}
              </code>
              <span className="hidden text-muted-foreground sm:inline">
                (auto-unmounts on lock)
              </span>
            </div>
          ) : (
            <span className="text-muted-foreground">
              Drag &amp; drop files/folders anywhere below, or mount a desktop virtual drive.
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {mountInfo ? (
            <>
              <Button variant="outline" size="sm" onClick={() => void handleRevealMount()}>
                <ExternalLink className="h-3.5 w-3.5" />
                Open Drive
              </Button>
              <Button variant="ghost" size="sm" onClick={() => void handleUnmount()}>
                Unmount
              </Button>
            </>
          ) : (
            <Button variant="outline" size="sm" disabled={mounting} onClick={() => void handleMount()}>
              <HardDrive className="h-3.5 w-3.5" />
              {mounting ? "Mounting…" : "Mount Virtual Drive"}
            </Button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2.5 border-b border-border bg-card/40 px-4 py-2.5 md:px-6 md:py-3">
        <div className="relative min-w-[180px] flex-1 max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            className="pl-8"
            placeholder="Search decrypted names…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-1.5">
          {(["all", "images", "documents"] as const).map((f) => (
            <Button
              key={f}
              size="sm"
              variant={filter === f ? "secondary" : "ghost"}
              onClick={() => setFilter(f)}
            >
              {f === "all" ? "All" : f === "images" ? "Images" : "Documents"}
            </Button>
          ))}
        </div>
      </div>

      {transfer && (
        <div className="border-b border-border bg-card px-4 py-3 md:px-6">
          <div className="mb-1 flex items-center justify-between text-xs text-muted-foreground">
            <span className="capitalize">{transfer.operation} in progress…</span>
            <span>
              {formatBytes(transfer.done)} / {formatBytes(transfer.total)} ({transferPct}%)
            </span>
          </div>
          <Progress value={transferPct} />
        </div>
      )}

      {error && (
        <div className="border-b border-destructive/40 bg-destructive/10 px-4 py-3 text-xs text-destructive md:px-6 md:text-sm">
          {error}
        </div>
      )}

      {notice && (
        <div className="flex items-center justify-between gap-2 border-b border-primary/30 bg-primary/10 px-4 py-2.5 text-xs text-primary md:px-6">
          <span className="break-all">{notice}</span>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="shrink-0 font-medium underline"
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto px-3 py-3 md:px-6 md:py-4">
        {loading ? (
          <p className="py-12 text-center text-sm text-muted-foreground">Decrypting listing…</p>
        ) : visibleEntries.length === 0 ? (
          <div className="my-6 rounded-lg border border-dashed border-border p-8 text-center md:p-12">
            <Upload className="mx-auto mb-2 h-6 w-6 text-muted-foreground" />
            <p className="text-sm font-medium">
              {searchQuery ? "No matching entries." : "This folder is empty"}
            </p>
            {!searchQuery && (
              <p className="mt-1 text-xs text-muted-foreground">
                Drag &amp; drop files or folders here, or use Import Files / Import Folder above.
              </p>
            )}
          </div>
        ) : (
          <div className="divide-y divide-border rounded-xl border border-border bg-card/70">
            {visibleEntries.map((entry) => (
              <div
                key={entry.path}
                className="flex flex-col gap-2 px-3 py-2.5 transition-colors hover:bg-accent/30 sm:flex-row sm:items-center sm:justify-between sm:gap-3 md:px-4"
              >
                <div className="min-w-0 flex-1">
                  {entry.kind === "directory" ? (
                    <button
                      type="button"
                      className="flex max-w-full items-center gap-2 text-left text-sm font-medium hover:underline"
                      onClick={() => {
                        setSearchQuery("");
                        setCwd(entry.path);
                      }}
                    >
                      <Folder className="h-4 w-4 shrink-0 text-primary" />
                      <span className="truncate">{entry.name}</span>
                    </button>
                  ) : entry.kind === "unreadable" ? (
                    <div className="flex items-center gap-2 text-destructive">
                      <AlertTriangle className="h-4 w-4 shrink-0" />
                      <span className="truncate font-mono text-xs">{entry.name}</span>
                      <Badge variant="destructive">Unreadable</Badge>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 text-sm">
                      <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <span className="truncate">{entry.name}</span>
                    </div>
                  )}
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 pl-6 text-[11px] text-muted-foreground">
                    <span>{entry.kind === "file" ? formatBytes(entry.size) : "Folder"}</span>
                    <span>{formatDate(entry.modified_ms)}</span>
                  </div>
                </div>

                {entry.kind !== "unreadable" && (
                  <div className="flex flex-wrap items-center justify-end gap-1 sm:shrink-0">
                    {entry.kind === "directory" && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 px-2 text-xs"
                          title={`Export folder "${entry.name}"`}
                          aria-label={`Export folder ${entry.name}`}
                          onClick={() => void handleExportDir(entry)}
                        >
                          <Download className="h-3.5 w-3.5" />
                          <span className="sm:hidden lg:inline">Export</span>
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 px-2 text-xs"
                          title={`Export "${entry.name}" as .zip`}
                          aria-label={`Export ${entry.name} as zip`}
                          onClick={() => void handleExportDirZip(entry)}
                        >
                          <FileArchive className="h-3.5 w-3.5" />
                          <span className="sm:hidden lg:inline">.zip</span>
                        </Button>
                      </>
                    )}
                    {entry.kind === "file" && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 px-2 text-xs"
                          aria-label={`Preview ${entry.name}`}
                          onClick={() => void handlePreview(entry)}
                        >
                          <Eye className="h-3.5 w-3.5" />
                          <span className="sm:hidden lg:inline">View</span>
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 px-2 text-xs"
                          aria-label={`Export ${entry.name}`}
                          onClick={() => void handleExport(entry)}
                        >
                          <Download className="h-3.5 w-3.5" />
                          <span className="sm:hidden lg:inline">Export</span>
                        </Button>
                      </>
                    )}
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      aria-label={`Rename ${entry.name}`}
                      onClick={() => openRenameModal(entry)}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      aria-label={`Delete ${entry.name}`}
                      onClick={() => setDeleteTarget(entry)}
                    >
                      <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Native React Modal: New Folder */}
      <Dialog open={newFolderOpen} onOpenChange={(o) => !modalBusy && setNewFolderOpen(o)}>
        <DialogContent className="max-w-md">
          <form onSubmit={(e) => void submitNewFolder(e)} noValidate>
            <DialogHeader>
              <DialogTitle>New Encrypted Folder</DialogTitle>
              <DialogDescription>
                Create a subfolder inside <code className="font-mono">{cwd}</code>.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-1.5">
              <Label htmlFor="fe-new-folder-name">Folder Name</Label>
              <Input
                id="fe-new-folder-name"
                value={newFolderName}
                onChange={(e) => setNewFolderName(e.target.value)}
                placeholder="Documents"
                autoFocus
                disabled={modalBusy}
              />
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setNewFolderOpen(false)}
                disabled={modalBusy}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={modalBusy || !newFolderName.trim()}>
                {modalBusy ? "Creating…" : "Create Folder"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Native React Modal: Rename Entry */}
      <Dialog open={Boolean(renameTarget)} onOpenChange={(o) => !o && !modalBusy && setRenameTarget(null)}>
        <DialogContent className="max-w-md">
          <form onSubmit={(e) => void submitRename(e)} noValidate>
            <DialogHeader>
              <DialogTitle>Rename Entry</DialogTitle>
              <DialogDescription>
                Enter a new encrypted filename for{" "}
                <strong className="break-all">{renameTarget?.name}</strong>.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-1.5">
              <Label htmlFor="fe-rename-input">New Name</Label>
              <Input
                id="fe-rename-input"
                value={renameValue}
                onChange={(e) => setRenameValue(e.target.value)}
                autoFocus
                disabled={modalBusy}
              />
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setRenameTarget(null)}
                disabled={modalBusy}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={modalBusy || !renameValue.trim()}>
                {modalBusy ? "Renaming…" : "Rename"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Native React Modal: Delete Confirmation */}
      <Dialog open={Boolean(deleteTarget)} onOpenChange={(o) => !o && !modalBusy && setDeleteTarget(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Delete Permanently?</DialogTitle>
            <DialogDescription>
              Permanently delete <strong className="break-all">{deleteTarget?.name}</strong> from
              this vault? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setDeleteTarget(null)}
              disabled={modalBusy}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={() => void confirmDelete()}
              disabled={modalBusy}
            >
              {modalBusy ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* In-Memory Preview Modal */}
      <Dialog open={Boolean(preview)} onOpenChange={(o) => !o && setPreview(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="break-all">{preview?.name}</DialogTitle>
            <DialogDescription>
              Decrypted in memory only. No plaintext file was written to disk.
            </DialogDescription>
          </DialogHeader>
          {preview && (
            <div className="max-h-[60vh] overflow-auto rounded-md border border-border bg-background p-4">
              {preview.payload.mime.startsWith("image/") ? (
                <img
                  src={`data:${preview.payload.mime};base64,${preview.payload.base64}`}
                  alt={preview.name}
                  className="mx-auto max-h-[52vh] object-contain"
                />
              ) : preview.payload.mime === "text/plain" ? (
                <pre className="whitespace-pre-wrap font-mono text-xs">
                  {atob(preview.payload.base64)}
                </pre>
              ) : (
                <p className="text-sm text-muted-foreground">
                  Binary preview unavailable ({preview.payload.mime},{" "}
                  {formatBytes(preview.payload.size)}). Use Export to write a decrypted copy outside
                  the vault.
                </p>
              )}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setPreview(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};
