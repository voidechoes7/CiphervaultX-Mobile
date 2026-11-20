import * as React from "react";
import {
  AlertTriangle,
  ArrowUp,
  Download,
  ExternalLink,
  Eye,
  FileText,
  Folder,
  FolderPlus,
  HardDrive,
  Lock,
  Pencil,
  Search,
  Trash2,
  Upload,
} from "lucide-react";
import {
  backend,
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
  const [preview, setPreview] = React.useState<{
    name: string;
    payload: PreviewPayload;
  } | null>(null);
  const [mountInfo, setMountInfo] = React.useState<MountInfo | null>(null);
  const [mounting, setMounting] = React.useState(false);

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
    void backend.getMountInfo(vault.id).then(setMountInfo).catch(() => setMountInfo(null));
  }, [vault.id]);

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

  const handleNewFolder = async () => {
    const name = window.prompt("New folder name");
    if (!name || !name.trim()) return;
    setError(null);
    try {
      await backend.createDir(vault.id, joinPath(cwd, name.trim()));
      await loadDirectory(cwd);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleImport = async () => {
    setError(null);
    const src = await backend.pickFileToImport();
    if (!src) return;
    const baseName = src.split(/[\\/]/).pop();
    if (!baseName) return;
    try {
      await backend.importFile(vault.id, src, joinPath(cwd, baseName));
      await loadDirectory(cwd);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleExport = async (entry: VaultEntry) => {
    setError(null);
    const dst = await backend.pickExportDestination(entry.name);
    if (!dst) return;
    try {
      await backend.exportFile(vault.id, entry.path, dst);
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

  const handleRename = async (entry: VaultEntry) => {
    const next = window.prompt("Rename entry", entry.name);
    if (!next || !next.trim() || next.trim() === entry.name) return;
    setError(null);
    try {
      await backend.renameEntry(vault.id, entry.path, next.trim());
      await loadDirectory(cwd);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleDelete = async (entry: VaultEntry) => {
    if (!window.confirm(`Permanently delete "${entry.name}" from this vault?`)) return;
    setError(null);
    try {
      await backend.deleteEntry(vault.id, entry.path);
      await loadDirectory(cwd);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const crumbs = cwd.split("/").filter(Boolean);
  const visibleEntries = entries.filter((e) => matchesFilter(e, filter));
  const transferPct =
    transfer && transfer.total > 0
      ? Math.round((transfer.done / transfer.total) * 100)
      : 0;

  return (
    <div className="flex h-full flex-col">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-6 py-4">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight">{vault.name}</h1>
            {vault.summary && <Badge variant="outline">{vault.summary.suite}</Badge>}
          </div>
          <nav className="flex items-center gap-1 text-xs text-muted-foreground" aria-label="Breadcrumb">
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

        <div className="flex items-center gap-2">
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
          <Button variant="outline" size="sm" onClick={handleNewFolder}>
            <FolderPlus className="h-4 w-4" />
            New Folder
          </Button>
          <Button size="sm" onClick={handleImport}>
            <Upload className="h-4 w-4" />
            Import
          </Button>
          <Button variant="secondary" size="sm" onClick={() => onLock(vault.id)}>
            <Lock className="h-4 w-4" />
            Lock
          </Button>
        </div>
      </header>

      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-card/70 px-6 py-2.5 text-xs">
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
              Mount a local loopback virtual drive to drag &amp; drop files directly from Explorer.
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {mountInfo ? (
            <>
              <Button variant="outline" size="sm" onClick={handleRevealMount}>
                <ExternalLink className="h-3.5 w-3.5" />
                Open Drive
              </Button>
              <Button variant="ghost" size="sm" onClick={handleUnmount}>
                Unmount
              </Button>
            </>
          ) : (
            <Button variant="outline" size="sm" disabled={mounting} onClick={handleMount}>
              <HardDrive className="h-3.5 w-3.5" />
              {mounting ? "Mounting…" : "Mount Virtual Drive"}
            </Button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-card/40 px-6 py-3">
        <div className="relative w-full max-w-xs">
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
        <div className="border-b border-border bg-card px-6 py-3">
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
        <div className="border-b border-destructive/40 bg-destructive/10 px-6 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <div className="flex-1 overflow-y-auto px-6 py-4">
        {loading ? (
          <p className="py-12 text-center text-sm text-muted-foreground">Decrypting listing…</p>
        ) : visibleEntries.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            {searchQuery ? "No matching entries." : "This folder is empty."}
          </p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
                <th className="py-2 font-medium">Name</th>
                <th className="py-2 font-medium">Size</th>
                <th className="py-2 font-medium">Modified</th>
                <th className="py-2 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {visibleEntries.map((entry) => (
                <tr key={entry.path} className="hover:bg-accent/30">
                  <td className="py-2.5 pr-4">
                    {entry.kind === "directory" ? (
                      <button
                        type="button"
                        className="flex items-center gap-2 font-medium hover:underline"
                        onClick={() => {
                          setSearchQuery("");
                          setCwd(entry.path);
                        }}
                      >
                        <Folder className="h-4 w-4 text-primary" />
                        <span>{entry.name}</span>
                      </button>
                    ) : entry.kind === "unreadable" ? (
                      <div className="flex items-center gap-2 text-destructive">
                        <AlertTriangle className="h-4 w-4 shrink-0" />
                        <span className="truncate font-mono text-xs">{entry.name}</span>
                        <Badge variant="destructive">Unreadable</Badge>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2">
                        <FileText className="h-4 w-4 text-muted-foreground" />
                        <span>{entry.name}</span>
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 text-xs text-muted-foreground">
                    {entry.kind === "file" ? formatBytes(entry.size) : "—"}
                  </td>
                  <td className="py-2.5 text-xs text-muted-foreground">
                    {formatDate(entry.modified_ms)}
                  </td>
                  <td className="py-2.5 text-right">
                    {entry.kind !== "unreadable" && (
                      <div className="inline-flex items-center gap-1">
                        {entry.kind === "file" && (
                          <>
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={`Preview ${entry.name}`}
                              onClick={() => handlePreview(entry)}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={`Export ${entry.name}`}
                              onClick={() => handleExport(entry)}
                            >
                              <Download className="h-4 w-4" />
                            </Button>
                          </>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Rename ${entry.name}`}
                          onClick={() => handleRename(entry)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Delete ${entry.name}`}
                          onClick={() => handleDelete(entry)}
                        >
                          <Trash2 className="h-4 w-4 text-muted-foreground" />
                        </Button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <Dialog open={Boolean(preview)} onOpenChange={(o) => !o && setPreview(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{preview?.name}</DialogTitle>
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
