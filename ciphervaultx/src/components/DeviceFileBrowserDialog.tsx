import * as React from "react";
import {
  ArrowUp,
  Check,
  FileText,
  Folder,
  FolderPlus,
  HardDrive,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  backend,
  hasAndroidAllFilesAccess,
  hasAndroidStorageBridge,
  requestAndroidAllFilesAccess,
  type DevicePickerRequest,
  type HostDirEntry,
  type HostDirListing,
  type StorageRoot,
} from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";
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

interface DeviceFileBrowserDialogProps {
  request: DevicePickerRequest | null;
  onResolve: (paths: string[] | null) => void;
}

export const DeviceFileBrowserDialog: React.FC<DeviceFileBrowserDialogProps> = ({
  request,
  onResolve,
}) => {
  const [roots, setRoots] = React.useState<StorageRoot[]>([]);
  const [currentPath, setCurrentPath] = React.useState("");
  const [listing, setListing] = React.useState<HostDirListing | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [selectedFiles, setSelectedFiles] = React.useState<string[]>([]);
  const [saveFileName, setSaveFileName] = React.useState("");
  const [creatingFolder, setCreatingFolder] = React.useState(false);
  const [newFolderName, setNewFolderName] = React.useState("");
  const [allFilesGranted, setAllFilesGranted] = React.useState(false);

  const hasBridge = hasAndroidStorageBridge();

  const refreshPermissionState = React.useCallback(() => {
    setAllFilesGranted(hasAndroidAllFilesAccess());
  }, []);

  const loadDir = React.useCallback(async (targetPath: string) => {
    setLoading(true);
    setError(null);
    setCurrentPath(targetPath);
    try {
      const res = await backend.listHostDir(targetPath);
      setListing(res);
    } catch (err) {
      setListing(null);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadRootsAndInitial = React.useCallback(
    async (req: DevicePickerRequest, preferredPath?: string) => {
      refreshPermissionState();
      setLoading(true);
      setError(null);
      try {
        const list = await backend.listStorageRoots();
        setRoots(list);

        const initial =
          preferredPath ||
          req.initialPath ||
          (req.mode === "save"
            ? list.find((r) => r.kind === "downloads" && r.readable)?.path ||
              list.find((r) => r.kind === "app-exports")?.path
            : req.highlightVaults === "cvz" || req.highlightVaults === "cryptomator"
            ? list.find((r) => r.kind === "internal" && r.readable)?.path ||
              list.find((r) => r.kind === "app-vaults")?.path
            : req.mode === "file" || req.mode === "files"
            ? list.find((r) => r.kind === "internal" && r.readable)?.path ||
              list.find((r) => r.kind === "downloads" && r.readable)?.path ||
              list.find((r) => r.readable)?.path
            : list.find((r) => r.kind === "app-vaults")?.path) ||
          list.find((r) => r.readable)?.path ||
          list[0]?.path ||
          "";

        if (initial) {
          await loadDir(initial);
        } else {
          setLoading(false);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        setLoading(false);
      }
    },
    [loadDir, refreshPermissionState]
  );

  React.useEffect(() => {
    if (!request) {
      setSelectedFiles([]);
      setCreatingFolder(false);
      setNewFolderName("");
      setError(null);
      return;
    }
    setSelectedFiles([]);
    setCreatingFolder(false);
    setNewFolderName(request.suggestedSubfolder || "");
    setSaveFileName(request.defaultFileName || "exported_file");
    void loadRootsAndInitial(request);
  }, [request, loadRootsAndInitial]);

  // Automatically reload storage roots & current folder when user returns from Android Settings
  React.useEffect(() => {
    if (!request) return;
    const handleResume = () => {
      refreshPermissionState();
      void loadRootsAndInitial(request, currentPath || undefined);
    };
    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        handleResume();
      }
    };
    window.addEventListener("android-storage-resumed", handleResume);
    document.addEventListener("visibilitychange", handleVisibility);
    return () => {
      window.removeEventListener("android-storage-resumed", handleResume);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [request, currentPath, loadRootsAndInitial, refreshPermissionState]);

  if (!request) return null;

  const isFolderMode = request.mode === "folder";
  const isSaveMode = request.mode === "save";
  const isFileMode = request.mode === "file" || request.mode === "files";

  const needsStoragePermission =
    (hasBridge && !allFilesGranted) ||
    roots.some((r) => (r.kind === "internal" || r.kind === "sdcard") && !r.readable);

  const handleGrantStorageAccess = () => {
    requestAndroidAllFilesAccess();
  };

  const handleCreateSubfolder = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newFolderName.trim();
    if (!trimmed || !currentPath) return;
    setError(null);
    try {
      const createdPath = await backend.createHostDir(currentPath, trimmed);
      setCreatingFolder(false);
      setNewFolderName("");
      await loadDir(createdPath);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleEntryClick = (entry: HostDirEntry) => {
    if (entry.is_dir) {
      void loadDir(entry.path);
      return;
    }
    if (request.mode === "file") {
      onResolve([entry.path]);
      return;
    }
    if (request.mode === "files") {
      setSelectedFiles((prev) =>
        prev.includes(entry.path) ? prev.filter((p) => p !== entry.path) : [...prev, entry.path]
      );
    }
  };

  const handleConfirm = () => {
    if (isFolderMode) {
      if (!currentPath) return;
      onResolve([currentPath]);
      return;
    }
    if (isSaveMode) {
      const cleanName = saveFileName.trim();
      if (!currentPath || !cleanName) return;
      const sep = currentPath.endsWith("/") ? "" : "/";
      onResolve([`${currentPath}${sep}${cleanName}`]);
      return;
    }
    if (selectedFiles.length > 0) {
      onResolve(selectedFiles);
    }
  };

  const visibleEntries = (listing?.entries ?? []).filter((entry) =>
    isFolderMode || isSaveMode ? entry.is_dir : true
  );

  return (
    <Dialog open={Boolean(request)} onOpenChange={(open) => !open && onResolve(null)}>
      <DialogContent className="flex max-h-[92dvh] max-w-2xl flex-col gap-3 overflow-hidden p-4 sm:p-5">
        <DialogHeader className="mb-0 shrink-0">
          <DialogTitle className="flex items-center gap-2 text-base sm:text-lg">
            <HardDrive className="h-5 w-5 shrink-0 text-primary" />
            <span className="truncate">{request.title}</span>
          </DialogTitle>
          <DialogDescription className="text-xs">
            {isFolderMode
              ? request.requireEmptyFolder
                ? "Navigate to a storage location and select an empty folder (or tap New Folder)."
                : "Browse device folders or App Storage, then tap Select."
              : isSaveMode
              ? "Choose a destination folder and filename for the decrypted export."
              : "Browse device storage and select files to import."}
          </DialogDescription>
        </DialogHeader>

        {/* Storage root shortcuts */}
        <div className="flex shrink-0 flex-wrap gap-1.5">
          {roots.map((root) => {
            const active = currentPath === root.path || currentPath.startsWith(`${root.path}/`);
            return (
              <button
                key={root.path}
                type="button"
                onClick={() => void loadDir(root.path)}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
                  active
                    ? "border-primary bg-primary/15 text-primary"
                    : "border-border bg-card/80 text-muted-foreground hover:border-primary/40 hover:text-foreground"
                )}
              >
                {!root.readable && <Lock className="h-3 w-3 text-amber-500" />}
                <span>{root.label}</span>
              </button>
            );
          })}
        </div>

        {/* Android All Files Access banner */}
        {needsStoragePermission && (
          <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs">
            <div className="flex min-w-0 flex-1 items-start gap-2">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
              <span className="text-foreground/90">
                To browse Android Internal Storage (<code>/storage/emulated/0</code>), enable{" "}
                <strong>All files access</strong> in Android Settings.
              </span>
            </div>
            {hasBridge && (
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 shrink-0 border-amber-500/50 text-xs"
                onClick={handleGrantStorageAccess}
              >
                Grant Storage Access
              </Button>
            )}
          </div>
        )}

        {/* Path toolbar */}
        <div className="flex shrink-0 items-center gap-1.5 rounded-lg border border-border bg-muted/40 px-2 py-1.5">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-7 w-7 shrink-0"
            disabled={!listing?.parent || loading}
            onClick={() => listing?.parent && void loadDir(listing.parent)}
            aria-label="Up one folder"
          >
            <ArrowUp className="h-4 w-4" />
          </Button>
          <div className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground">
            {currentPath || "Select a storage root"}
          </div>
          {(isFolderMode || isSaveMode) && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-7 shrink-0 px-2 text-xs"
              disabled={!currentPath || loading}
              onClick={() => setCreatingFolder((prev) => !prev)}
            >
              <FolderPlus className="h-3.5 w-3.5" />
              New Folder
            </Button>
          )}
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-7 w-7 shrink-0"
            disabled={loading || !currentPath}
            onClick={() => void loadRootsAndInitial(request, currentPath)}
            aria-label="Refresh directory"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          </Button>
        </div>

        {/* Inline New Folder form */}
        {creatingFolder && (
          <form
            onSubmit={(e) => void handleCreateSubfolder(e)}
            className="flex shrink-0 items-center gap-2 rounded-lg border border-primary/40 bg-primary/5 p-2"
          >
            <Input
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              placeholder="New folder name (e.g. PersonalVault)"
              className="h-8 text-xs"
              autoFocus
            />
            <Button type="submit" size="sm" className="h-8 shrink-0" disabled={!newFolderName.trim()}>
              Create
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-8 shrink-0"
              onClick={() => setCreatingFolder(false)}
            >
              Cancel
            </Button>
          </form>
        )}

        {/* Error banner */}
        {error && (
          <div className="shrink-0 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}

        {/* Current folder status badge for New Vault / Existing Vault */}
        {listing && isFolderMode && (
          <div className="flex shrink-0 flex-wrap items-center gap-2 text-xs">
            {listing.is_cvz_vault && (
              <Badge variant="default" className="gap-1">
                <ShieldCheck className="h-3 w-3" />
                CVZ v1 Vault Detected Here
              </Badge>
            )}
            {listing.is_cryptomator_vault && (
              <Badge variant="default" className="gap-1">
                <ShieldCheck className="h-3 w-3" />
                Cryptomator Vault Detected Here
              </Badge>
            )}
            {request.requireEmptyFolder && !listing.is_empty && (
              <span className="text-amber-500">
                This folder is not empty — tap <strong>New Folder</strong> to create an empty
                subfolder for your new vault.
              </span>
            )}
            {request.requireEmptyFolder && listing.is_empty && (
              <Badge variant="secondary" className="gap-1">
                <Check className="h-3 w-3" />
                Empty folder ready for new vault
              </Badge>
            )}
          </div>
        )}

        {/* Scrollable directory listing */}
        <div className="min-h-[180px] flex-1 overflow-y-auto rounded-lg border border-border bg-card/60">
          {loading ? (
            <div className="flex h-36 items-center justify-center text-xs text-muted-foreground">
              Loading directory…
            </div>
          ) : visibleEntries.length === 0 ? (
            <div className="flex h-36 flex-col items-center justify-center gap-1 px-4 text-center text-xs text-muted-foreground">
              <span>{isFolderMode || isSaveMode ? "No subfolders here." : "This folder is empty."}</span>
              {request.requireEmptyFolder && (
                <span className="text-primary">You can select this empty folder directly.</span>
              )}
            </div>
          ) : (
            <div className="divide-y divide-border/60">
              {visibleEntries.map((entry) => {
                const isSelected = selectedFiles.includes(entry.path);
                const highlightMatch =
                  (request.highlightVaults === "cvz" && entry.is_cvz_vault) ||
                  (request.highlightVaults === "cryptomator" && entry.is_cryptomator_vault);
                return (
                  <div
                    key={entry.path}
                    className={cn(
                      "flex items-center justify-between gap-2 px-3 py-2.5 text-sm transition-colors",
                      isSelected ? "bg-primary/15" : "hover:bg-accent/50"
                    )}
                  >
                    <button
                      type="button"
                      className="flex min-w-0 flex-1 items-center gap-2.5 text-left"
                      onClick={() => handleEntryClick(entry)}
                    >
                      {entry.is_dir ? (
                        <Folder
                          className={cn(
                            "h-4 w-4 shrink-0",
                            highlightMatch ? "text-primary" : "text-amber-500"
                          )}
                        />
                      ) : (
                        <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
                      )}
                      <div className="min-w-0 flex-1">
                        <div className="truncate font-medium">{entry.name}</div>
                        {!entry.is_dir && (
                          <div className="text-[11px] text-muted-foreground">
                            {formatBytes(entry.size)}
                          </div>
                        )}
                      </div>
                      {entry.is_cvz_vault && (
                        <Badge variant="default" className="shrink-0 text-[10px]">
                          CVZ Vault
                        </Badge>
                      )}
                      {entry.is_cryptomator_vault && (
                        <Badge variant="secondary" className="shrink-0 text-[10px]">
                          Cryptomator
                        </Badge>
                      )}
                    </button>

                    {isFolderMode && entry.is_dir && highlightMatch && (
                      <Button
                        type="button"
                        size="sm"
                        className="h-7 shrink-0 px-2.5 text-xs"
                        onClick={() => onResolve([entry.path])}
                      >
                        Select
                      </Button>
                    )}

                    {isFileMode && !entry.is_dir && isSelected && (
                      <Check className="h-4 w-4 shrink-0 text-primary" />
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Save filename input */}
        {isSaveMode && (
          <div className="shrink-0 space-y-1">
            <Label htmlFor="device-save-name" className="text-xs">
              File Name
            </Label>
            <Input
              id="device-save-name"
              value={saveFileName}
              onChange={(e) => setSaveFileName(e.target.value)}
              className="h-9 font-mono text-xs"
            />
          </div>
        )}

        <DialogFooter className="mt-1 shrink-0 flex-wrap gap-2">
          <Button type="button" variant="ghost" onClick={() => onResolve(null)}>
            Cancel
          </Button>
          {isFolderMode && (
            <Button
              type="button"
              disabled={!currentPath || Boolean(error)}
              onClick={handleConfirm}
            >
              <Check className="h-4 w-4" />
              Select This Folder
            </Button>
          )}
          {isSaveMode && (
            <Button
              type="button"
              disabled={!currentPath || !saveFileName.trim() || Boolean(error)}
              onClick={handleConfirm}
            >
              <Check className="h-4 w-4" />
              Save Here
            </Button>
          )}
          {request.mode === "files" && (
            <Button
              type="button"
              disabled={selectedFiles.length === 0}
              onClick={handleConfirm}
            >
              <Check className="h-4 w-4" />
              Import {selectedFiles.length} {selectedFiles.length === 1 ? "File" : "Files"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
