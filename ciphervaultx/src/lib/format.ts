export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, idx);
  return `${idx === 0 ? value : value.toFixed(value >= 100 ? 0 : 1)} ${units[idx]}`;
}

export function formatDate(ms: number): string {
  if (!ms) return "—";
  return new Date(ms).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function parentPath(path: string): string {
  const clean = path.replace(/\/+$/, "");
  if (!clean || clean === "/") return "/";
  const idx = clean.lastIndexOf("/");
  if (idx <= 0) return "/";
  return clean.slice(0, idx);
}

export function joinPath(base: string, name: string): string {
  const cleanBase = base.replace(/\/+$/, "");
  const cleanName = name.replace(/^\/+/, "");
  if (!cleanBase || cleanBase === "/") {
    return `/${cleanName}`;
  }
  return `${cleanBase}/${cleanName}`;
}
