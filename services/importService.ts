// Frontend helper to upload scanner files to an ax backend.
// Usage: import { uploadScannerFile } from './importService';

// Simple fixed backend URL used when running frontend alongside the ax backend.
// If you host ax elsewhere, change this constant.
const AX_BASE = "http://localhost:8000";

async function tryUpload(form: FormData, paths: string[]) {
  for (const p of paths) {
    try {
      const res = await fetch(`${AX_BASE}${p}`, { method: "POST", body: form });
      if (res.ok) return await safeJson(res);
    } catch (e) {
      // ignore and try next
    }
  }
  throw new Error("No import endpoint accepted the file");
}

async function safeJson(res: Response) {
  try {
    return await res.json();
  } catch (e) {
    return {};
  }
}

export async function uploadScannerFile(file: File): Promise<any> {
  const endpoints = [
    "/api/import",
    "/import",
    "/api/uploads",
    "/uploads",
    "/api/files/import",
    "/",
  ];
  const f = new FormData();
  f.append("file", file, file.name);
  f.append("filename", file.name);
  if (file.name.toLowerCase().includes("amass")) f.append("scanner", "amass");
  if (file.name.toLowerCase().includes("nmap")) f.append("scanner", "nmap");
  return tryUpload(f, endpoints);
}

export default { uploadScannerFile };
