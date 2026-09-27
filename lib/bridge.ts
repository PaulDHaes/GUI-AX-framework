// In production builds (`vite build`), import.meta.env.PROD is true and nginx
// proxies /api/ → the bridge on 127.0.0.1:5000, so we use relative paths.
// In development (`vite`), we talk directly to the Flask bridge on port 5000.
export const BRIDGE_BASE: string = import.meta.env.PROD ? "" : "http://localhost:5000";
