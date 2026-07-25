import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

// ── Global auth-token injector ─────────────────────────────────────────────
// Automatically adds  Authorization: Bearer <token>  to every fetch() call
// so individual components don't need to know about authentication.
const _originalFetch = window.fetch.bind(window);
window.fetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> => {
  const token = localStorage.getItem("ax_auth_token");
  if (token) {
    const headers = new Headers(init?.headers);
    if (!headers.has("Authorization")) {
      headers.set("Authorization", `Bearer ${token}`);
    }
    return _originalFetch(input, { ...init, headers });
  }
  return _originalFetch(input, init);
};

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

const root = ReactDOM.createRoot(rootElement);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
