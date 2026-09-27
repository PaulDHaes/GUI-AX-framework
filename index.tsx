import React from "react";
import ReactDOM from "react-dom/client";
import "./globals.css";
import App from "./App";
import { getTheme, applyTheme } from "./services/prefs";

// Catch ALL uncaught JS errors and show them instead of black screen
window.addEventListener("error", function(ev) {
  document.body.innerHTML = "<pre style=\"color:#f87171;background:#0a0a0a;padding:2rem;font-family:monospace;white-space:pre-wrap;font-size:13px\">UNCAUGHT ERROR:\n" + ev.message + "\n\n" + (ev.filename ? ev.filename + ":" + ev.lineno : "") + "</pre>";
});
window.addEventListener("unhandledrejection", function(ev) {
  document.body.innerHTML = "<pre style=\"color:#f87171;background:#0a0a0a;padding:2rem;font-family:monospace;white-space:pre-wrap;font-size:13px\">UNHANDLED REJECTION:\n" + String(ev.reason) + "</pre>";
});

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(e) { return { error: e }; }
  render() {
    if (this.state.error) {
      var e = this.state.error;
      return React.createElement(
        "div",
        { style: { color: "#f87171", background: "#0a0a0a", padding: "2rem", fontFamily: "monospace", whiteSpace: "pre-wrap", fontSize: "13px" } },
        "RENDER ERROR: " + e.message + "\n\n" + e.stack
      );
    }
    return this.props.children;
  }
}

applyTheme(getTheme());

var _orig = window.fetch.bind(window);
window.fetch = function(input, init) {
  // In production builds (served by nginx), rewrite absolute bridge URLs to
  // relative paths so nginx can proxy them — no code change needed per-file.
  if (import.meta.env.PROD && typeof input === "string" && input.startsWith("http://localhost:5000")) {
    input = input.slice("http://localhost:5000".length);
  }
  var token = localStorage.getItem("ax_auth_token");
  if (token) {
    var headers = new Headers(init && init.headers);
    if (!headers.has("Authorization")) {
      headers.set("Authorization", "Bearer " + token);
    }
    return _orig(input, Object.assign({}, init, { headers: headers }));
  }
  return _orig(input, init);
};

var rootElement = document.getElementById("root");
if (!rootElement) { throw new Error("Could not find root element to mount to"); }

var root = ReactDOM.createRoot(rootElement);
root.render(
  React.createElement(React.StrictMode, null,
    React.createElement(ErrorBoundary, null,
      React.createElement(App, null)))
);
