import React from "react";

// Custom SVG logo: skull looking through binoculars
const BinocularsSkullLogo: React.FC<{ size?: number; className?: string }> = ({
  size = 40,
  className = "",
}) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 48 48"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={className}
  >
    {/* ── Skull cranium ── */}
    <ellipse
      cx="24"
      cy="16"
      rx="11"
      ry="10"
      fill="#1e293b"
      stroke="#8b5cf6"
      strokeWidth="1.5"
    />

    {/* Skull cheekbones / jaw */}
    <path
      d="M14 20 Q13 26 16 28 L18 32 H30 L32 28 Q35 26 34 20"
      fill="#1e293b"
      stroke="#8b5cf6"
      strokeWidth="1.5"
      strokeLinejoin="round"
    />

    {/* Jaw teeth */}
    <rect
      x="18"
      y="31"
      width="3"
      height="3"
      rx="0.5"
      fill="#0f172a"
      stroke="#8b5cf6"
      strokeWidth="1"
    />
    <rect
      x="22.5"
      y="31"
      width="3"
      height="3.5"
      rx="0.5"
      fill="#0f172a"
      stroke="#8b5cf6"
      strokeWidth="1"
    />
    <rect
      x="27"
      y="31"
      width="3"
      height="3"
      rx="0.5"
      fill="#0f172a"
      stroke="#8b5cf6"
      strokeWidth="1"
    />

    {/* ── Binocular lenses (eye sockets) ── */}
    {/* Left lens ring */}
    <circle
      cx="18.5"
      cy="18"
      r="5.5"
      fill="#0f172a"
      stroke="#8b5cf6"
      strokeWidth="1.8"
    />
    {/* Right lens ring */}
    <circle
      cx="29.5"
      cy="18"
      r="5.5"
      fill="#0f172a"
      stroke="#8b5cf6"
      strokeWidth="1.8"
    />
    {/* Bridge between lenses */}
    <path d="M24 18 H24" stroke="#8b5cf6" strokeWidth="1.8" />
    <rect x="24" y="16.5" width="0" height="3" fill="#8b5cf6" />
    <line
      x1="24"
      y1="18"
      x2="24"
      y2="18"
      stroke="#8b5cf6"
      strokeWidth="2"
      strokeLinecap="round"
    />

    {/* Left eye glow (cyan iris) */}
    <circle cx="18.5" cy="18" r="3.2" fill="#0e7490" fillOpacity="0.4" />
    <circle cx="18.5" cy="18" r="2" fill="#22d3ee" fillOpacity="0.9" />
    <circle cx="18.5" cy="18" r="0.8" fill="#ffffff" />
    {/* Left lens shine */}
    <circle cx="17.2" cy="16.8" r="0.6" fill="#ffffff" fillOpacity="0.6" />

    {/* Right eye glow (cyan iris) */}
    <circle cx="29.5" cy="18" r="3.2" fill="#0e7490" fillOpacity="0.4" />
    <circle cx="29.5" cy="18" r="2" fill="#22d3ee" fillOpacity="0.9" />
    <circle cx="29.5" cy="18" r="0.8" fill="#ffffff" />
    {/* Right lens shine */}
    <circle cx="28.2" cy="16.8" r="0.6" fill="#ffffff" fillOpacity="0.6" />

    {/* ── Nose cavity ── */}
    <path
      d="M22.5 22 Q24 24.5 25.5 22"
      stroke="#8b5cf6"
      strokeWidth="1.2"
      strokeLinecap="round"
      fill="none"
    />

    {/* Subtle violet glow around lenses */}
    <circle
      cx="18.5"
      cy="18"
      r="5.5"
      fill="none"
      stroke="#8b5cf6"
      strokeWidth="0.5"
      opacity="0.4"
    />
    <circle
      cx="29.5"
      cy="18"
      r="5.5"
      fill="none"
      stroke="#8b5cf6"
      strokeWidth="0.5"
      opacity="0.4"
    />
  </svg>
);

export default BinocularsSkullLogo;
