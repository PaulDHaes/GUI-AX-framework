import * as React from "react";

interface ButtonProps {
  className?: string;
  children?: React.ReactNode;
  variant?:
    | "default"
    | "destructive"
    | "outline"
    | "secondary"
    | "ghost"
    | "link";
  size?: "default" | "sm" | "lg" | "icon";
  onClick?: (event: React.MouseEvent<HTMLButtonElement>) => void;
  disabled?: boolean;
  type?: "button" | "submit" | "reset";
  title?: string;
}

export function Button({
  className = "",
  variant = "default",
  size = "default",
  ...props
}: ButtonProps) {
  const variants = {
    default:
      "bg-primary-600 text-white hover:bg-primary-700 active:bg-primary-800",
    destructive: "bg-red-600 text-white hover:bg-red-700 active:bg-red-800",
    outline:
      "border border-slate-700 bg-slate-800 text-white hover:bg-slate-700 active:bg-slate-600",
    secondary: "bg-slate-700 text-white hover:bg-slate-600 active:bg-slate-500",
    ghost:
      "text-slate-300 hover:bg-slate-800 hover:text-white active:bg-slate-700",
    link: "text-primary-500 underline-offset-4 hover:underline hover:text-primary-400",
  };

  const sizes = {
    default: "h-10 px-4 py-2",
    sm: "h-9 rounded-md px-3 text-sm",
    lg: "h-11 rounded-md px-8",
    icon: "h-10 w-10",
  };

  return (
    <button
      className={`inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 disabled:pointer-events-none disabled:opacity-50 ${variants[variant]} ${sizes[size]} ${className}`}
      {...props}
    />
  );
}
