import * as React from "react";

interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string;
  children?: React.ReactNode;
  variant?: "default" | "destructive";
}

export function Alert({
  className = "",
  variant = "default",
  ...props
}: AlertProps) {
  const variants = {
    default:
      "bg-blue-50 text-blue-900 border-blue-200 dark:bg-blue-950 dark:text-blue-100 dark:border-blue-800",
    destructive:
      "bg-red-50 text-white-900 border-red-200 dark:bg-red-950 dark:text-white-100 dark:border-red-800",
  };

  return (
    <div
      className={`relative w-full rounded-lg border p-4 ${variants[variant]} ${className}`}
      {...props}
    />
  );
}

export function AlertDescription({
  className = "",
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) {
  return <div className={`text-sm ${className}`} {...props} />;
}
