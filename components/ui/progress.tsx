import * as React from "react";

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string;
  value?: number;
}

export function Progress({
  value = 0,
  className = "",
  ...props
}: ProgressProps) {
  return (
    <div
      className={`relative h-4 w-full overflow-hidden rounded-full bg-gray-200 dark:bg-gray-800 ${className}`}
      {...props}
    >
      <div
        className="h-full bg-blue-500 transition-all"
        style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
      />
    </div>
  );
}
