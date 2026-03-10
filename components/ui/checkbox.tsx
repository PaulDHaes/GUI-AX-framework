import * as React from "react";

interface CheckboxProps {
  className?: string;
  onCheckedChange?: (checked: boolean) => void;
  checked?: boolean;
  id?: string;
  name?: string;
  disabled?: boolean;
}

export function Checkbox({
  className = "",
  onCheckedChange,
  ...props
}: CheckboxProps) {
  return (
    <input
      type="checkbox"
      className={`h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-2 focus:ring-blue-500 dark:border-gray-600 dark:bg-gray-900 ${className}`}
      onChange={(e) => onCheckedChange?.(e.target.checked)}
      {...props}
    />
  );
}
