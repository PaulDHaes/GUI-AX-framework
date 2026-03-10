import * as React from "react";

interface SelectContextType {
  value: string;
  onValueChange: (value: string) => void;
}

const SelectContext = React.createContext<SelectContextType | undefined>(
  undefined,
);

interface SelectProps {
  value: string;
  onValueChange: (value: string) => void;
  children: React.ReactNode;
}

export function Select({ value, onValueChange, children }: SelectProps) {
  return (
    <SelectContext.Provider value={{ value, onValueChange }}>
      <div className="relative">{children}</div>
    </SelectContext.Provider>
  );
}

interface SelectTriggerProps {
  className?: string;
  children: React.ReactNode;
  id?: string;
  type?: "button" | "submit" | "reset";
}

export function SelectTrigger({
  children,
  className = "",
  ...props
}: SelectTriggerProps) {
  return (
    <button
      type="button"
      className={`flex h-10 w-full items-center justify-between rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white ring-offset-slate-950 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

export function SelectValue({ placeholder }: { placeholder?: string }) {
  const context = React.useContext(SelectContext);
  if (!context) throw new Error("SelectValue must be used within Select");

  return <span>{context.value || placeholder}</span>;
}

export function SelectContent({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-md border border-slate-700 bg-slate-900 shadow-lg ${className}`}
    >
      {children}
    </div>
  );
}

export function SelectGroup({ children }: { children: React.ReactNode }) {
  return <div className="py-1">{children}</div>;
}

export function SelectLabel({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`px-2 py-1 font-semibold text-slate-500 uppercase tracking-wider select-none ${className}`}
    >
      {children}
    </div>
  );
}

interface SelectItemProps {
  value: string;
  children: React.ReactNode;
  key?: string | number;
  disabled?: boolean;
  className?: string;
}

export function SelectItem({
  value,
  children,
  disabled = false,
  className = "",
}: SelectItemProps) {
  const context = React.useContext(SelectContext);
  if (!context) throw new Error("SelectItem must be used within Select");

  return (
    <div
      className={`relative flex select-none items-center rounded-sm px-2 py-1.5 text-sm text-white outline-none ${
        disabled
          ? "opacity-40 cursor-not-allowed"
          : "cursor-pointer hover:bg-slate-800"
      } ${className}`}
      onClick={() => !disabled && context.onValueChange(value)}
    >
      {children}
    </div>
  );
}
