import * as React from "react";

export interface TooltipProps {
  label: string;
  children: React.ReactNode;
}

export const Tooltip: React.FC<TooltipProps> = ({ label, children }) => (
  <span title={label} className="inline-flex">
    {children}
  </span>
);
