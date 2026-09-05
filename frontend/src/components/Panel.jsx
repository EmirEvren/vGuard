import React from "react";
import { Activity } from "lucide-react";

export function Panel({ title, icon: Icon, className = "", children, action }) {
  return (
    <div className={`panel ${className}`}>
      <div className="panel-head">
        <h2>
          {Icon && <Icon size={20} />} {title}
        </h2>
        {action}
      </div>
      {children}
    </div>
  );
}

export function Message({ text }) {
  return text ? (
    <div className="alert-box full">
      <Activity size={16} />
      {text}
    </div>
  ) : null;
}
