import { cn } from "@/lib/utils";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

interface StatsCardProps {
  title: string;
  value: string | number;
  description?: string;
  trend?: "up" | "down" | "flat";
  variant?: "default" | "danger" | "warning" | "success";
}

const variantStyles: Record<string, { text: string; bg: string; border: string; icon: string }> = {
  default: {
    text: "text-zinc-100",
    bg: "bg-zinc-900",
    border: "border-zinc-800",
    icon: "text-zinc-400",
  },
  danger: {
    text: "text-red-400",
    bg: "bg-zinc-900",
    border: "border-red-500/30",
    icon: "text-red-400",
  },
  warning: {
    text: "text-amber-400",
    bg: "bg-zinc-900",
    border: "border-amber-500/30",
    icon: "text-amber-400",
  },
  success: {
    text: "text-emerald-400",
    bg: "bg-zinc-900",
    border: "border-emerald-500/30",
    icon: "text-emerald-400",
  },
};

function TrendIcon({ trend }: { trend: "up" | "down" | "flat" }) {
  switch (trend) {
    case "up":
      return <TrendingUp className="h-4 w-4 text-emerald-400" />;
    case "down":
      return <TrendingDown className="h-4 w-4 text-red-400" />;
    case "flat":
      return <Minus className="h-4 w-4 text-zinc-500" />;
  }
}

export function StatsCard({
  title,
  value,
  description,
  trend,
  variant = "default",
}: StatsCardProps) {
  const styles = variantStyles[variant];

  return (
    <div
      className={cn(
        "rounded-lg border p-4 transition-shadow hover:shadow-lg hover:shadow-zinc-900/50",
        styles.bg,
        styles.border,
      )}
    >
      <div className="flex items-center justify-between">
        <p className="text-sm text-zinc-500">{title}</p>
        {trend && <TrendIcon trend={trend} />}
      </div>
      <p className={cn("mt-1 text-2xl font-semibold", styles.text)}>
        {value}
      </p>
      {description && (
        <p className="mt-1 text-xs text-zinc-500">{description}</p>
      )}
    </div>
  );
}