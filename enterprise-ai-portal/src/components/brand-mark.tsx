import { Sparkles } from "lucide-react";

import { cn } from "@/lib/utils";

const sizeStyles = {
  sm: "h-8 w-8 rounded-[10px]",
  md: "h-10 w-10 rounded-xl",
  lg: "h-14 w-14 rounded-2xl",
};

const iconStyles = {
  sm: "h-4 w-4",
  md: "h-5 w-5",
  lg: "h-7 w-7",
};

export function BrandMark({
  size = "md",
  className,
}: {
  size?: keyof typeof sizeStyles;
  className?: string;
}) {
  return (
    <span
      aria-hidden
      className={cn(
        "relative inline-flex shrink-0 items-center justify-center overflow-hidden bg-gradient-to-br from-primary to-primary/70 text-primary-foreground",
        "before:absolute before:inset-x-1 before:top-0 before:h-px before:bg-white/50",
        sizeStyles[size],
        className,
      )}
    >
      <span className="absolute -right-2 -top-2 h-5 w-5 rounded-full bg-white/20 blur-sm" />
      <Sparkles className={iconStyles[size]} strokeWidth={2.1} />
    </span>
  );
}
