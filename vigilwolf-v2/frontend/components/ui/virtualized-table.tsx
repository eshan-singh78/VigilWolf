"use client";

import { useRef, useCallback } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@/lib/utils";

interface Column<T> {
  key: string;
  header: string;
  render: (item: T) => React.ReactNode;
  className?: string;
}

interface VirtualizedTableProps<T> {
  columns: Column<T>[];
  data: T[];
  rowKey: (item: T) => string;
  onRowClick?: (item: T) => void;
  estimatedRowHeight?: number;
  maxHeight?: string;
  overscan?: number;
  className?: string;
  headerClassName?: string;
  rowClassName?: string | ((item: T) => string);
  isLoading?: boolean;
  loadingRowCount?: number;
  emptyContent?: React.ReactNode;
  footer?: React.ReactNode;
}

export function VirtualizedTable<T>({
  columns,
  data,
  rowKey,
  onRowClick,
  estimatedRowHeight = 52,
  maxHeight = "calc(100vh - 280px)",
  overscan = 10,
  className,
  headerClassName,
  rowClassName,
  isLoading,
  loadingRowCount = 5,
  emptyContent,
  footer,
}: VirtualizedTableProps<T>) {
  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: data.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => estimatedRowHeight,
    overscan,
  });

  const handleRowClick = useCallback(
    (item: T) => {
      if (onRowClick) onRowClick(item);
    },
    [onRowClick],
  );

  if (isLoading) {
    return (
      <div className={cn("space-y-2", className)}>
        {Array.from({ length: loadingRowCount }).map((_, i) => (
          <div
            key={i}
            className="h-12 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900"
          />
        ))}
      </div>
    );
  }

  if (data.length === 0 && emptyContent) {
    return <div className={className}>{emptyContent}</div>;
  }

  return (
    <div className={cn("overflow-hidden rounded-lg border border-zinc-800", className)}>
      {/* Fixed header */}
      <div className="border-b border-zinc-800 bg-zinc-900/80 backdrop-blur-sm">
        <div
          className="grid"
          style={{
            gridTemplateColumns: columns
              .map((c) => c.className || "1fr")
              .join(" "),
          }}
        >
          {columns.map((col) => (
            <div
              key={col.key}
              className="px-4 py-3 text-left text-sm font-medium text-zinc-400"
            >
              {col.header}
            </div>
          ))}
        </div>
      </div>

      {/* Virtualized scrollable body */}
      <div
        ref={parentRef}
        className="overflow-auto"
        style={{ maxHeight }}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const item = data[virtualRow.index];
            const rowClass =
              typeof rowClassName === "function"
                ? rowClassName(item)
                : rowClassName;

            return (
              <div
                key={rowKey(item)}
                className={cn(
                  "absolute left-0 flex w-full items-center border-b border-zinc-800/50 transition-colors hover:bg-zinc-900/70",
                  onRowClick && "cursor-pointer",
                  rowClass,
                )}
                style={{
                  top: 0,
                  transform: `translateY(${virtualRow.start}px)`,
                  height: `${virtualRow.size}px`,
                }}
                onClick={() => handleRowClick(item)}
              >
                <div
                  className="grid w-full"
                  style={{
                    gridTemplateColumns: columns
                      .map((c) => c.className || "1fr")
                      .join(" "),
                  }}
                >
                  {columns.map((col) => (
                    <div
                      key={col.key}
                      className="px-4 py-3 text-sm"
                    >
                      {col.render(item)}
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {footer && <div className="border-t border-zinc-800">{footer}</div>}
    </div>
  );
}