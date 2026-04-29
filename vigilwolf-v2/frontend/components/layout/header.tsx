"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Search, SlidersHorizontal, Globe, ShieldAlert, Bell, Loader2 } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useUIStore } from "@/lib/store";
import { searchApi, type SearchResult } from "@/lib/api-v2";

function ResultIcon({ type }: { type: SearchResult["type"] }) {
  switch (type) {
    case "domain":
      return <Globe className="h-4 w-4 text-blue-400" />;
    case "threat":
      return <ShieldAlert className="h-4 w-4 text-red-400" />;
    case "alert":
      return <Bell className="h-4 w-4 text-amber-400" />;
    default:
      return <Search className="h-4 w-4 text-zinc-500" />;
  }
}

function resultHref(result: SearchResult): string {
  switch (result.type) {
    case "domain":
      return `/threats/${result.id}`;
    case "threat":
      return `/threats/${result.id}`;
    case "alert":
      return `/alerts`;
    default:
      return "/";
  }
}

export function Header() {
  const { searchQuery, setSearchQuery } = useUIStore();
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [showDropdown, setShowDropdown] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  // Debounce search input (300ms)
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(searchQuery);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Fetch search results when debounced query changes
  const { data: results, isLoading: searchLoading } = useQuery({
    queryKey: ["globalSearch", debouncedQuery],
    queryFn: () => searchApi.search(debouncedQuery),
    enabled: debouncedQuery.length >= 2,
  });

  const searchResults = results ?? [];

  // Group results by type
  const groupedResults = searchResults.reduce<
    Record<string, SearchResult[]>
  >((acc, result) => {
    if (!acc[result.type]) acc[result.type] = [];
    acc[result.type].push(result);
    return acc;
  }, {});

  const flatResults = searchResults;

  // Reset selected index when results change
  useEffect(() => {
    setSelectedIdx(-1);
  }, [debouncedQuery]);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setShowDropdown(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSelect = useCallback(
    (result: SearchResult) => {
      setShowDropdown(false);
      setSearchQuery("");
      router.push(resultHref(result));
    },
    [router, setSearchQuery],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!showDropdown || flatResults.length === 0) return;

      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setSelectedIdx((prev) =>
            prev < flatResults.length - 1 ? prev + 1 : 0,
          );
          break;
        case "ArrowUp":
          e.preventDefault();
          setSelectedIdx((prev) =>
            prev > 0 ? prev - 1 : flatResults.length - 1,
          );
          break;
        case "Enter":
          e.preventDefault();
          if (selectedIdx >= 0 && selectedIdx < flatResults.length) {
            handleSelect(flatResults[selectedIdx]);
          }
          break;
        case "Escape":
          setShowDropdown(false);
          inputRef.current?.blur();
          break;
      }
    },
    [showDropdown, flatResults, selectedIdx, handleSelect],
  );

  return (
    <header className="flex h-14 items-center gap-4 border-b border-zinc-800 bg-zinc-950 px-6">
      {/* Global search */}
      <div ref={containerRef} className="relative flex-1 max-w-md">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
        <input
          ref={inputRef}
          type="text"
          value={searchQuery}
          onChange={(e) => {
            setSearchQuery(e.target.value);
            setShowDropdown(true);
          }}
          onFocus={() => {
            if (debouncedQuery.length >= 2) setShowDropdown(true);
          }}
          onKeyDown={handleKeyDown}
          placeholder="Search domains, threats, alerts..."
          className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 pl-9 pr-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600"
        />

        {/* Loading indicator */}
        {searchLoading && (
          <Loader2 className="absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 animate-spin text-zinc-500" />
        )}

        {/* Search results dropdown */}
        {showDropdown && debouncedQuery.length >= 2 && (
          <div className="absolute left-0 right-0 top-full z-50 mt-1 max-h-80 overflow-y-auto rounded-md border border-zinc-800 bg-zinc-950 shadow-xl">
            {flatResults.length === 0 && !searchLoading ? (
              <div className="px-4 py-6 text-center text-sm text-zinc-500">
                No results found for &ldquo;{debouncedQuery}&rdquo;
              </div>
            ) : (
              Object.entries(groupedResults).map(([type, items]) => (
                <div key={type}>
                  <div className="border-b border-zinc-800/50 px-4 py-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">
                    {type}
                  </div>
                  {items.map((result) => {
                    const globalIdx = flatResults.indexOf(result);
                    return (
                      <button
                        key={result.id}
                        onClick={() => handleSelect(result)}
                        className={`flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                          selectedIdx === globalIdx
                            ? "bg-zinc-800 text-zinc-100"
                            : "text-zinc-300 hover:bg-zinc-900"
                        }`}
                      >
                        <ResultIcon type={result.type as SearchResult["type"]} />
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-medium">
                            {result.title}
                          </p>
                          {result.description && (
                            <p className="truncate text-xs text-zinc-500">
                              {result.description}
                            </p>
                          )}
                        </div>
                        {result.score !== undefined && (
                          <span className="shrink-0 rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-500">
                            {result.score}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* Right side actions */}
      <div className="flex items-center gap-2">
        <button
          className="flex h-9 w-9 items-center justify-center rounded-md border border-zinc-800 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
          aria-label="Filters"
          title="Filters"
        >
          <SlidersHorizontal className="h-4 w-4" />
        </button>

        {/* User avatar placeholder */}
        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-zinc-800 text-xs font-semibold text-zinc-400">
          VW
        </div>
      </div>
    </header>
  );
}