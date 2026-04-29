"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Globe,
  Activity,
  ShieldAlert,
  Bell,
  Settings,
  Boxes,
  Swords,
  Drama,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useUIStore } from "@/lib/store";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  disabled?: boolean;
}

const navItems: NavItem[] = [
  { label: "Dashboard", href: "/", icon: LayoutDashboard },
  { label: "NRD", href: "/nrd", icon: Globe },
  { label: "Monitor", href: "/monitor", icon: Activity },
  { label: "Threats", href: "/threats", icon: ShieldAlert },
  { label: "Alerts", href: "/alerts", icon: Bell },
  { label: "Settings", href: "/settings", icon: Settings },
];

const phaseTwoItems: NavItem[] = [
  { label: "Clusters", href: "/clusters", icon: Boxes },
  { label: "Campaigns", href: "/campaigns", icon: Swords },
  { label: "Actors", href: "/actors", icon: Drama },
];


export function Sidebar() {
  const pathname = usePathname();
  const { sidebarOpen, toggleSidebar } = useUIStore();

  return (
    <aside
      className={cn(
        "flex flex-col border-r border-zinc-800 bg-zinc-950 transition-all duration-200",
        sidebarOpen ? "w-56" : "w-16",
      )}
    >
      {/* Logo / Brand */}
      <div className="flex h-14 items-center gap-2 border-b border-zinc-800 px-4">
        <ShieldAlert className="h-6 w-6 shrink-0 text-red-500" />
        {sidebarOpen && (
          <span className="text-lg font-bold tracking-tight text-zinc-100">
            VigilWolf
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-2 py-4">
        {navItems.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.label}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-zinc-800 text-zinc-100"
                  : "text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200",
              )}
            >
              <item.icon className="h-4 w-4 shrink-0" />
              {sidebarOpen && <span>{item.label}</span>}
            </Link>
          );
        })}

        {/* Intelligence */}
        {sidebarOpen && (
          <div className="my-3 border-t border-zinc-800" />
        )}
        {!sidebarOpen && (
          <div className="my-3 border-t border-zinc-800 mx-1" />
        )}

        {phaseTwoItems.map((item) => {
          const isActive = pathname.startsWith(item.href);
          return (
            <Link
              key={item.label}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-zinc-800 text-zinc-100"
                  : "text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200",
              )}
            >
              <item.icon className="h-4 w-4 shrink-0" />
              {sidebarOpen && <span>{item.label}</span>}
            </Link>
          );
        })}

      </nav>

      {/* Collapse toggle */}
      <button
        onClick={toggleSidebar}
        className="flex h-10 items-center justify-center border-t border-zinc-800 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
        aria-label={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
      >
        {sidebarOpen ? (
          <ChevronLeft className="h-4 w-4" />
        ) : (
          <ChevronRight className="h-4 w-4" />
        )}
      </button>
    </aside>
  );
}