import { create } from "zustand";

export interface UIState {
  sidebarOpen: boolean;
  activeFilters: Record<string, string>;
  searchQuery: string;
  setSidebarOpen: (open: boolean) => void;
  toggleSidebar: () => void;
  setActiveFilter: (key: string, value: string) => void;
  removeActiveFilter: (key: string) => void;
  setSearchQuery: (query: string) => void;
  clearFilters: () => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: true,
  activeFilters: {},
  searchQuery: "",
  setSidebarOpen: (open) => set({ sidebarOpen: open }),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  setActiveFilter: (key, value) =>
    set((state) => ({
      activeFilters: { ...state.activeFilters, [key]: value },
    })),
  removeActiveFilter: (key) =>
    set((state) => {
      const { [key]: _, ...rest } = state.activeFilters;
      return { activeFilters: rest };
    }),
  setSearchQuery: (query) => set({ searchQuery: query }),
  clearFilters: () => set({ activeFilters: {}, searchQuery: "" }),
}));