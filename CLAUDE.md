# nmap Visualizer — Architecture

## Overview

A **pure frontend SPA** that parses nmap XML output files in the browser and visualises the results in a modern, dark-themed dashboard. No backend or server required.

## Tech Stack

| Layer | Library | Why |
|---|---|---|
| Build | Vite + React 18 + TypeScript | Fast HMR, type safety |
| Styling | Tailwind CSS v3 | Utility-first, dark design system |
| State | Zustand | Minimal, composable, no boilerplate |
| Routing | React Router v6 | SPA navigation |
| XML Parsing | fast-xml-parser | Fast, browser-compatible XML → JS |
| Network Graph | React Flow | Interactive node-edge diagrams |
| Charts | Recharts | Declarative, Recharts + D3 inside |
| Animations | Framer Motion | Spring animations, AnimatePresence |
| Icons | Lucide React | Consistent icon set |
| Dates | date-fns | Lightweight date formatting |

## Folder Structure

```
src/
├── types/
│   └── nmap.ts          # All TypeScript interfaces for the nmap data model
├── lib/
│   ├── parser.ts        # nmap XML → NmapScan (pure function, no side effects)
│   ├── cn.ts            # clsx + tailwind-merge helper
│   └── colors.ts        # Color constants and helpers (port states, OS, services)
├── store/
│   └── scanStore.ts     # Zustand store: scans[], filters, selectedHostId
├── components/
│   ├── ui/              # Primitive UI: Badge, Button, Card, StatCard
│   ├── layout/          # Layout, Sidebar, Topbar
│   ├── upload/          # FileUpload (drag-and-drop XML parser)
│   ├── graph/           # NetworkGraph (ReactFlow canvas)
│   └── host/            # HostDetail (slide-in panel)
└── pages/
    ├── Dashboard.tsx    # Summary stats, charts, live host list
    ├── NetworkGraphPage.tsx  # ReactFlow network topology
    ├── HostList.tsx     # Filterable/searchable host table
    ├── PortAnalysis.tsx # Port/service charts and heatmap
    ├── Services.tsx     # Service cards grid with drill-down
    └── UploadPage.tsx   # File upload entry point
```

## Data Flow

```
User uploads XML file
        │
        ▼
parseNmapFile()          (src/lib/parser.ts)
  → parseNmapXml()
  → parse hosts, ports, OS, scripts
  → compute aggregations (service/port/OS distribution)
        │
        ▼
useScanStore.loadScan()  (src/store/scanStore.ts)
  → appends scan to scans[]
  → re-computes filteredHosts
        │
        ▼
React components read state via Zustand selectors
  → useActiveScan()      → current NmapScan
  → useSelectedHost()    → selected NmapHost (for detail panel)
  → useScanStore(s => s.filteredHosts)
```

## Key Data Model

```typescript
NmapScan
  ├── hosts: NmapHost[]
  │     ├── addresses: NmapAddress[]   (ipv4/ipv6/mac)
  │     ├── hostnames: NmapHostname[]
  │     ├── ports: NmapPort[]
  │     │     ├── state: PortState     (open/closed/filtered)
  │     │     ├── service?: NmapService (name, product, version)
  │     │     └── scripts?: NmapScript[]
  │     └── os?: NmapOs
  ├── serviceDistribution: ServiceCount[]
  ├── portDistribution: PortCount[]
  └── osDistribution: OsCount[]
```

## Views

| Route | Component | Description |
|---|---|---|
| `/` | Dashboard | Stats cards, pie/bar charts, live host list |
| `/graph` | NetworkGraphPage | Interactive ReactFlow topology map |
| `/hosts` | HostList | Searchable table with side panel |
| `/ports` | PortAnalysis | Bar chart, service pie, port heatmap |
| `/services` | Services | Service card grid with host drill-down |
| `/upload` | UploadPage | Drag-and-drop XML file loader |

## Design System

Dark-mode only. Custom Tailwind tokens:

- `surface` / `surface-elevated` / `surface-muted` / `surface-border` — layered dark backgrounds
- `accent-cyan` — primary interactive color (#00d4ff)
- `accent-green` — host up / open port (#00ff88)
- `accent-red` — host down / closed port (#ff4444)
- `accent-orange` — filtered ports (#ff6b35)
- `mono` class — JetBrains Mono for all technical data

## Commands

```bash
npm run dev      # Start dev server (http://localhost:5173)
npm run build    # Production build to dist/
npm run preview  # Serve production build locally
npx tsc --noEmit # Type check only
```

## Adding a New View

1. Create `src/pages/YourPage.tsx`
2. Add a route in `src/App.tsx`
3. Add a nav item in `src/components/layout/Sidebar.tsx`
