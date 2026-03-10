export enum Severity {
  CRITICAL = "CRITICAL",
  HIGH = "HIGH",
  MEDIUM = "MEDIUM",
  LOW = "LOW",
  INFO = "INFO",
}

export enum ScanStatus {
  RUNNING = "RUNNING",
  COMPLETED = "COMPLETED",
  FAILED = "FAILED",
  PENDING = "PENDING",
}

export interface Port {
  port: number;
  service: string;
  banner?: string;
  isOpen: boolean;
}

export interface GeoLocation {
  lat: number;
  lng: number;
  city?: string;
  country?: string;
  countryCode?: string;
}

export interface Subdomain {
  id: string;
  hostname: string;
  ip: string;
  ports: Port[];
  screenshot?: string;
  technologies: string[];
  location: string; // Display string
  geo?: GeoLocation; // Coordinates
  asn: string;
  // GoWitness enriched fields
  url?: string;
  title?: string;
  statusCode?: number;
}

export interface Vulnerability {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  path?: string;
  matched?: string; // nuclei: matched-at URL
  type?: string; // nuclei: protocol / "nuclei-md" / etc.
  rawContent?: string; // full raw output (markdown line, JSON, or .md file content)
}

export interface Target {
  id: string;
  domain: string;
  programName: string; // e.g., Bug Bounty Program Name
  lastScanDate: string;
  status: ScanStatus;
  subdomains: Subdomain[];
  vulnerabilities: Vulnerability[];
  totalPorts: number;
  axiomFleetSize: number; // How many instances used
  rawWhoisData?: Record<string, string>; // domain → full whois text (populated by bridge)
  sources?: string[]; // source filenames that built this target
}

export interface FleetInstance {
  id: string;
  name: string;
  provider: "DigitalOcean" | "AWS" | "Linode" | "Azure" | "GCP";
  ip: string;
  region: string;
  status: "initializing" | "running" | "idle" | "terminating";
  instanceType: string; // e.g., s-1vcpu-1gb
  currentTask?: string; // e.g., "Scanning target-A"
  uptime: string;
}

export interface DashboardStats {
  totalTargets: number;
  totalSubdomains: number;
  criticalVulns: number;
  runningScans: number;
  fleetStatus: number;
}
