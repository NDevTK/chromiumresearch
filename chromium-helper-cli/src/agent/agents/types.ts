// src/agent/agents/types.ts
import { ProactiveBugFinderConfig, BugPatternAnalysisConfig, CodebaseUnderstandingConfig, GenericTaskAgentConfig } from '../../agent_config.js';

// --- Enums and Basic Agent Interfaces ---
export enum SpecializedAgentType {
  ProactiveBugFinding = "ProactiveBugFinding",
  BugPatternAnalysis = "BugPatternAnalysis",
  CodebaseUnderstanding = "CodebaseUnderstanding",
  GenericTask = "GenericTask",
}

export interface SpecializedAgent {
  type: SpecializedAgentType;
  start(): Promise<void>;
  stop(): Promise<void>;
  getStatus(): Promise<string>;
  processData?(data: unknown): Promise<void>;
  setSharedContext?(context: SharedAgentContextType): void;
  processPendingRequests?(): Promise<void>;
}

// --- Data Structures for Agents ---
export interface BugPattern {
  id: string;
  name: string;
  description: string;
  cwe?: string;
  tags: string[];
  exampleGoodPractice?: string;
  exampleVulnerableCode?: string;
  source?: string;
  confidence?: 'High' | 'Medium' | 'Low';
  severity?: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
}

export interface ProcessedItemEntry {
  lastAnalyzed: string;
  analysisTypes: string[];
  contentHash?: string;
  version?: string;
}
export type ProcessedItemsHistory = Record<string, ProcessedItemEntry>;

// --- Structures for CodebaseUnderstandingAgent ---
export interface SymbolInfo {
  name: string;
  type?: string; // e.g., "function", "class", "variable", "mojo_interface"
  definitionLocation?: string; // File path + line number from findSymbol
  description?: string; // Brief LLM-generated description of the symbol OR from findSymbol
  referenceCount?: number; // From findSymbol's estimatedUsageCount
  // We could add more fields from XRefResult if needed, like declarationLocation
}

export interface AnalyzedCommitInfo {
  cl: string; // CL number or full URL
  subject: string;
  date: string;
  author?: string;
  keyFilesChanged?: string[]; // Files within the current module that were part of this commit
}

export interface KeyFileWithSymbols {
  filePath: string;
  description: string; // LLM-generated summary of the file's role in the module
  identifiedSymbols?: SymbolInfo[]; // Key functions, classes, etc. in this file
  owners?: string[]; // From closest OWNERS file directly responsible for this file
  lastCommitDate?: string; // Date of the last commit touching this file
  primaryPurpose?: string; // e.g., "IPC Handler", "Data Model", "UI Component"
}

export interface CodebaseModuleInsight {
  modulePath: string; // e.g., "src/components/safe_browsing"
  summary: string; // LLM-generated overview of the module's purpose and main functions
  primaryOwners?: string[]; // From top-level OWNERS in this module
  keyFiles: KeyFileWithSymbols[]; // Important files within this module
  dependencies?: string[]; // Other module paths this module depends on
  dependents?: string[]; // Other module paths that depend on this module (harder to get, optional)
  interactionPoints?: { type: string, name: string, filePath?: string }[]; // e.g., {type: "mojo_interface", name: "FooService", filePath: "services/foo/public/mojom/foo.mojom"}
  keyTechnologies?: string[]; // e.g., "Mojo", "IPC", "SQLite", "WebUI"
  commonSecurityRisks?: string[]; // LLM-identified common security considerations for this module
  recentSignificantCommits?: AnalyzedCommitInfo[]; // Summaries of important recent changes
  documentationLinks?: string[]; // Links to READMEs or design docs
  lastAnalyzed: string; // Timestamp of the last analysis
  contentHash?: string; // Hash of key inputs used to generate this insight, for re-analysis decisions
}

// --- Agent Request & Event Structures ---
export interface AgentRequest {
  requestId: string;
  requestingAgentId?: string;
  targetAgentType: SpecializedAgentType;
  taskType: string;
  params: Record<string, any>;
  status: "pending" | "in_progress" | "completed" | "failed";
  createdAt: string;
  updatedAt: string;
  result?: any;
  error?: string;
  priority?: number;
}

export interface AgentEvent {
  eventId: string;
  eventType: string;
  sourceAgent: SpecializedAgentType | string;
  data: any;
  timestamp: string;
}

// --- Shared Context ---
export type SharedAgentContextType = {
  findings: Array<{ sourceAgent: string, type: string, data: any, timestamp: Date }>;
  requests: AgentRequest[];
  knownBugPatterns: Array<BugPattern | string>;
  codebaseInsights: Record<string, CodebaseModuleInsight>;
  recentEvents: AgentEvent[];
  specializedAgents?: Map<SpecializedAgentType, SpecializedAgent>; // To allow agents to call each other
};

// --- Issue Structure (as returned by API and used by agents) ---
// Based on ai-guide.ts output for issue search results.
export interface IssueSummary {
  issueId: string;
  title: string;
  status: string;
  priority: string;
  reporter?: string;
  assignee?: string;
  created: string;
  modified: string;
  browserUrl: string;
  // The actual API might return more fields, agent can pick these.
}


// Re-export agent-specific configs for convenience if agents need them directly
// although they are typically passed by the researcher.
export type { ProactiveBugFinderConfig, BugPatternAnalysisConfig, CodebaseUnderstandingConfig, GenericTaskAgentConfig };
