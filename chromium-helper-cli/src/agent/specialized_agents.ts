// For the specialized agents
import { LLMCommunication } from './llm_communication.js';
import { PersistentStorage } from './persistent_storage.js';
import { ChromiumAPI, SearchResult } from '../api.js';
import { ProactiveBugFinderConfig, BugPatternAnalysisConfig, CodebaseUnderstandingConfig, GenericTaskAgentConfig } from '../agent_config.js';
import { computeSha256Hash } from '../agent_utils.js';

// --- Data Structures ---
export interface BugPattern { id: string; name: string; description: string; cwe?: string; tags: string[]; exampleGoodPractice?: string; exampleVulnerableCode?: string; source?: string; confidence?: 'High' | 'Medium' | 'Low'; severity?: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'; }
export interface ProcessedItemEntry { lastAnalyzed: string; analysisTypes: string[]; contentHash?: string; version?: string; }
export type ProcessedItemsHistory = Record<string, ProcessedItemEntry>;

// Revised structures for CodebaseUnderstandingAgent
export interface SymbolInfo {
  name: string;
  type?: string; // e.g., "function", "class", "variable", "mojo_interface"
  definitionLocation?: string; // File path + line number
  description?: string; // Brief LLM-generated description of the symbol
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

// --- Agent Request Structure ---
export interface AgentRequest {
  requestId: string; // Unique ID for the request
  requestingAgentId?: string; // ID of the agent making the request (could be its type or a unique instance ID)
  targetAgentType: SpecializedAgentType; // Which type of agent should handle this
  taskType: string; // e.g., "analyze_file_for_vulnerabilities", "get_module_insight", "get_contextual_advice_for_snippet"
  params: Record<string, any>; // Task-specific parameters (e.g., { filePath: "..." }, { codeSnippet: "..." })
  status: "pending" | "in_progress" | "completed" | "failed";
  createdAt: string; // ISO timestamp
  updatedAt: string; // ISO timestamp
  result?: any; // Result of the task
  error?: string; // Error message if failed
  priority?: number; // Optional priority, lower numbers = higher priority
}

export type SharedAgentContextType = {
  findings: Array<{ sourceAgent: string, type: string, data: any, timestamp: Date }>;
  requests: AgentRequest[]; // Using the new AgentRequest structure
  knownBugPatterns: Array<BugPattern | string>;
  codebaseInsights: Record<string, CodebaseModuleInsight>;
};

export enum SpecializedAgentType { ProactiveBugFinding = "ProactiveBugFinding", BugPatternAnalysis = "BugPatternAnalysis", CodebaseUnderstanding = "CodebaseUnderstanding", GenericTask = "GenericTask", }
export interface SpecializedAgent { type: SpecializedAgentType; start(): Promise<void>; stop(): Promise<void>; getStatus(): Promise<string>; processData?(data: unknown): Promise<void>; setSharedContext?(context: SharedAgentContextType): void; processPendingRequests?(): Promise<void>; } // Added processPendingRequests

// --- ProactiveBugFinder --- (Includes changes from previous plan's Phase 2 & 4)
export class ProactiveBugFinder implements SpecializedAgent {
  public type = SpecializedAgentType.ProactiveBugFinding;
  private llmComms: LLMCommunication;
  private storage: PersistentStorage;
  private chromiumApi: ChromiumAPI;
  private sharedContext!: SharedAgentContextType;
  private config: ProactiveBugFinderConfig;
  private isActive: boolean = false;
  private isAnalyzing: boolean = false; // To prevent concurrent cycle runs
  private analysisIntervalId?: NodeJS.Timeout;
  private lastAnalysisTimestamp?: Date;
  private processedItemsHistory: ProcessedItemsHistory = {};

  private readonly ANALYSIS_TYPE_HEURISTIC_SWEEP = "pbf_heuristic_sweep";
  private readonly ANALYSIS_TYPE_SPECIFIC_REQUEST = "pbf_specific_request";

  constructor( llmComms: LLMCommunication, chromiumApi: ChromiumAPI, sharedContext: SharedAgentContextType, config: ProactiveBugFinderConfig ) {
    this.llmComms = llmComms; this.chromiumApi = chromiumApi; this.config = config;
    this.storage = new PersistentStorage('ProactiveBugFinder_data');
    this.setSharedContext(sharedContext); console.log("Proactive Bug Finder agent initialized."); this.loadState();
  }
  public setSharedContext(context: SharedAgentContextType): void { this.sharedContext = context; }
  private async loadState(): Promise<void> {
    const state = await this.storage.loadData<{ lastAnalysis?: string; processedFilePaths?: string[]; processedItemsHistory?: ProcessedItemsHistory; }>();
    if (state) {
      if (state.lastAnalysis) this.lastAnalysisTimestamp = new Date(state.lastAnalysis);
      if (state.processedItemsHistory) this.processedItemsHistory = state.processedItemsHistory;
      else if (state.processedFilePaths && Array.isArray(state.processedFilePaths)) {
        this.processedItemsHistory = {}; const now = new Date().toISOString();
        state.processedFilePaths.forEach(fp => { this.processedItemsHistory[fp] = { lastAnalyzed: now, analysisTypes: [this.ANALYSIS_TYPE_HEURISTIC_SWEEP + "_legacy"]};});
        console.log(`PBF: Migrated ${state.processedFilePaths.length} paths.`);
      }
      console.log(`PBF: Loaded ${Object.keys(this.processedItemsHistory).length} items into history.`);
    }
  }
  private async saveState(): Promise<void> {
    const maxItems = this.config.maxProcessedFileHistory || 100; const keys = Object.keys(this.processedItemsHistory);
    if (keys.length > maxItems) {
      const sorted = keys.sort((a,b) => new Date(this.processedItemsHistory[a].lastAnalyzed).getTime() - new Date(this.processedItemsHistory[b].lastAnalyzed).getTime());
      for(let i=0; i < keys.length - maxItems; i++) delete this.processedItemsHistory[sorted[i]];
    }
    await this.storage.saveData({ lastAnalysis: this.lastAnalysisTimestamp?.toISOString(), processedItemsHistory: this.processedItemsHistory });
  }
  public async start(): Promise<void> {
    if (this.isActive) return;
    this.isActive = true;
    this.isAnalyzing = false; // Ensure this is reset on start
    console.log("PBF: Continuous operation started.");
    this.runContinuousAnalysisLoop().catch(e => {
        console.error("PBF: ContinuousAnalysisLoop encountered critical error and exited:", e);
        this.isActive = false; // Stop if the main loop crashes
    });
  }

  public async stop(): Promise<void> {
    this.isActive = false; // Signal the loop to stop
    // No intervalId to clear anymore for the main loop
    console.log("PBF: Continuous operation signaled to stop.");
  }

  public async getStatus(): Promise<string> {
    let s = `PBF: ${this.isActive?'Continuous - Running':'Idle/Stopped'}.`;
    s += ` ${this.isAnalyzing ? 'Currently Processing Item.' : 'Awaiting next item/discovery.'}`;
    if(this.lastAnalysisTimestamp)s+=` Last Item Processed At: ${this.lastAnalysisTimestamp.toLocaleTimeString()}.`;
    s+=` History: ${Object.keys(this.processedItemsHistory).length} files.`;
    // TODO: Add internal queue size to status if implemented
    return s;
  }

  private async runContinuousAnalysisLoop(): Promise<void> {
    console.log("PBF: Entered continuous analysis loop.");
    while (this.isActive) {
      if (this.isAnalyzing) { // Still processing the previous item
        await new Promise(resolve => setTimeout(resolve, this.config.itemProcessingCheckIntervalMs || 1000)); // Check back shortly
        continue;
      }

      this.isAnalyzing = true; // Mark as busy for the next item
      let workFound = false;

      try {
        // 1. Process pending external requests first (high priority)
        await this.processPendingRequests(); // Assumes this method processes one or more requests if available

        // 2. Select next file for heuristic sweep / self-directed analysis
        // This part needs to be refactored to select ONE file, or a small batch, then analyze.
        // For now, adapting the existing cycle logic to process ONE file from a potential batch.
        const candidateFile = await this.selectNextFileForHeuristicAnalysis();

        if (candidateFile) {
          workFound = true;
          console.log(`PBF: Selected file for heuristic analysis: ${candidateFile.file}`);
          // --- Adapted single file analysis logic from runAnalysisCycle ---
          const targetFile = candidateFile;
          const fileData = await this.chromiumApi.getFile({ filePath: targetFile.file });
          const currentHash = computeSha256Hash(fileData.content);
          const existingEntry = this.processedItemsHistory[targetFile.file];

          if (existingEntry && existingEntry.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP) && existingEntry.contentHash === currentHash) {
            console.log(`PBF: File ${targetFile.file} (heuristic) already analyzed with same content hash. Updating timestamp.`);
            existingEntry.lastAnalyzed = new Date().toISOString();
            this.processedItemsHistory[targetFile.file] = existingEntry;
            await this.saveState();
          } else {
            let additionalContextForLLM = "";
            const cuaInsights = this.sharedContext?.codebaseInsights;
            if (cuaInsights) {
              const modulePathParts = targetFile.file.split('/');
              modulePathParts.pop();
              const parentModulePath = modulePathParts.join('/');
              const moduleInsight = cuaInsights[parentModulePath];
              if (moduleInsight) {
                additionalContextForLLM += `\n\n--- Context from CUA for module ${parentModulePath} ---\nSummary: ${moduleInsight.summary}\nKey Technologies: ${moduleInsight.keyTechnologies?.join(', ')}\nCommon Risks: ${moduleInsight.commonSecurityRisks?.join(', ')}\n--- End CUA Context ---\n`;
              }
            }

            const analysisSystemPrompt = "You are a security auditor. Analyze the provided C++ code from a Chromium file for potential vulnerabilities. Focus on common C++ pitfalls, IPC issues, or web security concerns. Consider any provided module context. Be concise. If you identify a specific risky function call or pattern, also output a line formatted as: SEARCHABLE_PATTERN: <the_pattern_to_search_for_globally>";
            const analysisUserPrompt = `File: ${targetFile.file}\n${additionalContextForLLM}\n\nCode (first 4000 chars):\n${fileData.content.substring(0,4000)}\n\nIdentify potential vulnerabilities. If you find a specific risky pattern (like a function call or macro usage), include a line: SEARCHABLE_PATTERN: <pattern_string_for_codesearch>`;
            const llmAnalysis = await this.llmComms.sendMessage(analysisUserPrompt, analysisSystemPrompt);

            // ... (pattern extraction and finding push logic as before) ...
             this.sharedContext.findings.push({
                sourceAgent: this.type, type: "PotentialVulnerability",
                data: { file: targetFile.file, analysis: llmAnalysis, snippet: fileData.content.substring(0, 500), relatedOccurrences: [] /* placeholder for extracted patterns */ },
                timestamp: new Date()
            });


            const entryUpdate = this.processedItemsHistory[targetFile.file] || { lastAnalyzed: "", analysisTypes: [], contentHash: "" };
            entryUpdate.lastAnalyzed = new Date().toISOString();
            entryUpdate.contentHash = currentHash;
            if (!entryUpdate.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP)) {
              entryUpdate.analysisTypes.push(this.ANALYSIS_TYPE_HEURISTIC_SWEEP);
            }
            this.processedItemsHistory[targetFile.file] = entryUpdate;
            this.lastAnalysisTimestamp = new Date();
            await this.saveState();
            console.log(`PBF: Heuristic analysis complete for ${targetFile.file}.`);
          }
          // --- End of adapted single file analysis ---
        }
      } catch (error) {
        console.error(`PBF: Error during continuous analysis iteration:`, error);
        // Implement more robust error handling, e.g., backoff on repeated errors
      } finally {
        this.isAnalyzing = false; // Ready for next item
      }

      if (!workFound) {
        // No immediate work (no requests processed, no heuristic file found). Wait before checking again.
        const idleDelayMs = this.config.idleCycleDelayMs || 5000; // Default to 5 seconds
        // console.log(`PBF: No work found, idling for ${idleDelayMs}ms.`);
        await new Promise(resolve => setTimeout(resolve, idleDelayMs));
      }
       // Minimal delay even if work was found, to allow other async operations and prevent tight loop on fast tasks.
      await new Promise(resolve => setTimeout(resolve, this.config.interItemDelayMs || 100));
    }
    console.log("PBF: Exited continuous analysis loop because isActive is false.");
  }


  private async selectNextFileForHeuristicAnalysis(): Promise<SearchResult | undefined> {
    // TODO: Implement a more sophisticated internal work queue and prioritization for PBF.

    // 1. Check for high-priority files from external requests that might need immediate attention
    //    (even though processPendingRequests is called, this allows PBF to "focus" if a request just came in)
    if (this.sharedContext && this.sharedContext.requests) {
        const highPriorityPBFRequest = this.sharedContext.requests.find(
            req => req.targetAgentType === this.type &&
                   req.taskType === "analyze_file_for_vulnerabilities" && // Assuming this is the task type PBF handles
                   req.status === "pending" &&
                   req.params.filePath &&
                   (req.priority ?? 100) < 50 // Example: priority < 50 is high
        );
        if (highPriorityPBFRequest) {
            console.log(`PBF: Prioritizing requested file: ${highPriorityPBFRequest.params.filePath}`);
            // We don't mark it as processed here, processPendingRequests will handle that.
            // This selection just informs the main loop what to focus on if it were to pick self-directed work.
            // However, processPendingRequests already handles this. So, this specific check might be redundant
            // if processPendingRequests is always called before this selection logic in the main loop.
            // For now, let's assume processPendingRequests handles explicit tasks.
        }
    }

    // 2. If no high-priority external requests, proceed with heuristic-based selection.
    let candidateFiles: SearchResult[] = [];
    try {
        // Simplified heuristic: check recent commits in sensitive paths
        // This can be expanded with more heuristics (keyword search in codebase, etc.)
        const query = `(path:${this.config.sensitivePathPatterns?.join(' OR path:')}) (security OR fix OR vuln OR warning OR critical)`;
        const recentCommits = await this.chromiumApi.searchCommits({ query, limit: this.config.maxCandidatesPerHeuristicQuery || 5 });

        if (recentCommits.log && recentCommits.log.length > 0) {
            for (const commit of recentCommits.log) {
                if (commit.files) {
                    for (const filePath of commit.files) {
                        const existing = this.processedItemsHistory[filePath];
                        const isRecentlyChecked = existing && (new Date().getTime() - new Date(existing.lastAnalyzed).getTime()) < (this.config.recheckIntervalMs || 24 * 3600 * 1000);
                        if (isRecentlyChecked) {
                            continue;
                        }
                        // Ensure file is likely a source file, not e.g. OWNERS, README.md if desired
                        if (!filePath.match(/\.(cc|h|cpp|js|ts|java|py)$/i) && !filePath.endsWith('.mojom')) { // Basic filter
                            // console.log(`PBF: Skipping non-source file from commit scan: ${filePath}`);
                            continue;
                        }
                        candidateFiles.push({ file: filePath, line: 0, browserUrl: '', type: 'recent-commit-sensitive' });
                        if (candidateFiles.length >= (this.config.maxCandidatesPerHeuristicQuery || 5)) break;
                    }
                }
                if (candidateFiles.length >= (this.config.maxCandidatesPerHeuristicQuery || 5)) break;
            }
        }
    } catch (e) { console.warn(`PBF: Error gathering candidates for heuristic analysis: ${(e as Error).message}`); }

    if (candidateFiles.length === 0) {
        // TODO: Could try other heuristics here if the first one yields nothing.
        // E.g., search for files with "TODO(security)" or specific risky keywords.
        return undefined;
    }

    // Prioritize and pick one. For now, just pick the first unprocessed or "stale" one.
    // This is where a proper priority queue would be beneficial.
    for (const cand of candidateFiles) {
        const entry = this.processedItemsHistory[cand.file];
        const isStale = entry && (new Date().getTime() - new Date(entry.lastAnalyzed).getTime()) > (this.config.recheckIntervalMs || 7 * 24 * 3600 * 1000);

        if (!entry || !entry.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP) || isStale) {
            // TODO: Could add content hash check here if possible before returning,
            // but that requires fetching file content, which we want to do only for the selected file.
            // The main loop already does this.
            return cand;
        }
    }
    // console.log("PBF: No suitable new/stale candidates from current heuristic query.");
    return undefined;
  }


  public async analyzeSpecificFile(filePath: string, analysisType: string = this.ANALYSIS_TYPE_SPECIFIC_REQUEST): Promise<string> {
    // No longer checks this.isActive, can be called even if periodic scan is "stopped"
    if (!this.chromiumApi) return "Agent not ready (ChromiumAPI missing).";
    try {
      const fileData = await this.chromiumApi.getFile({ filePath }); const currentHash = computeSha256Hash(fileData.content);
      // TODO: Incorporate context from CUA if available for this file's module from sharedContext.codebaseInsights
      const analysisPrompt = `Analyze file ${filePath} for potential security vulnerabilities. Consider common C++ pitfalls, IPC issues, memory safety, and web security concerns relevant to Chromium. Be concise. If you identify a specific risky function call or pattern, also output a line formatted as: SEARCHABLE_PATTERN: <the_pattern_to_search_for_globally>`;
      const analysis = await this.llmComms.sendMessage(analysisPrompt, "You are a security auditor for Chromium source code.");
      this.sharedContext.findings.push({ sourceAgent:this.type, type:"SpecificFileAnalysis", data:{file:filePath, analysis:analysis, snippet:fileData.content.substring(0,500)}, timestamp:new Date() });

      const entry = this.processedItemsHistory[filePath] || { lastAnalyzed: "", analysisTypes: [] };
      entry.lastAnalyzed = new Date().toISOString(); entry.contentHash = currentHash;
      if (!entry.analysisTypes.includes(analysisType)) entry.analysisTypes.push(analysisType);
      this.processedItemsHistory[filePath] = entry;
      await this.saveState();
      return analysis;
    } catch (e) { const err=e as Error; console.error(`PBF: Error specific analysis ${filePath}:`, err); return `Error: ${err.message}`; }
  }

  public async processPendingRequests(): Promise<void> {
    if (!this.sharedContext || !this.sharedContext.requests) return;

    const pendingRequests = this.sharedContext.requests.filter(
      req => req.targetAgentType === this.type && req.status === "pending"
    ).sort((a,b) => (a.priority ?? 100) - (b.priority ?? 100)); // Process higher priority first

    if (pendingRequests.length === 0) return;
    console.log(`PBF: Found ${pendingRequests.length} pending request(s).`);

    for (const request of pendingRequests.slice(0, 1)) { // Process one request per cycle to avoid overload
      console.log(`PBF: Processing request ${request.requestId} (${request.taskType})`);
      request.status = "in_progress";
      request.updatedAt = new Date().toISOString();

      try {
        switch (request.taskType) {
          case "analyze_file_for_vulnerabilities":
            if (!request.params.filePath || typeof request.params.filePath !== 'string') {
              throw new Error("Missing or invalid filePath parameter for analyze_file_for_vulnerabilities");
            }
            request.result = await this.analyzeSpecificFile(request.params.filePath, this.ANALYSIS_TYPE_SPECIFIC_REQUEST);
            break;
          default:
            throw new Error(`Unsupported task type for PBF: ${request.taskType}`);
        }
        request.status = "completed";
      } catch (error) {
        console.error(`PBF: Error processing request ${request.requestId}:`, error);
        request.status = "failed";
        request.error = (error as Error).message;
      }
      request.updatedAt = new Date().toISOString();
      // Update the request in sharedContext by finding its index
      const reqIndex = this.sharedContext.requests.findIndex(r => r.requestId === request.requestId);
      if (reqIndex !== -1) this.sharedContext.requests[reqIndex] = request;
    }
  }
}

// --- BugPatternAnalysisAgent --- (This is the agent being modified in this step)
export class BugPatternAnalysisAgent implements SpecializedAgent {
  public type = SpecializedAgentType.BugPatternAnalysis;
  private llmComms: LLMCommunication;
  private storage: PersistentStorage;
  private chromiumApi: ChromiumAPI;
  private sharedContext!: SharedAgentContextType;
  private config: BugPatternAnalysisConfig;
  private patternIdCounter: number = 0;
  private processedItemsHistory: ProcessedItemsHistory = {};
  private isActive: boolean = false;
  private isExtracting: boolean = false; // For pattern extraction
  private isIssueScanning: boolean = false; // For issue scanning
  private lastPatternExtraction?: Date;
  private lastIssueScan?: Date;
  private patternExtractionIntervalId?: NodeJS.Timeout;
  private issueAnalysisIntervalId?: NodeJS.Timeout;


  private readonly ANALYSIS_TYPE_COMMIT = "bpa_commit_analysis";
  private readonly ANALYSIS_TYPE_ISSUE = "bpa_issue_analysis";

  constructor( llmComms: LLMCommunication, chromiumApi: ChromiumAPI, sharedContext: SharedAgentContextType, config: BugPatternAnalysisConfig ) {
    this.llmComms = llmComms; this.chromiumApi = chromiumApi; this.config = config;
    this.storage = new PersistentStorage('BugPatternAnalysis_data');
    this.setSharedContext(sharedContext); console.log("Bug Pattern Analysis agent initialized."); this.loadState();
  }
  public setSharedContext(context: SharedAgentContextType): void { this.sharedContext = context; if(!this.sharedContext.knownBugPatterns) this.sharedContext.knownBugPatterns = []; }
  private async loadState(): Promise<void> {
    const state = await this.storage.loadData<{ lastExtraction?: string; lastIssueScan?: string; patterns?: Array<BugPattern|string>; patternIdCounter?: number; processedCommitIds?: string[]; processedIssueIds?: string[]; processedItemsHistory?: ProcessedItemsHistory; }>();
    if (state) {
      if (state.lastExtraction) this.lastPatternExtraction = new Date(state.lastExtraction);
      if (state.lastIssueScan) this.lastIssueScan = new Date(state.lastIssueScan);
      if (state.patterns) this.sharedContext.knownBugPatterns = state.patterns.map(p => typeof p === 'string' ? {id:`BPA-OLD-${Math.random().toString(36).substring(2,9)}`, name:"Legacy", description:p, tags:["legacy"], source:"Migrated"} : p);
      this.patternIdCounter = state.patternIdCounter || this.sharedContext.knownBugPatterns.length;
      if (state.processedItemsHistory) this.processedItemsHistory = state.processedItemsHistory;
      else {
        this.processedItemsHistory = {}; const now = new Date().toISOString();
        if (state.processedCommitIds && Array.isArray(state.processedCommitIds)) {
          state.processedCommitIds.forEach(id => { this.processedItemsHistory[id] = { lastAnalyzed: now, analysisTypes: [this.ANALYSIS_TYPE_COMMIT + "_legacy"]}; });
        }
        if (state.processedIssueIds && Array.isArray(state.processedIssueIds)) {
          state.processedIssueIds.forEach(id => { this.processedItemsHistory[id] = { lastAnalyzed: now, analysisTypes: [this.ANALYSIS_TYPE_ISSUE + "_legacy"]}; });
        }
      }
      console.log(`BPA: Loaded ${Object.keys(this.processedItemsHistory).length} items into history.`);
    }
  }
  private async saveState(): Promise<void> {
    const maxItems = this.config.maxProcessedHistorySize || 200; const keys = Object.keys(this.processedItemsHistory);
    if (keys.length > maxItems) {
      const sorted = keys.sort((a,b) => new Date(this.processedItemsHistory[a].lastAnalyzed).getTime() - new Date(this.processedItemsHistory[b].lastAnalyzed).getTime());
      for(let i=0; i < keys.length - maxItems; i++) delete this.processedItemsHistory[sorted[i]];
    }
    await this.storage.saveData({ lastExtraction: this.lastPatternExtraction?.toISOString(), lastIssueScan: this.lastIssueScan?.toISOString(), patterns: [...this.sharedContext.knownBugPatterns], patternIdCounter: this.patternIdCounter, processedItemsHistory: this.processedItemsHistory });
  }

  public async start(): Promise<void> {
    if(this.isActive)return;
    this.isActive=true;
    this.isExtracting = false;
    this.isIssueScanning = false;
    console.log("BPA: Continuous operation started.");
    this.runContinuousProcessingLoop().catch(e => {
        console.error("BPA: ContinuousProcessingLoop encountered critical error and exited:", e);
        this.isActive = false; // Stop if the main loop crashes
    });
  }

  public async stop(): Promise<void> {
    this.isActive=false; // Signal the loop to stop
    console.log("BPA: Continuous operation signaled to stop.");
  }

  public async getStatus(): Promise<string> {
    let s = `BPA: ${this.isActive?'Continuous - Running':'Idle/Stopped'}. Patterns: ${this.sharedContext.knownBugPatterns.length}.`;
    s += ` ${this.isExtracting ? 'Processing Commit.' : ''} ${this.isIssueScanning ? 'Processing Issue.' : ''}`;
    if(this.lastPatternExtraction) s+=` Last Commit Processed: ${this.lastPatternExtraction.toLocaleTimeString()}.`;
    if(this.lastIssueScan) s+=` Last Issue Processed: ${this.lastIssueScan.toLocaleTimeString()}.`;
    s+=` History: ${Object.keys(this.processedItemsHistory).length} items.`;
    // TODO: Add internal queue sizes if implemented
    return s;
  }

  // Renamed and refactored main loop
  private async runContinuousProcessingLoop(): Promise<void> {
    console.log("BPA: Entered continuous processing loop.");
    let lastProcessedType: 'commit' | 'issue' = 'issue'; // To alternate tasks

    while (this.isActive) {
      if (this.isExtracting || this.isIssueScanning) {
        await new Promise(resolve => setTimeout(resolve, this.config.itemProcessingCheckIntervalMsBPA || 1000));
        continue;
      }
      let workFoundThisIteration = false;

      try {
        // 1. Process pending external requests first
        await this.processPendingRequests();

        // 2. Alternate between processing commits and issues
        if (lastProcessedType === 'issue') {
          this.isExtracting = true; // Mark as busy with commit processing
          const commitToProcess = await this.selectNextCommitForAnalysis();
          if (commitToProcess) {
            workFoundThisIteration = true;
            console.log(`BPA: Selected commit for analysis: ${commitToProcess.commit.substring(0, 12)}...`);
            await this.analyzeCommit(commitToProcess); // This is the refactored single commit analysis logic
            this.lastPatternExtraction = new Date();
            await this.saveState();
            console.log(`BPA: Analysis complete for commit ${commitToProcess.commit.substring(0,12)}.`);
          }
          lastProcessedType = 'commit';
          this.isExtracting = false;
        } else { // lastProcessedType === 'commit'
          this.isIssueScanning = true; // Mark as busy with issue processing
          const issueToProcess = await this.selectNextIssueForAnalysis();
          if (issueToProcess) {
            workFoundThisIteration = true;
            console.log(`BPA: Selected issue for analysis: ${issueToProcess.id}`);
            await this.analyzeIssue(issueToProcess); // This is the refactored single issue analysis logic
            this.lastIssueScan = new Date();
            await this.saveState();
            console.log(`BPA: Analysis complete for issue ${issueToProcess.id}.`);
          }
          lastProcessedType = 'issue';
          this.isIssueScanning = false;
        }
      } catch (error) {
        console.error("BPA: Error during continuous processing iteration:", error);
        // Reset flags in case of error within analyzeCommit/analyzeIssue
        this.isExtracting = false; this.isIssueScanning = false;
      } finally {
        // Ensure flags are reset if an error didn't occur in analyzeCommit/analyzeIssue but before them
        this.isExtracting = false; this.isIssueScanning = false;
      }

      if (!workFoundThisIteration) {
        const idleDelayMs = this.config.idleCycleDelayMsBPA || 15000; // Default to 15 seconds
        // console.log(`BPA: No new commits or issues found, idling for ${idleDelayMs}ms.`);
        await new Promise(resolve => setTimeout(resolve, idleDelayMs));
      }
      await new Promise(resolve => setTimeout(resolve, this.config.interItemDelayMsBPA || 200));
    }
    console.log("BPA: Exited continuous processing loop because isActive is false.");
  }


  // Placeholder for selecting next commit - extract from old runPatternExtractionCycle
  private async selectNextCommitForAnalysis(): Promise<any | undefined> {
    // Simplified: fetch a few recent commits and pick the first unprocessed one.
    // TODO: Implement proper internal queue & prioritization for commits.
    let relevantCommits:any[]=[];
    try {
        const r = await this.chromiumApi.searchCommits({query:'fix security OR cve-', limit: (this.config.commitsPerCycle||1)*2 }); // Fetch a bit more
        relevantCommits=(r.log||[]).filter((c:any)=>c.message.toLowerCase().includes('security')||c.message.toLowerCase().includes('vuln'));
    } catch(e) { console.error("BPA: Failed commit search during selection",e); return undefined; }

    const newCommits = relevantCommits.filter(c => {
        const id=c.commit; if(!id)return false;
        const e=this.processedItemsHistory[id];
        return !e || !e.analysisTypes.includes(this.ANALYSIS_TYPE_COMMIT);
    });
    return newCommits.length > 0 ? newCommits[0] : undefined;
  }

  // Placeholder for selecting next issue - extract from old runIssueAnalysisCycle
  private async selectNextIssueForAnalysis(): Promise<any | undefined> {
    // Simplified: fetch a few recent issues and pick the first unprocessed one.
    // TODO: Implement proper internal queue & prioritization for issues.
    let relevantIssues:any[]=[];
    try {
        let q='type:vulnerability status:fixed';
        if(this.config.targetIssueSeverities?.length)q+=` (${this.config.targetIssueSeverities.map(s=>`severity:${s}`).join(" OR ")})`;
        else q+=` (security OR vulnerability)`;
        const r=await this.chromiumApi.searchIssues(q, (this.config.issuesPerCycle||1)*2 ); // Fetch a bit more
        relevantIssues=r.issues||[];
    } catch(e) { console.error("BPA: Failed issue search during selection",e); return undefined; }

    const newIssues=relevantIssues.filter(i=>{
        const id=i.id?.toString(); if(!id)return false;
        const e=this.processedItemsHistory[id];
        return !e||!e.analysisTypes.includes(this.ANALYSIS_TYPE_ISSUE);
    });
    return newIssues.length > 0 ? newIssues[0] : undefined;
  }

  // Refactored logic to analyze a single commit
  private async analyzeCommit(commit: any): Promise<void> {
    const id = commit.commit;
    try {
      let clComments = ""; // Fetch comments if necessary
      const prompt = `Commit:\n${commit.message}\n${clComments}\nExtract BugPattern JSON...`;
      const sysPrompt = "JSON output for BugPattern...";
      const llmJson = await this.llmComms.sendMessage(prompt, sysPrompt);
      const pData: Partial<BugPattern> = JSON.parse(llmJson);
      const nP: BugPattern = {
        id: `BPA-C-${Date.now()}-${++this.patternIdCounter}`,
        name: pData.name || `From ${id.substring(0, 7)}`,
        description: pData.description || "",
        tags: pData.tags || [],
        source: `Commit ${id.substring(0, 7)}`
      };
      if (!this.sharedContext.knownBugPatterns.find(p => (typeof p !== 'string' && p.id === nP.id))) {
        this.sharedContext.knownBugPatterns.push(nP);
      }
      const entry = this.processedItemsHistory[id] || { lastAnalyzed: "", analysisTypes: [] };
      entry.lastAnalyzed = new Date().toISOString();
      if (!entry.analysisTypes.includes(this.ANALYSIS_TYPE_COMMIT)) entry.analysisTypes.push(this.ANALYSIS_TYPE_COMMIT);
      this.processedItemsHistory[id] = entry;
    } catch (e) { console.error(`BPA: Error processing commit ${id}`, e); }
  }


  // Refactored logic to analyze a single issue
  private async analyzeIssue(issue: any): Promise<void> {
    const id = issue.id.toString();
    try {
      const details = await this.chromiumApi.getIssue(id);
      if (!details?.description) {
        this.processedItemsHistory[id] = { lastAnalyzed: new Date().toISOString(), analysisTypes: [this.ANALYSIS_TYPE_ISSUE] };
        return;
      }
      let commentsText = ""; // Extract comments if necessary
      const prompt = `Issue: ${details.title}\n${details.description.substring(0, 1000)}\n${commentsText}\nExtract BugPattern JSON...`;
      const sysPrompt = "JSON for BugPattern...";
      const llmJson = await this.llmComms.sendMessage(prompt, sysPrompt);
      const pData: Partial<BugPattern> = JSON.parse(llmJson);
      const nP: BugPattern = {
        id: `BPA-I-${Date.now()}-${++this.patternIdCounter}`,
        name: pData.name || `From Issue ${id}`,
        description: pData.description || "",
        tags: pData.tags || [],
        source: `Issue ${id}`
      };
      if (!this.sharedContext.knownBugPatterns.find(p => (typeof p !== 'string' && p.id === nP.id))) {
        this.sharedContext.knownBugPatterns.push(nP);
      }
      const entry = this.processedItemsHistory[id] || { lastAnalyzed: "", analysisTypes: [] };
      entry.lastAnalyzed = new Date().toISOString();
      if (!entry.analysisTypes.includes(this.ANALYSIS_TYPE_ISSUE)) entry.analysisTypes.push(this.ANALYSIS_TYPE_ISSUE);
      this.processedItemsHistory[id] = entry;
    } catch (e) { console.error(`BPA: Error processing issue ${id}`, e); }
  }

  // Original runPatternExtractionCycle and runIssueAnalysisCycle are now effectively replaced by the
  // continuous loop and the single item processing methods (analyzeCommit, analyzeIssue)
  // combined with selection methods (selectNextCommitForAnalysis, selectNextIssueForAnalysis).
  // The old batch processing logic within those cycles is now handled one by one in the continuous loop.

  /*
  private async runPatternExtractionCycle(): Promise<void> { // KEEPING OLD METHOD SIGNATURE FOR NOW, BUT IT'S REPLACED
    if(!this.isActive || this.isExtracting) {
      if(this.isExtracting) console.log("BPA: Pattern extraction already in progress. Skipping.");
      return;
    }
    this.isExtracting = true;
    console.log(`BPA: Starting commit scan (type: ${this.ANALYSIS_TYPE_COMMIT})`);
    let relevantCommits:any[]=[]; try{ const r = await this.chromiumApi.searchCommits({query:'fix security OR cve-', limit:(this.config.commitsPerCycle||2)*2}); relevantCommits=(r.log||[]).filter((c:any)=>c.message.toLowerCase().includes('security')||c.message.toLowerCase().includes('vuln'));}catch(e){console.error("BPA: Failed commit search",e);return;}
    const newCommits = relevantCommits.filter(c => { const id=c.commit; if(!id)return false; const e=this.processedItemsHistory[id]; return !e || !e.analysisTypes.includes(this.ANALYSIS_TYPE_COMMIT); });
    if(newCommits.length===0){console.log("BPA: No new commits."); await this.saveState(); return;}
    const toProcess = newCommits.slice(0,this.config.commitsPerCycle||2); console.log(`BPA: Analyzing ${toProcess.length} new commits.`);
    for(const commit of toProcess){
      const id=commit.commit; try{
        let clComments=""; /* ... fetch comments for commit.changeId ... */
        const prompt = `Commit:\n${commit.message}\n${clComments}\nExtract BugPattern JSON...`; const sysPrompt = "JSON output for BugPattern...";
        const llmJson = await this.llmComms.sendMessage(prompt,sysPrompt); const pData:Partial<BugPattern> = JSON.parse(llmJson);
        const nP:BugPattern={id:`BPA-C-${Date.now()}-${++this.patternIdCounter}`,name:pData.name||`From ${id.substring(0,7)}`,description:pData.description||"",tags:pData.tags||[],source:`Commit ${id.substring(0,7)}`};
        if(!this.sharedContext.knownBugPatterns.find(p=>(typeof p !== 'string' && p.id===nP.id)))this.sharedContext.knownBugPatterns.push(nP);
        const entry=this.processedItemsHistory[id]||{lastAnalyzed:"",analysisTypes:[]}; entry.lastAnalyzed=new Date().toISOString(); if(!entry.analysisTypes.includes(this.ANALYSIS_TYPE_COMMIT))entry.analysisTypes.push(this.ANALYSIS_TYPE_COMMIT); this.processedItemsHistory[id]=entry;
      }catch(e){console.error(`BPA: Error commit ${id}`,e);}
    }
    this.lastPatternExtraction=new Date();
    await this.saveState();
    console.log("BPA: Commit scan done.");
    this.isExtracting = false;
  }

  public async runIssueAnalysisCycle(): Promise<void> {
    if(!this.isActive || this.isIssueScanning) {
      if(this.isIssueScanning) console.log("BPA: Issue analysis already in progress. Skipping.");
      return;
    }
    this.isIssueScanning = true;
    console.log(`BPA: Starting issue scan (type: ${this.ANALYSIS_TYPE_ISSUE})`);
    let relevantIssues:any[]=[]; try{ let q='type:vulnerability status:fixed'; if(this.config.targetIssueSeverities?.length)q+=` (${this.config.targetIssueSeverities.map(s=>`severity:${s}`).join(" OR ")})`; else q+=` (security OR vulnerability)`; const r=await this.chromiumApi.searchIssues(q); relevantIssues=r.issues||[];}catch(e){console.error("BPA: Failed issue search",e);return;} // Changed searchIssues call
    const newIssues=relevantIssues.filter(i=>{const id=i.id?.toString();if(!id)return false;const e=this.processedItemsHistory[id];return !e||!e.analysisTypes.includes(this.ANALYSIS_TYPE_ISSUE);});
    if(newIssues.length===0){console.log("BPA: No new issues."); await this.saveState();return;}
    const toProcess=newIssues.slice(0,this.config.commitsPerCycle||2); console.log(`BPA: Analyzing ${toProcess.length} new issues.`);
    for(const issue of toProcess){
      const id=issue.id.toString(); try{
        const details=await this.chromiumApi.getIssue(id); if(!details?.description){this.processedItemsHistory[id]={lastAnalyzed:new Date().toISOString(),analysisTypes:[this.ANALYSIS_TYPE_ISSUE]};continue;}
        let commentsText = ""; /* ... extract comments ... */
        const prompt = `Issue: ${details.title}\n${details.description.substring(0,1000)}\n${commentsText}\nExtract BugPattern JSON...`; const sysPrompt = "JSON for BugPattern...";
        const llmJson = await this.llmComms.sendMessage(prompt,sysPrompt); const pData:Partial<BugPattern> = JSON.parse(llmJson);
        const nP:BugPattern={id:`BPA-I-${Date.now()}-${++this.patternIdCounter}`,name:pData.name||`From Issue ${id}`,description:pData.description||"",tags:pData.tags||[],source:`Issue ${id}`};
        if(!this.sharedContext.knownBugPatterns.find(p=>(typeof p !== 'string' && p.id===nP.id)))this.sharedContext.knownBugPatterns.push(nP);
        const entry=this.processedItemsHistory[id]||{lastAnalyzed:"",analysisTypes:[]}; entry.lastAnalyzed=new Date().toISOString(); if(!entry.analysisTypes.includes(this.ANALYSIS_TYPE_ISSUE))entry.analysisTypes.push(this.ANALYSIS_TYPE_ISSUE); this.processedItemsHistory[id]=entry;
      }catch(e){console.error(`BPA: Error issue ${id}`,e);}
    }
    this.lastIssueScan = new Date();
    await this.saveState();
    console.log("BPA: Issue scan done.");
    this.isIssueScanning = false;
  }
  public async getContextualAdvice(codeSnippet: string): Promise<string> {
    if (!this.llmComms) return "BPA: LLM not available.";
    if (this.sharedContext.knownBugPatterns.length === 0) return "BPA: No known bug patterns loaded to compare against.";

    const systemPrompt = `You are a security expert. Given a code snippet and a list of known bug patterns, identify if any patterns are relevant and provide advice. Be concise.`;
    let userPrompt = `Code Snippet:\n\`\`\`\n${codeSnippet}\n\`\`\`\n\nKnown Bug Patterns (summarized):\n`;
    this.sharedContext.knownBugPatterns.slice(0, 10).forEach((p: BugPattern | string) => { // Consider top 10 patterns
        if (typeof p === 'string') {
            userPrompt += `- ${p.substring(0,150)}...\n`;
        } else {
            userPrompt += `- ${p.name}: ${p.description.substring(0,100)}... (Severity: ${p.severity || 'N/A'})\n`;
        }
    });
    userPrompt += "\nAre any of these patterns relevant? If so, which ones and why? Provide brief advice.";

    try {
        const advice = await this.llmComms.sendMessage(userPrompt, systemPrompt);
        return advice;
    } catch (e) {
        console.error("BPA: Error getting contextual advice from LLM:", e);
        return "BPA: Error processing advice request.";
    }
  }

  public async processPendingRequests(): Promise<void> {
    if (!this.sharedContext || !this.sharedContext.requests) return;

    const pendingRequests = this.sharedContext.requests.filter(
      req => req.targetAgentType === this.type && req.status === "pending"
    ).sort((a,b) => (a.priority ?? 100) - (b.priority ?? 100));

    if (pendingRequests.length === 0) return;
    console.log(`BPA: Found ${pendingRequests.length} pending request(s).`);

    for (const request of pendingRequests.slice(0, 1)) { // Process one request per cycle
      console.log(`BPA: Processing request ${request.requestId} (${request.taskType})`);
      request.status = "in_progress";
      request.updatedAt = new Date().toISOString();
      try {
        switch (request.taskType) {
          case "get_contextual_advice_for_snippet":
            if (!request.params.codeSnippet || typeof request.params.codeSnippet !== 'string') {
              throw new Error("Missing or invalid codeSnippet parameter");
            }
            request.result = await this.getContextualAdvice(request.params.codeSnippet);
            break;
          // TODO: Could add task like "extract_patterns_from_text" if BPA is to be more dynamic
          default:
            throw new Error(`Unsupported task type for BPA: ${request.taskType}`);
        }
        request.status = "completed";
      } catch (error) {
        console.error(`BPA: Error processing request ${request.requestId}:`, error);
        request.status = "failed";
        request.error = (error as Error).message;
      }
      request.updatedAt = new Date().toISOString();
      const reqIndex = this.sharedContext.requests.findIndex(r => r.requestId === request.requestId);
      if (reqIndex !== -1) this.sharedContext.requests[reqIndex] = request;
    }
  }
}

// --- CodebaseUnderstandingAgent ---
export class CodebaseUnderstandingAgent implements SpecializedAgent {
  public type = SpecializedAgentType.CodebaseUnderstanding;
  private llmComms: LLMCommunication; private storage: PersistentStorage; private chromiumApi: ChromiumAPI;
  private isActive: boolean = false;
  private isAnalyzing: boolean = false; // To prevent concurrent cycle runs
  private analysisIntervalId?: NodeJS.Timeout;
  private lastModuleAnalysis?: Date;
  private sharedContext!: SharedAgentContextType; private config: CodebaseUnderstandingConfig;
  private processedItemsHistory: ProcessedItemsHistory = {};
  private readonly ANALYSIS_TYPE_MODULE = "cua_module_analysis";

  constructor( llmComms: LLMCommunication, chromiumApi: ChromiumAPI, sharedContext: SharedAgentContextType, config: CodebaseUnderstandingConfig ) {
    this.llmComms = llmComms; this.chromiumApi = chromiumApi; this.config = config;
    this.storage = new PersistentStorage('CodebaseUnderstanding_data');
    this.setSharedContext(sharedContext); console.log("Codebase Understanding agent initialized."); this.loadState();
  }
  public setSharedContext(context: SharedAgentContextType): void { this.sharedContext = context; if(!this.sharedContext.codebaseInsights) this.sharedContext.codebaseInsights = {}; }
  private async loadState(): Promise<void> {
    const state = await this.storage.loadData<{ lastAnalysis?: string; insights?: Record<string, CodebaseModuleInsight>; processedItemsHistory?: ProcessedItemsHistory; }>();
    if (state) {
      if (state.lastAnalysis) this.lastModuleAnalysis = new Date(state.lastAnalysis);
      if (state.insights) this.sharedContext.codebaseInsights = state.insights;
      this.processedItemsHistory = state.processedItemsHistory || {};
      console.log(`CUA: Loaded ${Object.keys(this.sharedContext.codebaseInsights).length} insights, ${Object.keys(this.processedItemsHistory).length} processed modules.`);
    }
  }
  private async saveState(): Promise<void> {
    const maxItems = this.config.maxProcessedModuleHistory || 50;
    const keys = Object.keys(this.processedItemsHistory);
    if (keys.length > maxItems) {
        const sorted = keys.sort((a,b) => new Date(this.processedItemsHistory[a].lastAnalyzed).getTime() - new Date(this.processedItemsHistory[b].lastAnalyzed).getTime());
        for(let i=0; i < keys.length - maxItems; i++) delete this.processedItemsHistory[sorted[i]];
    }
    await this.storage.saveData({
        lastAnalysis: this.lastModuleAnalysis?.toISOString(),
        insights: this.sharedContext.codebaseInsights,
        processedItemsHistory: this.processedItemsHistory
    });
  }

  public async start(): Promise<void> {
    if (this.isActive) return;
    this.isActive = true;
    this.isAnalyzing = false;
    console.log("CUA: Continuous operation started.");
    this.runContinuousModuleAnalysisLoop().catch(e => {
        console.error("CUA: ContinuousModuleAnalysisLoop encountered critical error and exited:", e);
        this.isActive = false; // Stop if the main loop crashes
    });
  }

  public async stop(): Promise<void> {
    this.isActive = false; // Signal the loop to stop
    console.log("CUA: Continuous operation signaled to stop.");
  }

  public async getStatus(): Promise<string> {
    let s = `CUA: ${this.isActive?'Continuous - Running':'Idle/Stopped'}. Insights: ${Object.keys(this.sharedContext.codebaseInsights).length}.`;
    s += ` ${this.isAnalyzing ? 'Processing Module.' : 'Awaiting next module/discovery.'}`;
    if(this.lastModuleAnalysis) s+=` Last Module Processed At: ${this.lastModuleAnalysis.toLocaleTimeString()}.`;
    s+=` Processed History: ${Object.keys(this.processedItemsHistory).length} modules.`;
    // TODO: Add internal queue size if implemented
    return s;
  }

  private parseOwnersFileContent(content: string): string[] {
    const owners: string[] = [];
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmedLine = line.trim();
      if (trimmedLine.startsWith('#') || trimmedLine === '') continue; // Skip comments and empty lines
      if (trimmedLine.startsWith('per-file')) continue; // Skip per-file rules for module owners
      if (trimmedLine === '*') continue; // Wildcard, not a specific owner email
      // Add more sophisticated parsing if needed (e.g., set noparent, file= directives)
      if (trimmedLine.includes('@')) { // Basic email check
        owners.push(trimmedLine.split(' ')[0]); // Take first part if line has comments like " # foo"
      }
    }
    return owners;
  }

  private async runContinuousModuleAnalysisLoop(): Promise<void> {
    console.log("CUA: Entered continuous module analysis loop.");
    while (this.isActive) {
      if (this.isAnalyzing) {
        await new Promise(resolve => setTimeout(resolve, this.config.itemProcessingCheckIntervalMsCUA || 1000));
        continue;
      }
      this.isAnalyzing = true;
      let workFoundThisIteration = false;

      try {
        // 1. Process pending external requests first
        await this.processPendingRequests();

        // 2. Select next module for self-directed analysis
        const moduleToAnalyze = await this.selectNextModuleToAnalyzeForContinuousRun(); // New selection method
        if (moduleToAnalyze) {
          workFoundThisIteration = true;
          console.log(`CUA: Selected module for analysis: ${moduleToAnalyze}`);
          // The existing performSingleModuleAnalysis is for a *single* module, so we can call it.
          await this.performSingleModuleAnalysis(moduleToAnalyze);
        }
      } catch (error) {
        console.error("CUA: Error during continuous module analysis iteration:", error);
      } finally {
        this.isAnalyzing = false;
      }

      if (!workFoundThisIteration) {
        const idleDelayMs = this.config.idleCycleDelayMsCUA || 30000; // Default to 30 seconds
        // console.log(`CUA: No new modules to analyze, idling for ${idleDelayMs}ms.`);
        await new Promise(resolve => setTimeout(resolve, idleDelayMs));
      }
      await new Promise(resolve => setTimeout(resolve, this.config.interItemDelayMsCUA || 500));
    }
    console.log("CUA: Exited continuous module analysis loop because isActive is false.");
  }

  // Renamed from runModuleAnalysisCycle to reflect it processes a single, specific module.
  private async performSingleModuleAnalysis(modulePath: string): Promise<void> {
    // This method now assumes modulePath is always provided.
    // The continuous loop calls this with a selected module.
    // External requests (via processPendingRequests) will also call this with a specific module.
    console.log(`CUA: Starting analysis for specific module: ${modulePath}`);

    const historyEntry = this.processedItemsHistory[modulePath];
    // If called from continuous loop (not an explicit request), check staleness.
    // For an explicit request (e.g. user asks "!workflow targeted-module-audit module_X"), we might always re-run or have different logic.
    // For simplicity now, if it's in history and not "too old", we might skip even if explicitly asked unless a "force" flag is introduced.
    if (historyEntry && historyEntry.analysisTypes.includes(this.ANALYSIS_TYPE_MODULE)) {
      const lastAnalyzedDate = new Date(historyEntry.lastAnalyzed);
      const stalenessThresholdDays = this.config.moduleInsightStalenessDays || 30;
      if ((new Date().getTime() - lastAnalyzedDate.getTime()) / (1000 * 3600 * 24) < stalenessThresholdDays) {
        console.log(`CUA: Module ${modulePath} analyzed recently (${lastAnalyzedDate.toLocaleDateString()}). Skipping deep re-analysis unless forced.`);
        // We might still update the lastModuleAnalysis timestamp for this "check"
        this.lastModuleAnalysis = new Date(); // Reflects it was considered
        return;
      }
    }

    try {
      // 1. Gather Information
      const targetModulePath = modulePath; // Use the provided path
      let primaryOwners: string[] = [];
      try {
        const ownersResults = await this.chromiumApi.searchCode({ query: `file:${targetModulePath}/OWNERS`, limit: 1 });
        if (ownersResults.length > 0) {
          const ownersFile = await this.chromiumApi.getFile({ filePath: ownersResults[0].file });
          // Content from getFile is already decoded and includes line numbers, need raw content for parsing.
          // HACK: Refetch raw content for parsing OWNERS. Ideally getFile would offer raw option or searchCode provides content.
          const rawOwnersContentResponse = await fetch(`https://chromium.googlesource.com/chromium/src/+/main/${ownersResults[0].file}?format=TEXT`);
          if (rawOwnersContentResponse.ok) {
            const base64Content = await rawOwnersContentResponse.text();
            const rawOwnersContent = Buffer.from(base64Content, 'base64').toString('utf-8');
            primaryOwners = this.parseOwnersFileContent(rawOwnersContent);
          }
        }
      } catch (e) { console.error(`CUA: Error fetching OWNERS for ${targetModulePath}:`, e); }

      let mojoInterfaces: SearchResult[] = [];
      try {
        mojoInterfaces = await this.chromiumApi.searchCode({ query: `content:"interface " file:${targetModulePath}/.*\\.mojom`, limit: 10 });
      } catch (e) { console.error(`CUA: Error searching Mojo interfaces for ${targetModulePath}:`, e); }

      let ipcHandlers: SearchResult[] = [];
      try {
        ipcHandlers = await this.chromiumApi.searchCode({ query: `content:"IPC_MESSAGE_HANDLER" file:${targetModulePath}/.*\\.(cc|h)`, limit: 10 });
      } catch (e) { console.error(`CUA: Error searching IPC handlers for ${targetModulePath}:`, e); }

      let recentCommitsRaw: any = { log: [] };
      try {
        recentCommitsRaw = await this.chromiumApi.searchCommits({ query: `path:${targetModulePath} (security OR fix OR vuln OR refactor)`, limit: 5 });
      } catch (e) { console.error(`CUA: Error searching commits for ${targetModulePath}:`, e); }

      const recentCommits: AnalyzedCommitInfo[] = (recentCommitsRaw.log || []).map((commit: any) => ({
        cl: commit.commit, // Assuming commit hash is the CL identifier here; may need parsing for Gerrit URL
        subject: commit.message.split('\n')[0], // First line as subject
        date: commit.author?.time, // Assuming this is a parsable date string
        author: commit.author?.email,
        // keyFilesChanged: commit.files_changed_within_module // This would require more processing
      }));

      // 2. LLM Synthesis
      const synthesisSystemPrompt = "You are a Chromium codebase analysis expert. Synthesize a module insight object.";
      const synthesisUserPrompt = `
Analyze the Chromium module: "${targetModulePath}" based on the following gathered data.
Provide a concise overall summary. Identify key files and their purposes. List interaction points (Mojo, IPC).
List key technologies used. Identify common security risks or considerations for this module.

Data:
- Primary Owners (from OWNERS): ${primaryOwners.join(', ') || 'N/A'}
- Potential Mojo Interfaces (files ending in .mojom with "interface "):
${mojoInterfaces.map(r => `  - ${r.file} (line ${r.line})`).join('\n') || '  N/A'}
- Potential IPC Handlers (files with "IPC_MESSAGE_HANDLER"):
${ipcHandlers.map(r => `  - ${r.file} (line ${r.line})`).join('\n') || '  N/A'}
- Recent Significant Commits:
${recentCommits.map(c => `  - ${c.subject} (Author: ${c.author}, Date: ${c.date})`).join('\n') || '  N/A'}

Output a JSON object matching the CodebaseModuleInsight structure, focusing on:
"summary": (string)
"keyFiles": [{ "filePath": string, "description": string, "primaryPurpose": string, "owners": string[] (if discernible) }] (List up to 3-5 key files)
"interactionPoints": [{ "type": "mojo_interface" | "ipc_handler" | "public_api", "name": string, "filePath": string }]
"keyTechnologies": string[]
"commonSecurityRisks": string[]
"documentationLinks": string[] (Try to infer common locations like README.md within the module path)
`;

      const llmResponse = await this.llmComms.sendMessage(synthesisUserPrompt, synthesisSystemPrompt);
      let insightData: Partial<CodebaseModuleInsight> = { summary: "LLM synthesis failed or produced invalid format." };
      try {
        insightData = JSON.parse(llmResponse);
      } catch (e) { console.error(`CUA: Failed to parse LLM response for module ${targetModulePath}:`, e, "\nLLM Response:", llmResponse); }

      // 3. Store Insight
      const newInsight: CodebaseModuleInsight = {
        modulePath: targetModulePath,
        summary: insightData.summary || "Summary not generated.",
        primaryOwners: primaryOwners,
        keyFiles: insightData.keyFiles || [],
        // dependencies: // TODO: Implement dependency detection
        interactionPoints: insightData.interactionPoints || [],
        keyTechnologies: insightData.keyTechnologies || [],
        commonSecurityRisks: insightData.commonSecurityRisks || [],
        recentSignificantCommits: recentCommits, // Store the structured commit info
        documentationLinks: insightData.documentationLinks || [`https://source.chromium.org/chromium/chromium/src/+/main:${targetModulePath}/README.md`], // Default README guess
        lastAnalyzed: new Date().toISOString(),
        // contentHash: // TODO: Calculate hash based on inputs
      };

      this.sharedContext.codebaseInsights[targetModulePath] = newInsight;
      this.processedItemsHistory[targetModulePath] = {
        lastAnalyzed: newInsight.lastAnalyzed,
        analysisTypes: [this.ANALYSIS_TYPE_MODULE],
        // contentHash: newInsight.contentHash
      };

      this.lastModuleAnalysis = new Date();
      await this.saveState();
      console.log(`CUA: Analysis complete for module ${targetModulePath}. Insight stored.`);

    } catch (error) {
      console.error(`CUA: Error during module analysis cycle for ${targetModulePath}:`, error);
    } finally {
      this.isAnalyzing = false;
    }
  }

  private selectNextModuleToAnalyze(): string | undefined {
    // Placeholder for module selection logic for autonomous CUA runs
    // Could be:
    // 1. Round-robin from a predefined list of important modules.
    // 2. Prioritize modules with stale or missing insights.
    // 3. Prioritize modules frequently mentioned in recent commits or issues.
    // 4. Modules requested by other agents (if request system is more developed).
    // For now, return a default or pick one from config if available.
    const exampleModules = ["components/safe_browsing/core/browser", "services/network", "content/browser/renderer_host"];
    const processedPaths = Object.keys(this.processedItemsHistory);
    const notYetProcessed = exampleModules.filter(m => !processedPaths.includes(m));
    if (notYetProcessed.length > 0) return notYetProcessed[0];

    // Fallback: find the oldest analyzed module from example list that is stale or not processed.
    let oldestStaleDate = new Date(); // Initialize to now, looking for dates older than this
    let oldestStaleModule: string | undefined = undefined;
    const stalenessThresholdDays = this.config.moduleInsightStalenessDays || 30;

    // Check a predefined list of important/example modules
    const modulesToConsider = this.config.exampleModulesForCUA || ["components/safe_browsing/core/browser", "services/network", "content/browser/renderer_host", "components/history", "device/fido"];

    for (const mod of modulesToConsider) {
        const entry = this.processedItemsHistory[mod];
        if (!entry) { // Not processed yet, high priority
            return mod;
        }
        const analyzedDate = new Date(entry.lastAnalyzed);
        if ((new Date().getTime() - analyzedDate.getTime()) / (1000 * 3600 * 24) >= stalenessThresholdDays) {
            // It's stale, is it the "most stale" we've found so far?
            if (analyzedDate < oldestStaleDate) {
                oldestStaleDate = analyzedDate;
                oldestStaleModule = mod;
            }
        }
    }

    if (oldestStaleModule) {
        return oldestStaleModule; // Return the most stale module
    }

    // If no modules are stale or unprocessed from the example list, CUA could:
    // 1. Pick a random module from a larger list of known Chromium modules.
    // 2. Look for modules mentioned in recent high-impact commits that don't have insights.
    // 3. Simply wait (which the main loop's idle delay will handle).
    // For now, returning undefined means it will just idle if no obvious candidates.
    // console.log("CUA: No clearly stale or unprocessed modules found in example list for continuous run.");
    return undefined;
  }

  // Renamed from selectNextModuleToAnalyze
  private async selectNextModuleToAnalyzeForContinuousRun(): Promise<string | undefined> {
    // This is where CUA decides which module to analyze next in its continuous loop.
    // It should prioritize:
    // 1. Modules explicitly requested (handled by processPendingRequests, but could influence here too)
    // 2. Modules without any insight.
    // 3. Modules with stale insights.
    // 4. Modules deemed important by other heuristics (e.g., frequent changes, security focus).

    // For now, using the logic from the previous selectNextModuleToAnalyze (which was already pretty good for this)
    return this.selectNextModuleToAnalyze(); // The previous selectNextModuleToAnalyze is now effectively this.
  }


  public async processPendingRequests(): Promise<void> {
    if (!this.sharedContext || !this.sharedContext.requests) return;

    const pendingRequests = this.sharedContext.requests.filter(
      req => req.targetAgentType === this.type && req.status === "pending"
    ).sort((a,b) => (a.priority ?? 100) - (b.priority ?? 100));

    if (pendingRequests.length === 0) return;
    console.log(`CUA: Found ${pendingRequests.length} pending request(s).`);

    for (const request of pendingRequests.slice(0, 1)) { // Process one request per cycle
      console.log(`CUA: Processing request ${request.requestId} (${request.taskType})`);
      request.status = "in_progress";
      request.updatedAt = new Date().toISOString();
      try {
        switch (request.taskType) {
          case "get_module_insight":
            if (!request.params.modulePath || typeof request.params.modulePath !== 'string') {
              throw new Error("Missing or invalid modulePath parameter for get_module_insight");
            }
            // Run analysis for this specific module. performSingleModuleAnalysis handles storing the insight.
            await this.performSingleModuleAnalysis(request.params.modulePath);
            request.result = this.sharedContext.codebaseInsights[request.params.modulePath] || "Insight generation attempted but not found.";
            break;
          case "provide_context_for_file":
             if (!request.params.filePath || typeof request.params.filePath !== 'string') {
              throw new Error("Missing or invalid filePath parameter for provide_context_for_file");
            }
            request.result = await this.provideContextForFile(request.params.filePath, request.params.codeSnippet as string | undefined);
            break;
          default:
            throw new Error(`Unsupported task type for CUA: ${request.taskType}`);
        }
        request.status = "completed";
      } catch (error) {
        console.error(`CUA: Error processing request ${request.requestId}:`, error);
        request.status = "failed";
        request.error = (error as Error).message;
      }
      request.updatedAt = new Date().toISOString();
      const reqIndex = this.sharedContext.requests.findIndex(r => r.requestId === request.requestId);
      if (reqIndex !== -1) this.sharedContext.requests[reqIndex] = request;
    }
  }

  private getParentModulePath(filePath: string): string {
    // Simple heuristic: take the directory containing the file.
    // This can be improved to find a more meaningful module path.
    // e.g., components/history/core/browser/history_service.cc -> components/history/core/browser
    const parts = filePath.split('/');
    if (parts.length > 1) {
      parts.pop(); // Remove filename
      // Example: if path is like 'src/foo/bar/baz.cc', module could be 'src/foo/bar'
      // Or, if it's 'components/foo/bar/baz.cc', module is 'components/foo/bar'
      // A more robust approach would look for known top-level module dirs or OWNERS files.
      // For now, just the immediate parent dir.
      if (parts.join('/').startsWith("src/")) return parts.join('/'); // if it's like src/foo/bar.cc -> src/foo
      if (parts.length > 2 && ["components", "services", "content", "third_party_blink"].includes(parts[0])) {
         // e.g. components/foo/bar/file.cc -> components/foo/bar
         return parts.join('/');
      }
      if (parts.length > 1) return parts.join('/'); // Fallback to parent dir
    }
    return filePath; // Fallback if it's a top-level file or path is unusual
  }

  public getInsightForModule(modulePathOrFilePath: string): CodebaseModuleInsight | undefined {
    // TODO: Implement a way to check if it's a file path and find its module insight
    return this.sharedContext.codebaseInsights[modulePathOrFilePath];
  }

  public async provideContextForFile(filePath: string, codeSnippet?: string): Promise<string> {
    console.log(`CUA: Providing context for file: ${filePath}`);
    try {
      const fileData = await this.chromiumApi.getFile({ filePath });
      // Note: fileData.content is already formatted with line numbers by api.getFile.
      // For LLM analysis, raw content is better. Re-fetch raw for now (similar to OWNERS hack).
      let rawFileContent = `Could not fetch raw content for ${filePath}. Displaying formatted snippet.`;
       try {
        const rawFileResponse = await fetch(`https://chromium.googlesource.com/chromium/src/+/main/${filePath}?format=TEXT`);
        if (rawFileResponse.ok) {
            const base64Content = await rawFileResponse.text();
            rawFileContent = Buffer.from(base64Content, 'base64').toString('utf-8');
        }
      } catch (fetchError) { console.error(`CUA: Error fetching raw content for ${filePath}:`, fetchError); }


      const parentModulePath = this.getParentModulePath(filePath);
      const moduleInsight = this.sharedContext.codebaseInsights[parentModulePath];

      let contextPrompt = `File Path: ${filePath}\n`;
      if (moduleInsight) {
        contextPrompt += `\n--- Parent Module Insight (${parentModulePath}) ---\n`;
        contextPrompt += `Summary: ${moduleInsight.summary}\n`;
        if (moduleInsight.primaryOwners && moduleInsight.primaryOwners.length > 0) {
          contextPrompt += `Owners: ${moduleInsight.primaryOwners.join(', ')}\n`;
        }
        if (moduleInsight.keyTechnologies && moduleInsight.keyTechnologies.length > 0) {
            contextPrompt += `Key Technologies: ${moduleInsight.keyTechnologies.join(', ')}\n`;
        }
        if (moduleInsight.commonSecurityRisks && moduleInsight.commonSecurityRisks.length > 0) {
            contextPrompt += `Common Module Security Risks: ${moduleInsight.commonSecurityRisks.join(', ')}\n`;
        }
        contextPrompt += "---\n\n";
      } else {
        contextPrompt += "No specific module insight available for the parent directory.\n\n";
      }

      if (codeSnippet) {
        contextPrompt += `User provided code snippet:\n\`\`\`\n${codeSnippet}\n\`\`\`\n\n`;
      }

      const systemPrompt = "You are a Chromium codebase expert. Provide a concise summary of the given file's purpose, its key components/responsibilities, and its relationship to its parent module (if context provided). If a code snippet is provided, focus your explanation on that snippet in the context of the file.";
      // Limit raw file content sent to LLM for performance/token limits
      const userPrompt = `${contextPrompt}File Content (first 4000 chars):\n\`\`\`\n${rawFileContent.substring(0, 4000)}\n\`\`\`\n\nSummarize the file's role and key aspects:`;

      const llmSummary = await this.llmComms.sendMessage(userPrompt, systemPrompt);
      return llmSummary;

    } catch (error) {
      console.error(`CUA: Error providing context for file ${filePath}:`, error);
      return `Sorry, I encountered an error trying to get context for ${filePath}: ${(error as Error).message}`;
    }
  }
}

// --- GenericTaskAgent --- (Restored to its state before this plan)
export class GenericTaskAgent implements SpecializedAgent {
  public type = SpecializedAgentType.GenericTask;
  public id: string;
  private llmComms: LLMCommunication;
  private config: GenericTaskAgentConfig & { id: string };
  private sharedContext?: SharedAgentContextType;
  private isActive: boolean = false;
  private result: string | null = null;
  private error: string | null = null;

  constructor(llmComms: LLMCommunication, config: GenericTaskAgentConfig, sharedContext?: SharedAgentContextType) {
    this.id = config.id || `generic-task-${Date.now()}`;
    this.llmComms = llmComms;
    this.config = { ...config, id: this.id };
    if (sharedContext) this.setSharedContext(sharedContext);
    console.log(`GenericTaskAgent [${this.id}] initialized for task: ${this.config.taskDescription}`);
  }
  public setSharedContext(context: SharedAgentContextType): void { this.sharedContext = context; }
  async start(): Promise<void> {
    if (this.isActive) { console.warn(`GenericTaskAgent [${this.id}] is already active.`); return; }
    this.isActive = true; this.result = null; this.error = null;
    console.log(`GenericTaskAgent [${this.id}] started.`);
    try {
      this.result = await this.llmComms.sendMessage(this.config.llmPrompt, `Executing task: ${this.config.taskDescription}`);
      console.log(`GenericTaskAgent [${this.id}] completed. Result preview: ${(this.result || "").substring(0, 100)}...`);
    } catch (e) {
      const err = e as Error; this.error = err.message;
      console.error(`GenericTaskAgent [${this.id}] failed: ${this.error}`);
    } finally { this.isActive = false; }
  }
  async stop(): Promise<void> { this.isActive = false; console.log(`GenericTaskAgent [${this.id}] stopped.`); }
  async getStatus(): Promise<string> {
    let status = `GenericTaskAgent [${this.id}] (${this.config.taskDescription}): `;
    if (this.isActive) status += "Active/Running.";
    else if (this.result !== null) status += `Completed. Result: ${(this.result || "").substring(0,50)}...`;
    else if (this.error !== null) status += `Failed. Error: ${this.error}`;
    else status += "Idle/Pending.";
    return status;
  }
  public getResult(): string | null { return this.result; }
  public getError(): string | null { return this.error; }
}
