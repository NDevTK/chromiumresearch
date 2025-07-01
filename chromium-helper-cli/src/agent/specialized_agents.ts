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

export type SharedAgentContextType = { findings: Array<{ sourceAgent: string, type: string, data: any, timestamp: Date }>; requests: Array<{ requestingAgent: string, targetAgentType: SpecializedAgentType, request: any, timestamp: Date }>; knownBugPatterns: Array<BugPattern | string>; codebaseInsights: Record<string, CodebaseModuleInsight>; };
export enum SpecializedAgentType { ProactiveBugFinding = "ProactiveBugFinding", BugPatternAnalysis = "BugPatternAnalysis", CodebaseUnderstanding = "CodebaseUnderstanding", GenericTask = "GenericTask", }
export interface SpecializedAgent { type: SpecializedAgentType; start(): Promise<void>; stop(): Promise<void>; getStatus(): Promise<string>; processData?(data: unknown): Promise<void>; setSharedContext?(context: SharedAgentContextType): void; }

// --- ProactiveBugFinder --- (Includes changes from previous plan's Phase 2 & 4)
export class ProactiveBugFinder implements SpecializedAgent {
  public type = SpecializedAgentType.ProactiveBugFinding;
  private llmComms: LLMCommunication;
  private storage: PersistentStorage;
  private chromiumApi: ChromiumAPI;
  private sharedContext!: SharedAgentContextType;
  private config: ProactiveBugFinderConfig;
  private isActive: boolean = false;
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
  public async start(): Promise<void> { if (this.isActive) return; this.isActive = true; this.runAnalysisCycle(); }
  public async stop(): Promise<void> { this.isActive = false; }
  public async getStatus(): Promise<string> {
    let s = `PBF: ${this.isActive?'Active':'Idle'}.`; if(this.lastAnalysisTimestamp)s+=` LastRun: ${this.lastAnalysisTimestamp.toLocaleTimeString()}.`;
    s+=` History: ${Object.keys(this.processedItemsHistory).length} files.`; return s;
  }
  private async runAnalysisCycle(): Promise<void> {
    if (!this.isActive) return; console.log(`PBF: Starting cycle (type: ${this.ANALYSIS_TYPE_HEURISTIC_SWEEP}).`); let candidateFiles: SearchResult[] = [];
    try { /* ... Heuristic candidate gathering (recent commits, keywords, sensitive paths) ... */ } catch (e) { console.warn(`PBF: Error gathering candidates: ${(e as Error).message}`); }
    const uniqueFilesMap = new Map<string, SearchResult>(); candidateFiles.forEach(f => { const e = uniqueFilesMap.get(f.file); if(!e || (f.type === 'recent-commit-sensitive' && e.type !== 'recent-commit-sensitive')) uniqueFilesMap.set(f.file,f); else if(!e) uniqueFilesMap.set(f.file,f);}); candidateFiles = Array.from(uniqueFilesMap.values());
    const newCandFiles = candidateFiles.filter(f => { const entry = this.processedItemsHistory[f.file]; return !entry || !entry.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP); });
    if (newCandFiles.length === 0) { console.log("PBF: No new files for sweep."); this.lastAnalysisTimestamp = new Date(); await this.saveState(); return; }
    const prioritizedF = newCandFiles.sort((a,b) => { /* ... sorting logic ... */ return 0; }).slice(0, this.config.filesPerCycle);
    if (prioritizedF.length === 0 ) { console.log("PBF: No files after prioritization."); this.lastAnalysisTimestamp = new Date(); await this.saveState(); return; }
    const cycleSummary: string[] = [];
    for (const targetFile of prioritizedF) {
      try {
        const fileData = await this.chromiumApi.getFile({ filePath: targetFile.file }); const currentHash = computeSha256Hash(fileData.content);
        const existingEntry = this.processedItemsHistory[targetFile.file];
        if (existingEntry && existingEntry.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP) && existingEntry.contentHash === currentHash) {
          existingEntry.lastAnalyzed = new Date().toISOString(); this.processedItemsHistory[targetFile.file] = existingEntry; continue;
        }
        let contextLLM = ""; /* ... build additionalContextForLLM + scratchpadContext ... */
        // TODO: Actually build contextLLM (e.g. from sharedAgentContext.codebaseInsights for the file's module, or known bug patterns)

        const analysisSystemPrompt = "You are a security auditor. Analyze the provided C++ code from a Chromium file for potential vulnerabilities. Focus on common C++ pitfalls, IPC issues, or web security concerns. Be concise. If you identify a specific risky function call or pattern, also output a line formatted as: SEARCHABLE_PATTERN: <the_pattern_to_search_for_globally>";
        const analysisUserPrompt = `File: ${targetFile.file}\n${contextLLM}\n\nCode (first 4000 chars):\n${fileData.content.substring(0,4000)}\n\nIdentify potential vulnerabilities. If you find a specific risky pattern (like a function call or macro usage), include a line: SEARCHABLE_PATTERN: <pattern_string_for_codesearch>`;

        const llmAnalysis = await this.llmComms.sendMessage(analysisUserPrompt, analysisSystemPrompt);

        // New logic to extract pattern and search
        let additionalSearchResults: SearchResult[] = []; // Use SearchResult type
        const patternPrefix = "SEARCHABLE_PATTERN: ";
        if (llmAnalysis.includes(patternPrefix)) {
            const patternLine = llmAnalysis.split('\n').find(line => line.startsWith(patternPrefix));
            if (patternLine) {
                const extractedPattern = patternLine.substring(patternPrefix.length).trim();
                if (extractedPattern) {
                    console.log(`PBF: Found searchable pattern: "${extractedPattern}". Searching for other occurrences...`);
                    try {
                        // Using a sub-set of SearchCodeParams for simplicity here
                        additionalSearchResults = await this.chromiumApi.searchCode({ query: extractedPattern, limit: 5 });
                        console.log(`PBF: Found ${additionalSearchResults.length} additional occurrences of pattern.`);
                    } catch (searchError) {
                        console.error(`PBF: Error searching for pattern "${extractedPattern}":`, searchError);
                    }
                }
            }
        }

        this.sharedContext.findings.push({ // Corrected from sharedAgentContext to sharedContext
            sourceAgent: this.type,
            type: "PotentialVulnerability",
            data: {
                file: targetFile.file,
                analysis: llmAnalysis, // Original LLM analysis
                snippet: fileData.content.substring(0, 500),
                relatedOccurrences: additionalSearchResults // New field
            },
            timestamp: new Date()
        });

        if (llmAnalysis.toLowerCase().includes("vulnerability") || additionalSearchResults.length > 0) {
             cycleSummary.push(`${targetFile.file}: ${llmAnalysis.substring(0,100)}... (Found ${additionalSearchResults.length} related)`);
        }
        if(cycleSummary.length>3)cycleSummary.shift(); // Keep summary short

        const entryUpdate = this.processedItemsHistory[targetFile.file] || { lastAnalyzed: "", analysisTypes: [], contentHash: "" };
        entryUpdate.lastAnalyzed = new Date().toISOString(); entryUpdate.contentHash = currentHash;
        if (!entryUpdate.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP)) entryUpdate.analysisTypes.push(this.ANALYSIS_TYPE_HEURISTIC_SWEEP);
        this.processedItemsHistory[targetFile.file] = entryUpdate;
      } catch (e) { console.error(`PBF: Error analyzing ${targetFile.file}:`, e); }
    }
    this.lastAnalysisTimestamp = new Date(); await this.saveState(); console.log("PBF: Sweep cycle complete.");
  }
  public async analyzeSpecificFile(filePath: string): Promise<string> {
    if (!this.isActive && !this.chromiumApi) return "Agent not ready.";
    try {
      const fileData = await this.chromiumApi.getFile({ filePath }); const currentHash = computeSha256Hash(fileData.content);
      const analysisPrompt = `Analyze ${filePath} for vulnerabilities...`;
      const analysis = await this.llmComms.sendMessage(analysisPrompt, "Security auditor...");
      this.sharedContext.findings.push({ sourceAgent:this.type, type:"SpecificFileAnalysis", data:{file:filePath, analysis:analysis, snippet:fileData.content.substring(0,500)}, timestamp:new Date() });
      const entry = this.processedItemsHistory[filePath] || { lastAnalyzed: "", analysisTypes: [] };
      entry.lastAnalyzed = new Date().toISOString(); entry.contentHash = currentHash;
      if (!entry.analysisTypes.includes(this.ANALYSIS_TYPE_SPECIFIC_REQUEST)) entry.analysisTypes.push(this.ANALYSIS_TYPE_SPECIFIC_REQUEST);
      this.processedItemsHistory[filePath] = entry; await this.saveState(); return analysis;
    } catch (e) { const err=e as Error; console.error(`PBF: Error specific analysis ${filePath}:`, err); return `Error: ${err.message}`; }
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
  private isActive: boolean = false; // Added missing property
  private lastPatternExtraction?: Date; // Added missing property

  private readonly ANALYSIS_TYPE_COMMIT = "bpa_commit_analysis";
  private readonly ANALYSIS_TYPE_ISSUE = "bpa_issue_analysis";

  constructor( llmComms: LLMCommunication, chromiumApi: ChromiumAPI, sharedContext: SharedAgentContextType, config: BugPatternAnalysisConfig ) {
    this.llmComms = llmComms; this.chromiumApi = chromiumApi; this.config = config;
    this.storage = new PersistentStorage('BugPatternAnalysis_data');
    this.setSharedContext(sharedContext); console.log("Bug Pattern Analysis agent initialized."); this.loadState();
  }
  public setSharedContext(context: SharedAgentContextType): void { this.sharedContext = context; if(!this.sharedContext.knownBugPatterns) this.sharedContext.knownBugPatterns = []; }
  private async loadState(): Promise<void> {
    const state = await this.storage.loadData<{ lastExtraction?: string; patterns?: Array<BugPattern|string>; patternIdCounter?: number; processedCommitIds?: string[]; processedIssueIds?: string[]; processedItemsHistory?: ProcessedItemsHistory; }>();
    if (state) {
      if (state.lastExtraction) this.lastPatternExtraction = new Date(state.lastExtraction);
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
    await this.storage.saveData({ lastExtraction: this.lastPatternExtraction?.toISOString(), patterns: [...this.sharedContext.knownBugPatterns], patternIdCounter: this.patternIdCounter, processedItemsHistory: this.processedItemsHistory });
  }
  public async start(): Promise<void> { if(this.isActive)return; this.isActive=true; this.runPatternExtractionCycle(); this.runIssueAnalysisCycle(); }
  public async stop(): Promise<void> { this.isActive=false; }
  public async getStatus(): Promise<string> {
    let s = `BPA: ${this.isActive?'Active':'Idle'}. Patterns: ${this.sharedContext.knownBugPatterns.length}.`;
    if(this.lastPatternExtraction)s+=` LastRun: ${this.lastPatternExtraction.toLocaleTimeString()}.`;
    s+=` History: ${Object.keys(this.processedItemsHistory).length} items.`; return s;
  }
  private async runPatternExtractionCycle(): Promise<void> {
    if(!this.isActive)return; console.log(`BPA: Starting commit scan (type: ${this.ANALYSIS_TYPE_COMMIT})`);
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
    this.lastPatternExtraction=new Date(); await this.saveState(); console.log("BPA: Commit scan done.");
  }
  public async runIssueAnalysisCycle(): Promise<void> {
    if(!this.isActive)return; console.log(`BPA: Starting issue scan (type: ${this.ANALYSIS_TYPE_ISSUE})`);
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
    await this.saveState(); console.log("BPA: Issue scan done.");
  }
  public async getContextualAdvice(codeSnippet: string): Promise<string> { /* ... as before ... */ return "Placeholder"; }
}

// --- CodebaseUnderstandingAgent --- (Restored to its state before this plan's Phase 3 for CUA)
export class CodebaseUnderstandingAgent implements SpecializedAgent {
  public type = SpecializedAgentType.CodebaseUnderstanding;
  private llmComms: LLMCommunication; private storage: PersistentStorage; private chromiumApi: ChromiumAPI;
  private isActive: boolean = false; private lastModuleAnalysis?: Date;
  private sharedContext!: SharedAgentContextType; private config: CodebaseUnderstandingConfig;
  private processedItemsHistory: ProcessedItemsHistory = {}; // Using ProcessedItemsHistory now
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
  public async start(): Promise<void> { if (this.isActive) return; this.isActive = true; this.runModuleAnalysisCycle(); } // TODO: Run periodically
  public async stop(): Promise<void> { this.isActive = false; }
  public async getStatus(): Promise<string> {
    let s = `CUA: ${this.isActive?'Active':'Idle'}. Insights: ${Object.keys(this.sharedContext.codebaseInsights).length}.`;
    if(this.lastModuleAnalysis) s+=` LastRun: ${this.lastModuleAnalysis.toLocaleTimeString()}.`;
    s+=` Processed Modules: ${Object.keys(this.processedItemsHistory).length}.`; return s;
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

  private async runModuleAnalysisCycle(modulePath?: string): Promise<void> {
    if (!this.isActive && !modulePath) return; // If not active and no specific path, do nothing.

    // TODO: Implement module selection logic if modulePath is not provided.
    // For now, using a hardcoded example or passed path.
    const targetModulePath = modulePath || "components/safe_browsing/core/browser";
    console.log(`CUA: Starting analysis cycle for module: ${targetModulePath}`);

    const historyEntry = this.processedItemsHistory[targetModulePath];
    // TODO: Add content hashing for inputs to decide if re-analysis is truly needed.
    // For now, just check if it was analyzed before.
    if (historyEntry && historyEntry.analysisTypes.includes(this.ANALYSIS_TYPE_MODULE)) {
      console.log(`CUA: Module ${targetModulePath} previously analyzed. Skipping.`);
      // Potentially check lastAnalyzed date and re-analyze if too old, based on config.
      // For now, a simple skip.
      return;
    }

    try {
      // 1. Gather Information
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
