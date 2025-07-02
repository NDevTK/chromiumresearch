// src/agent/agents/bug_pattern_analysis_agent.ts
import { LLMCommunication } from '../llm_communication.js';
import { PersistentStorage } from '../persistent_storage.js';
import { ChromiumAPI } from '../../api.js';
import { BugPatternAnalysisConfig } from '../../agent_config.js';
import {
    SpecializedAgent,
    SpecializedAgentType,
    SharedAgentContextType,
    ProcessedItemsHistory,
    BugPattern // Import BugPattern if it's used directly by type hints
} from './types.js'; // Import from new types.ts

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

  // Pagination state for issues
  private currentIssueStartIndex: number = 0;
  private totalIssuesDiscoveredInLastFullScan: number = 0;

  // Commit processing will now fetch top N and rely on history, no specific pagination state needed here.

  // private patternExtractionIntervalId?: NodeJS.Timeout; // Not used
  // private issueAnalysisIntervalId?: NodeJS.Timeout; // Not used


  private readonly ANALYSIS_TYPE_COMMIT = "bpa_commit_analysis";
  private readonly ANALYSIS_TYPE_ISSUE = "bpa_issue_analysis";
  private readonly ANALYSIS_TYPE_EVENT = "bpa_event_analysis";


  constructor( llmComms: LLMCommunication, chromiumApi: ChromiumAPI, sharedContext: SharedAgentContextType, config: BugPatternAnalysisConfig ) {
    this.llmComms = llmComms; this.chromiumApi = chromiumApi; this.config = config;
    this.storage = new PersistentStorage('BugPatternAnalysis_data');
    this.setSharedContext(sharedContext); console.log("Bug Pattern Analysis agent initialized."); this.loadState();
  }
  public setSharedContext(context: SharedAgentContextType): void { this.sharedContext = context; if(!this.sharedContext.knownBugPatterns) this.sharedContext.knownBugPatterns = []; }

  private async loadState(): Promise<void> {
    const state = await this.storage.loadData<{
        lastExtraction?: string;
        lastIssueScan?: string;
        patterns?: Array<BugPattern|string>;
        patternIdCounter?: number;
        patterns?: Array<BugPattern|string>;
        patternIdCounter?: number;
        processedItemsHistory?: ProcessedItemsHistory;
        currentIssueStartIndex?: number;
        totalIssuesDiscoveredInLastFullScan?: number;
        // currentCommitStartToken and commitsScannedInCurrentFullSweep are removed
    }>();
    if (state) {
      if (state.lastExtraction) this.lastPatternExtraction = new Date(state.lastExtraction);
      if (state.lastIssueScan) this.lastIssueScan = new Date(state.lastIssueScan);
      if (state.patterns) this.sharedContext.knownBugPatterns = state.patterns.map(p => typeof p === 'string' ? {id:`BPA-OLD-${Math.random().toString(36).substring(2,9)}`, name:"Legacy", description:p, tags:["legacy"], source:"Migrated"} : p);
      this.patternIdCounter = state.patternIdCounter || this.sharedContext.knownBugPatterns.length;
      this.processedItemsHistory = state.processedItemsHistory || {};
      this.currentIssueStartIndex = state.currentIssueStartIndex || 0;
      this.totalIssuesDiscoveredInLastFullScan = state.totalIssuesDiscoveredInLastFullScan || 0;

      // Legacy migration for old processedCommitIds/processedIssueIds
      if (!state.processedItemsHistory && (state.processedCommitIds || state.processedIssueIds)) {
        const now = new Date().toISOString();
        if (state.processedCommitIds && Array.isArray(state.processedCommitIds)) {
          state.processedCommitIds.forEach((id: string) => { this.processedItemsHistory[id] = { lastAnalyzed: now, analysisTypes: [this.ANALYSIS_TYPE_COMMIT + "_legacy"]}; });
        }
        if (state.processedIssueIds && Array.isArray(state.processedIssueIds)) {
          state.processedIssueIds.forEach((id: string) => { this.processedItemsHistory[id] = { lastAnalyzed: now, analysisTypes: [this.ANALYSIS_TYPE_ISSUE + "_legacy"]}; });
        }
      }
      console.log(`BPA: Loaded ${Object.keys(this.processedItemsHistory).length} items into history. Issue Start Index: ${this.currentIssueStartIndex}.`);
    }
  }
  private async saveState(): Promise<void> {
    const maxItems = this.config.maxProcessedHistorySize || 200; const keys = Object.keys(this.processedItemsHistory);
    if (keys.length > maxItems) {
      const sorted = keys.sort((a,b) => new Date(this.processedItemsHistory[a].lastAnalyzed).getTime() - new Date(this.processedItemsHistory[b].lastAnalyzed).getTime());
      for(let i=0; i < keys.length - maxItems; i++) delete this.processedItemsHistory[sorted[i]];
    }
    await this.storage.saveData({
        lastExtraction: this.lastPatternExtraction?.toISOString(),
        lastIssueScan: this.lastIssueScan?.toISOString(),
        patterns: [...this.sharedContext.knownBugPatterns],
        patternIdCounter: this.patternIdCounter,
        processedItemsHistory: this.processedItemsHistory,
        currentIssueStartIndex: this.currentIssueStartIndex,
        totalIssuesDiscoveredInLastFullScan: this.totalIssuesDiscoveredInLastFullScan
        // currentCommitStartToken and commitsScannedInCurrentFullSweep are removed
    });
  }

  public async start(): Promise<void> {
    if(this.isActive)return;
    this.isActive=true;
    this.isExtracting = false;
    this.isIssueScanning = false;
    console.log("BPA: Continuous operation started.");
    this.runContinuousProcessingLoop().catch(e => {
        console.error("BPA: ContinuousProcessingLoop encountered critical error and exited:", e);
        this.isActive = false;
    });
  }

  public async stop(): Promise<void> {
    this.isActive=false;
    console.log("BPA: Continuous operation signaled to stop.");
  }

  public async getStatus(): Promise<string> {
    let s = `BPA: ${this.isActive?'Continuous - Running':'Idle/Stopped'}. Patterns: ${this.sharedContext.knownBugPatterns.length}.`;
    s += ` ${this.isExtracting ? 'Processing Commit/Event.' : ''} ${this.isIssueScanning ? 'Processing Issue.' : ''}`;
    if(this.lastPatternExtraction) s+=` Last Commit/Event Processed: ${this.lastPatternExtraction.toLocaleTimeString()}.`;
    if(this.lastIssueScan) s+=` Last Issue Processed: ${this.lastIssueScan.toLocaleTimeString()}.`;
    s+=` History: ${Object.keys(this.processedItemsHistory).length} items.`;
    return s;
  }

  private async runContinuousProcessingLoop(): Promise<void> {
    console.log("BPA: Entered continuous processing loop.");
    let lastProcessedType: 'commit' | 'issue' = 'issue';

    while (this.isActive) {
      if (this.isExtracting || this.isIssueScanning) {
        await new Promise(resolve => setTimeout(resolve, this.config.itemProcessingCheckIntervalMsBPA || 1000));
        continue;
      }
      let workFoundThisIteration = false;

      try {
        await this.processPendingRequests();

        const relevantEvents = (this.sharedContext.recentEvents || []).filter(event =>
            event.eventType === "HighSeverityVulnerabilityFound" &&
            !this.processedItemsHistory[event.eventId]
        );

        if (relevantEvents.length > 0) {
            const eventToProcess = relevantEvents[0];
            console.log(`BPA: Detected relevant event ${eventToProcess.eventId} from ${eventToProcess.sourceAgent}. Analyzing for pattern.`);
            this.isExtracting = true;
            workFoundThisIteration = true;
            try {
                if (eventToProcess.data && eventToProcess.data.analysis) {
                    const simplifiedCommitLike = {
                        message: `Analysis of ${eventToProcess.data.file}:\n${eventToProcess.data.analysis}`,
                        commit: eventToProcess.eventId
                    };
                    await this.analyzeCommit(simplifiedCommitLike);
                    this.processedItemsHistory[eventToProcess.eventId] = { lastAnalyzed: new Date().toISOString(), analysisTypes: [this.ANALYSIS_TYPE_EVENT] };
                    this.lastPatternExtraction = new Date();
                    await this.saveState();
                    console.log(`BPA: Analysis complete for event ${eventToProcess.eventId}.`);
                }
            } catch (e) {
                console.error(`BPA: Error processing event ${eventToProcess.eventId}:`, e);
            } finally {
                this.isExtracting = false;
            }
        }

        if (!workFoundThisIteration) {
            if (lastProcessedType === 'issue') {
              this.isExtracting = true;
              const commitToProcess = await this.selectNextCommitForAnalysis();
              if (commitToProcess) {
                workFoundThisIteration = true;
                console.log(`BPA: Selected commit for analysis: ${commitToProcess.commit.substring(0, 12)}...`);
                await this.analyzeCommit(commitToProcess);
                this.lastPatternExtraction = new Date();
                await this.saveState();
                console.log(`BPA: Analysis complete for commit ${commitToProcess.commit.substring(0,12)}.`);
              }
              lastProcessedType = 'commit';
              this.isExtracting = false;
            } else {
              this.isIssueScanning = true;
              const issueToProcess = await this.selectNextIssueForAnalysis();
              if (issueToProcess) {
                workFoundThisIteration = true;
                console.log(`BPA: Selected issue for analysis: ${issueToProcess.id}`);
                await this.analyzeIssue(issueToProcess);
                this.lastIssueScan = new Date();
                await this.saveState();
                console.log(`BPA: Analysis complete for issue ${issueToProcess.id}.`);
              }
              lastProcessedType = 'issue';
              this.isIssueScanning = false;
            }
        }
      } catch (error) {
        console.error("BPA: Error during continuous processing iteration:", error);
        this.isExtracting = false; this.isIssueScanning = false;
      } finally {
        this.isExtracting = false; this.isIssueScanning = false;
      }

      if (!workFoundThisIteration) {
        const idleDelayMs = this.config.idleCycleDelayMsBPA || 15000;
        await new Promise(resolve => setTimeout(resolve, idleDelayMs));
      }
      await new Promise(resolve => setTimeout(resolve, this.config.interItemDelayMsBPA || 200));
    }
    console.log("BPA: Exited continuous processing loop because isActive is false.");
  }

  private async selectNextCommitForAnalysis(): Promise<any | undefined> {
    const commitsToFetch = this.config.commitsPerCycle || 1; // This now acts as a simple limit.
    const query = 'security OR cve- OR vulnerability OR exploit OR rce OR xss OR uaf';

    try {
      // Fetch the most recent N commits matching the criteria.
      // The ChromiumAPI.searchCommits has been reverted and no longer takes startCommit or returns nextCommitToken.
      // It will internally filter by query if the API doesn't support it directly for +log.
      console.log(`BPA: Selecting next commit. Query: "${query}", Limit: ${commitsToFetch}`);
      const searchResults = await this.chromiumApi.searchCommits({
        query: query,
        limit: commitsToFetch * 2 // Fetch a bit more to increase chances of finding an unprocessed one
      });

      const fetchedCommits = searchResults.log || []; // Assuming searchCommits returns { log: CommitLogEntry[] }

      // Filter out already processed commits
      const newCommits = fetchedCommits.filter(commit => {
        const id = commit.commit;
        if (!id) return false;
        const entry = this.processedItemsHistory[id];
        return !entry || !entry.analysisTypes.includes(this.ANALYSIS_TYPE_COMMIT);
      });

      if (newCommits.length > 0) {
        console.log(`BPA: Found ${newCommits.length} new commit(s) to process. Selecting one.`);
        return newCommits[0]; // Process the first new commit found
      } else {
        // console.log(`BPA: No new commits found in the latest batch of ${fetchedCommits.length}.`);
        return undefined;
      }

    } catch (e) {
      console.error("BPA: Failed commit search during selection:", e);
      return undefined;
    }
  }

  private async selectNextIssueForAnalysis(): Promise<any | undefined> {
    const issuesToFetch = this.config.issuesPerCycle || 1; // How many to fetch per API call
    let query = 'type:vulnerability status:fixed';
    if (this.config.targetIssueSeverities?.length) {
      query += ` (${this.config.targetIssueSeverities.map(s => `severity:"${s}"`).join(" OR ")})`; // Added quotes for severity
    } else {
      query += ``;
    }

    // Max pages to scan in one full sweep before resetting.
    // This prevents endless scanning if there are thousands of old issues.
    const maxPagesPerFullScan = this.config.maxIssuePagesToScanPerCycle || 10;
    const pagesScannedSoFar = Math.floor(this.currentIssueStartIndex / (issuesToFetch || 1));

    if (pagesScannedSoFar >= maxPagesPerFullScan && this.currentIssueStartIndex > 0) {
        console.log(`BPA: Reached max pages (${maxPagesPerFullScan}) for current issue scan sweep. Resetting to start.`);
        this.currentIssueStartIndex = 0;
        this.totalIssuesDiscoveredInLastFullScan = 0;
        // No need to save state here, will be saved after an item is processed or loop idles.
    }

    try {
      console.log(`BPA: Selecting next issue. Query: "${query}", StartIndex: ${this.currentIssueStartIndex}, Limit: ${issuesToFetch}`);
      const rawSearchResults = await this.chromiumApi.searchIssues(query, {
        limit: issuesToFetch,
        startIndex: this.currentIssueStartIndex
      });

      // Manual parsing of the response (assuming 'any' type from reverted API)
      let fetchedIssues: IssueSummary[] = [];
      let totalIssuesFromAPI = 0;

      if (rawSearchResults && typeof rawSearchResults === 'object') {
        // Based on `ai-guide.ts` CLI output structure, which abstracts the direct API response.
        // The direct API response was previously parsed by api.ts into IssueSearchResultSet.
        // Now, BPAA must do a similar parsing or make assumptions.
        // Let's assume the raw response *might* look like what the CLI would output,
        // or we inspect common locations for 'issues' array and 'total' count.
        // This is the riskiest part of the revert.
        if (Array.isArray((rawSearchResults as any).issues)) {
          fetchedIssues = (rawSearchResults as any).issues as IssueSummary[];
        }
        if (typeof (rawSearchResults as any).total === 'number') {
          totalIssuesFromAPI = (rawSearchResults as any).total;
        } else if (Array.isArray(rawSearchResults) && rawSearchResults[0] && typeof rawSearchResults[0][1] === 'number' && fetchedIssues.length > 0) {
          // Fallback: trying to find total count like in the complex array structure: data[0][1]
          totalIssuesFromAPI = rawSearchResults[0][1];
           console.log(`BPA_DEBUG: Attempted to parse total from complex array structure, got: ${totalIssuesFromAPI}`);
        } else {
           console.log(`BPA_DEBUG: Could not find 'total' in searchIssues response. Found ${fetchedIssues.length} issues. Pagination might be impaired.`);
           totalIssuesFromAPI = this.currentIssueStartIndex + fetchedIssues.length + (fetchedIssues.length === issuesToFetch ? 1 : 0); // Guess, or assume current page if total unknown
        }
      }

      // Update total discovered if it's the first page of a new scan sweep
      if (this.currentIssueStartIndex === 0) {
        this.totalIssuesDiscoveredInLastFullScan = totalIssuesFromAPI;
      }

      const newIssues = fetchedIssues.filter(issue => {
        const id = issue.issueId?.toString(); // issue is now IssueSummary
        if (!id) return false;
        const entry = this.processedItemsHistory[id];
        // Process if not in history or if entry is for a different analysis type (though less likely for issues)
        return !entry || !entry.analysisTypes.includes(this.ANALYSIS_TYPE_ISSUE);
      });

      if (newIssues.length > 0) {
        // Advance the start index for the next fetch by the number of items *actually fetched* in this page.
        this.currentIssueStartIndex += fetchedIssues.length;
        return newIssues[0]; // Process one new issue from this page
      }

      // If no new issues on this page, but issues were fetched, it means all were processed.
      if (fetchedIssues.length > 0 && newIssues.length === 0) {
        console.log(`BPA: All ${fetchedIssues.length} issues on current page (start: ${this.currentIssueStartIndex - fetchedIssues.length}) already processed.`);
        this.currentIssueStartIndex += fetchedIssues.length; // Advance to next page
        // The main loop will call this method again if no other work (like event processing or commit processing) is found.
      }

      // If no issues were fetched at all from this startIndex, and it's not the very beginning of a scan
      if (fetchedIssues.length === 0 && this.currentIssueStartIndex > 0) {
         console.log(`BPA: No issues found starting at index ${this.currentIssueStartIndex}. Likely reached the end for query "${query}". Resetting.`);
         this.currentIssueStartIndex = 0;
         this.totalIssuesDiscoveredInLastFullScan = 0;
      } else if (fetchedIssues.length === 0 && this.currentIssueStartIndex === 0) {
         console.log(`BPA: No issues found at all for query "${query}". Will retry later.`);
         // Keep currentIssueStartIndex at 0 to retry the query in the next cycle.
      }

      // Save state if index changed significantly or reset
      // This will be saved by the main loop after an item is processed or after idling.
      // await this.saveState(); // Potentially save here if important, but can be noisy.

      return undefined; // No new issue to process in this specific call

    } catch (e) {
      console.error("BPA: Failed issue search during selection:", e);
      // Optional: Reset index on persistent errors to avoid getting stuck.
      // For now, let it retry with the same index in the next cycle.
      return undefined;
    }
  }

  private async analyzeCommit(commit: any): Promise<void> {
    const id = commit.commit;
    try {
      let clComments = "";
      const systemPrompt = `You are an expert security analyst. Extract information to populate a BugPattern JSON object.
The BugPattern structure is: { id: string, name: string, description: string, cwe?: string, tags: string[], exampleGoodPractice?: string, exampleVulnerableCode?: string, source?: string, confidence?: 'High'|'Medium'|'Low', severity?: 'Critical'|'High'|'Medium'|'Low'|'Info' }
Focus on the main vulnerability described or fixed. Be concise. The 'name' should be a short title for the bug type.
'description' should explain the pattern. 'tags' can include terms like 'UAF', 'IPC', 'RaceCondition', etc.
'source' will be pre-filled. Output ONLY the JSON object.`;
      const userPrompt = `Analyze the following commit message and extract a concise BugPattern JSON object.
Commit Message:
---
${commit.message.substring(0, 2000)}
---
${clComments}
Extract the BugPattern JSON:`;

      const llmJson = await this.llmComms.sendMessage(userPrompt, systemPrompt);
      const pData: Partial<BugPattern> = JSON.parse(llmJson);
      const nP: BugPattern = {
        id: `BPA-C-${Date.now()}-${++this.patternIdCounter}`,
        name: pData.name || `Pattern from Commit ${id.substring(0, 7)}`,
        description: pData.description || "No detailed description extracted.",
        cwe: pData.cwe,
        tags: pData.tags || [],
        exampleGoodPractice: pData.exampleGoodPractice,
        exampleVulnerableCode: pData.exampleVulnerableCode,
        source: `Commit ${id.substring(0, 7)}`,
        confidence: pData.confidence || 'Medium',
        severity: pData.severity
      };
      if (!this.sharedContext.knownBugPatterns.find(p => (typeof p !== 'string' && p.id === nP.id))) {
        this.sharedContext.knownBugPatterns.push(nP);
        this.sharedContext.findings.push({
            sourceAgent: this.type,
            type: "NewBugPattern",
            data: { patternId: nP.id, name: nP.name, source: nP.source, description: nP.description.substring(0,100)+"..." },
            timestamp: new Date()
        });
      }
      const entry = this.processedItemsHistory[id] || { lastAnalyzed: "", analysisTypes: [] };
      entry.lastAnalyzed = new Date().toISOString();
      if (!entry.analysisTypes.includes(this.ANALYSIS_TYPE_COMMIT)) entry.analysisTypes.push(this.ANALYSIS_TYPE_COMMIT);
      this.processedItemsHistory[id] = entry;
    } catch (e) { console.error(`BPA: Error processing commit ${id}`, e); }
  }

  private async analyzeIssue(issue: any): Promise<void> {
    const id = issue.id.toString();
    try {
      const details = await this.chromiumApi.getIssue(id);
      if (!details?.description) {
        this.processedItemsHistory[id] = { lastAnalyzed: new Date().toISOString(), analysisTypes: [this.ANALYSIS_TYPE_ISSUE] };
        return;
      }
      let commentsText = "";
      const systemPrompt = `You are an expert security analyst. Extract information to populate a BugPattern JSON object.
The BugPattern structure is: { id: string, name: string, description: string, cwe?: string, tags: string[], exampleGoodPractice?: string, exampleVulnerableCode?: string, source?: string, confidence?: 'High'|'Medium'|'Low', severity?: 'Critical'|'High'|'Medium'|'Low'|'Info' }
Focus on the main vulnerability described. Be concise. The 'name' should be a short title for the bug type.
'description' should explain the pattern. 'tags' can include terms like 'UAF', 'IPC', 'RaceCondition', etc.
'source' will be pre-filled. Output ONLY the JSON object.`;
      const userPrompt = `Analyze the following issue details and extract a concise BugPattern JSON object.
Issue Title: ${details.title}
Issue Description (first 1000 chars):
---
${details.description.substring(0, 1000)}
---
${commentsText}
Extract the BugPattern JSON:`;

      const llmJson = await this.llmComms.sendMessage(userPrompt, systemPrompt);
      const pData: Partial<BugPattern> = JSON.parse(llmJson);
      const nP: BugPattern = {
        id: `BPA-I-${Date.now()}-${++this.patternIdCounter}`,
        name: pData.name || `Pattern from Issue ${id}`,
        description: pData.description || "No detailed description extracted.",
        cwe: pData.cwe,
        tags: pData.tags || [],
        exampleGoodPractice: pData.exampleGoodPractice, // Corrected from p_Data
        exampleVulnerableCode: pData.exampleVulnerableCode,
        source: `Issue ${id}`,
        confidence: pData.confidence || 'Medium',
        severity: pData.severity
      };
      if (!this.sharedContext.knownBugPatterns.find(p => (typeof p !== 'string' && p.id === nP.id))) {
        this.sharedContext.knownBugPatterns.push(nP);
        this.sharedContext.findings.push({
            sourceAgent: this.type,
            type: "NewBugPattern",
            data: { patternId: nP.id, name: nP.name, source: nP.source, description: nP.description.substring(0,100)+"..." },
            timestamp: new Date()
        });
      }
      const entry = this.processedItemsHistory[id] || { lastAnalyzed: "", analysisTypes: [] };
      entry.lastAnalyzed = new Date().toISOString();
      if (!entry.analysisTypes.includes(this.ANALYSIS_TYPE_ISSUE)) entry.analysisTypes.push(this.ANALYSIS_TYPE_ISSUE);
      this.processedItemsHistory[id] = entry;
    } catch (e) { console.error(`BPA: Error processing issue ${id}`, e); }
  }

  public async getContextualAdvice(codeSnippet: string): Promise<string> {
    if (!this.llmComms) return "BPA: LLM not available.";
    if (this.sharedContext.knownBugPatterns.length === 0) return "BPA: No known bug patterns loaded to compare against.";

    const systemPrompt = `You are a security expert. Given a code snippet and a list of known bug patterns, identify if any patterns are relevant and provide advice. Be concise.`;
    let userPrompt = `Code Snippet:\n\`\`\`\n${codeSnippet}\n\`\`\`\n\nKnown Bug Patterns (summarized):\n`;
    this.sharedContext.knownBugPatterns.slice(0, 10).forEach((p: BugPattern | string) => {
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

    for (const request of pendingRequests.slice(0, 1)) {
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
