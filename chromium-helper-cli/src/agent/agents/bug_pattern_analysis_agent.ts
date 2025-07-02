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
    BugPattern,
    ContextualAdvice,
    ContextualAdviceType,
    RegexAdvice,
    GeneralAdvice
} from './types.js'; // Import from new types.ts
import { escapeRegExp } from '../../agent_utils.js';

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
  private lastCommitKeywordIndex: number = 0; // For iterating through commit search keywords

  // Pagination state for issues
  private currentIssueStartIndex: number = 0;
  private totalIssuesDiscoveredInLastFullScan: number = 0;

  // Commit processing will now fetch top N and rely on history, no specific pagination state needed here.

  // private patternExtractionIntervalId?: NodeJS.Timeout; // Not used
  // private issueAnalysisIntervalId?: NodeJS.Timeout; // Not used

  private readonly COMMIT_SEARCH_KEYWORDS = ['security', 'cve', 'vulnerability', 'exploit', 'rce', 'xss', 'uaf', 'asan', 'msan', 'tsan', 'ubsan', 'sandbox', 'permissions'];

  private readonly ANALYSIS_TYPE_COMMIT = "bpa_commit_analysis";
  private readonly ANALYSIS_TYPE_ISSUE = "bpa_issue_analysis";
  private readonly ANALYSIS_TYPE_EVENT = "bpa_event_analysis";


  constructor( llmComms: LLMCommunication, chromiumApi: ChromiumAPI, sharedContext: SharedAgentContextType, config: BugPatternAnalysisConfig ) {
    this.llmComms = llmComms; this.chromiumApi = chromiumApi; this.config = config;
    this.storage = new PersistentStorage('BugPatternAnalysis_data');
    this.setSharedContext(sharedContext); console.log("Bug Pattern Analysis agent initialized."); this.loadState();
  }
  public setSharedContext(context: SharedAgentContextType): void {
    this.sharedContext = context;
    if(!this.sharedContext.knownBugPatterns) this.sharedContext.knownBugPatterns = [];
    if(!this.sharedContext.contextualAdvice) this.sharedContext.contextualAdvice = [];
  }

  private async loadState(): Promise<void> {
    const state = await this.storage.loadData<{
        lastExtraction?: string;
        lastIssueScan?: string;
        patterns?: Array<BugPattern|string>;
        patternIdCounter?: number;
        processedItemsHistory?: ProcessedItemsHistory;
        currentIssueStartIndex?: number;
        totalIssuesDiscoveredInLastFullScan?: number;
        contextualAdviceBPA?: ContextualAdvice[]; // Added for BPA specific advice
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
      if (!state.processedItemsHistory && ((state as any).processedCommitIds || (state as any).processedIssueIds)) {
        const now = new Date().toISOString();
        if ((state as any).processedCommitIds && Array.isArray((state as any).processedCommitIds)) {
          (state as any).processedCommitIds.forEach((id: string) => { this.processedItemsHistory[id] = { lastAnalyzed: now, analysisTypes: [this.ANALYSIS_TYPE_COMMIT + "_legacy"]}; });
        }
        if ((state as any).processedIssueIds && Array.isArray((state as any).processedIssueIds)) {
          (state as any).processedIssueIds.forEach((id: string) => { this.processedItemsHistory[id] = { lastAnalyzed: now, analysisTypes: [this.ANALYSIS_TYPE_ISSUE + "_legacy"]}; });
        }
      }

      // Load and merge contextual advice for BPA
      const loadedAdvice = state.contextualAdviceBPA || [];
      const existingAdviceIds = new Set(this.sharedContext.contextualAdvice?.map(a => a.adviceId) || []);
      loadedAdvice.forEach(advice => {
        if (!existingAdviceIds.has(advice.adviceId)) {
          this.sharedContext.contextualAdvice?.push(advice);
          existingAdviceIds.add(advice.adviceId);
        }
      });
      console.log(`BPA: Loaded ${Object.keys(this.processedItemsHistory).length} items into history. Issue Start Index: ${this.currentIssueStartIndex}. Loaded ${loadedAdvice.length} BPA-specific contextual advice items.`);
    }
  }
  private async saveState(): Promise<void> {
    const maxItems = this.config.maxProcessedHistorySize || 200; const keys = Object.keys(this.processedItemsHistory);
    if (keys.length > maxItems) {
      const sorted = keys.sort((a,b) => new Date(this.processedItemsHistory[a].lastAnalyzed).getTime() - new Date(this.processedItemsHistory[b].lastAnalyzed).getTime());
      for(let i=0; i < keys.length - maxItems; i++) delete this.processedItemsHistory[sorted[i]];
    }

    // Filter and save only BPA-generated advice
    const bpaGeneratedAdvice = this.sharedContext.contextualAdvice?.filter(a => a.sourceAgent === this.type) || [];

    await this.storage.saveData({
        lastExtraction: this.lastPatternExtraction?.toISOString(),
        lastIssueScan: this.lastIssueScan?.toISOString(),
        patterns: [...this.sharedContext.knownBugPatterns],
        patternIdCounter: this.patternIdCounter,
        processedItemsHistory: this.processedItemsHistory,
        currentIssueStartIndex: this.currentIssueStartIndex,
        totalIssuesDiscoveredInLastFullScan: this.totalIssuesDiscoveredInLastFullScan,
        contextualAdviceBPA: bpaGeneratedAdvice
    });
    console.log(`BPA: Saved state. BPA-specific advice items saved: ${bpaGeneratedAdvice.length}`);
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
    const commitsToFetch = this.config.commitsPerCycle || 1;

    // Cycle through keywords for broader search over time
    const keyword = this.COMMIT_SEARCH_KEYWORDS[this.lastCommitKeywordIndex];
    this.lastCommitKeywordIndex = (this.lastCommitKeywordIndex + 1) % this.COMMIT_SEARCH_KEYWORDS.length;

    try {
      console.log(`BPA: Selecting next commit. Query keyword: "${keyword}", Limit: ${commitsToFetch}`);
      const searchResults = await this.chromiumApi.searchCommits({
        query: keyword, // Use single keyword
        limit: commitsToFetch * 3 // Fetch a bit more to increase chances of finding an unprocessed one with a single term
      });

      const fetchedCommits = searchResults.log || [];

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
    const commitHash = commit.commit;
    if (!commitHash) {
      console.warn("BPA: analyzeCommit called with no commit hash.");
      return;
    }

    try {
      const detailedCommit = await this.chromiumApi.getCommitDetails(commitHash);
      const diffText = await this.chromiumApi.getCommitDiff(commitHash);

      let clComments = ""; // Placeholder for actual CL comments if fetched separately
      let diffSummaryForPrompt = "";
      let changedFilesSummary = "";

      if (diffText) {
        const maxDiffChars = this.config.maxDiffSummaryCharsForLLM || 750;
        diffSummaryForPrompt = "\n\nCommit Diff (summary):\n---\n";
        if (diffText.length < maxDiffChars) {
          diffSummaryForPrompt += diffText;
        } else {
          diffSummaryForPrompt += diffText.substring(0, maxDiffChars) + "\n... (diff truncated) ...";
        }
        diffSummaryForPrompt += "\n---";
      }

      if (detailedCommit.tree_diff && detailedCommit.tree_diff.length > 0) {
        changedFilesSummary = "\n\nFiles changed in this commit:\n";
        detailedCommit.tree_diff.slice(0, 10).forEach(fileEntry => { // Limit to 10 files for summary
          changedFilesSummary += `- ${fileEntry.filename} (${fileEntry.status}, +${fileEntry.additions || 0}/-${fileEntry.deletions || 0})\n`;
        });
        if (detailedCommit.tree_diff.length > 10) {
          changedFilesSummary += "... (and more files)\n";
        }
      } else if (commit.files && commit.files.length > 0) { // Fallback to files from searchCommits if tree_diff is empty
         changedFilesSummary = `\n\nFiles changed (from commit log): ${commit.files.slice(0, 5).join(', ')}${commit.files.length > 5 ? ', ...' : ''}`;
      }

      const systemPrompt = `You are an expert security analyst. Extract information to populate a BugPattern JSON object.
The BugPattern structure is: { id: string, name: string, description: string, cwe?: string, tags: string[], exampleGoodPractice?: string, exampleVulnerableCode?: string, source?: string, confidence?: 'High'|'Medium'|'Low', severity?: 'Critical'|'High'|'Medium'|'Low'|'Info' }
Focus on the main vulnerability described or fixed, using the full commit message, list of changed files (with stats), and diff summary. Be concise. The 'name' should be a short title for the bug type.
'description' should explain the pattern. 'tags' can include terms like 'UAF', 'IPC', 'RaceCondition', etc.
'source' will be pre-filled. Output ONLY the JSON object.`;
      const userPrompt = `Analyze the following commit data and extract a concise BugPattern JSON object.
Full Commit Message:
---
${detailedCommit.message.substring(0, 3000)}
---${changedFilesSummary}${diffSummaryForPrompt}
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
        this.generateAndStoreContextualAdviceForPattern(nP);
      }
      const entry = this.processedItemsHistory[commitHash] || { lastAnalyzed: "", analysisTypes: [] };
      entry.lastAnalyzed = new Date().toISOString();
      if (!entry.analysisTypes.includes(this.ANALYSIS_TYPE_COMMIT)) entry.analysisTypes.push(this.ANALYSIS_TYPE_COMMIT);
      this.processedItemsHistory[commitHash] = entry;

      // Step 4: Generate commit-derived general advice
      try {
        const adviceSystemPrompt = `You are a security expert reviewing a commit that fixed a known bug pattern. Your goal is to provide a single piece of concise, actionable security advice for developers reviewing similar code or components in the future. Focus on preventative measures or specific areas to scrutinize based on the bug type and the context of the fix. Output only the single piece of advice as a string.`;
        const topChangedFiles = detailedCommit.tree_diff?.slice(0,3).map(f => f.filename).join(', ') || "N/A";
        const adviceUserPrompt = `A commit fixed a '${nP.name}' vulnerability (tags: ${nP.tags?.join(', ') || 'N/A'}).
Commit Message Snippet:
---
${detailedCommit.message.substring(0, 1000)}...
---
Key files changed included: ${topChangedFiles}

Based on this, provide one concise piece of actionable security advice (1-2 sentences) for developers working on similar code/components:`;

        const generatedAdviceString = await this.llmComms.sendMessage(adviceUserPrompt, adviceSystemPrompt);

        if (generatedAdviceString && generatedAdviceString.length > 10) { // Basic check for non-empty response
          const commitDerivedAdvice: GeneralAdvice = {
            adviceId: `bpa-cmgen-${nP.id.substring(0,10)}-${Date.now()}`,
            sourceAgent: this.type,
            type: ContextualAdviceType.General,
            advice: generatedAdviceString.trim(),
            description: `General advice derived from commit ${commitHash.substring(0,7)} which fixed a ${nP.name}.`,
            keywords: [
                ...(nP.tags || []),
                ...(detailedCommit.tree_diff?.slice(0,1).map(f => f.filename.split('/').pop()?.replace(/\.\w+$/, "") || "") || []) // First changed filename without extension
            ].filter(kw => kw), // Remove empty keywords
            priority: 6,
            createdAt: new Date().toISOString(),
            // source: `commit:${commitHash}` // Already part of description
          };
          this.sharedContext.contextualAdvice?.push(commitDerivedAdvice);
          console.log(`BPA: Generated commit-derived general advice for pattern ${nP.name} from commit ${commitHash.substring(0,7)}.`);
        }
      } catch(adviceError) {
        console.warn(`BPA: Failed to generate commit-derived advice for ${commitHash}: ${(adviceError as Error).message}`);
      }

    } catch (e) { console.error(`BPA: Error processing commit ${commitHash}`, e); }
  }

  private async analyzeIssue(issue: any): Promise<void> {
    const id = issue.id.toString();
    try {
      const details = await this.chromiumApi.getIssue(id);
      if (!details?.description) {
        this.processedItemsHistory[id] = { lastAnalyzed: new Date().toISOString(), analysisTypes: [this.ANALYSIS_TYPE_ISSUE] };
        return;
      }

      let associatedCommitInfo = "";
      let primaryCommitHashToFetch: string | null = null;

      // Prefer structured relatedCLs if available
      if (details.relatedCLs && details.relatedCLs.length > 0) {
        // Assuming relatedCLs might contain full commit hashes or CL numbers.
        // For now, we'll try the first one, assuming it's a hash or CL that getCommitDetails can handle.
        // A more robust solution would parse these to ensure they are valid hashes.
        const firstRelatedCl = details.relatedCLs[0];
        if (typeof firstRelatedCl === 'string' && /^[a-f0-9]{7,40}$/i.test(firstRelatedCl)) { // Check if it looks like a hash
             primaryCommitHashToFetch = firstRelatedCl;
             console.log(`BPA: Using first relatedCL ${primaryCommitHashToFetch} from issue ${id}.`);
        } else if (typeof firstRelatedCl === 'string' && /^\d+$/.test(firstRelatedCl)) { // Check if it looks like a CL number
            console.log(`BPA: Found CL number ${firstRelatedCl} in relatedCLs for issue ${id}. Attempting to use it with getCommitDetails.`);
            primaryCommitHashToFetch = firstRelatedCl; // Assume getCommitDetails might handle CL numbers
        } else {
            console.log(`BPA: First relatedCL '${firstRelatedCl}' for issue ${id} is not a recognized hash or CL number format. Falling back to regex search.`);
        }
      }

      if (!primaryCommitHashToFetch) {
        const textToSearchCommits = details.description + (details.comments?.map(c => c.content).join('\n') || '');
        const commitHashRegex = /\b([a-f0-9]{40})\b/gi;
        const crDashCommitRegex = /chromiumdash\.appspot\.com\/commit\/([a-f0-9]{40})/gi;
        // Gerrit CL regex is less useful here if we can't resolve CL# to hash easily via API.
        // const gerritClRegex = /chromium-review\.googlesource\.com\/c\/chromium\/src\/\+\/(\d+)/gi;

        let match;
        if ((match = commitHashRegex.exec(textToSearchCommits)) !== null) {
          primaryCommitHashToFetch = match[1];
        } else if ((match = crDashCommitRegex.exec(textToSearchCommits)) !== null) {
          primaryCommitHashToFetch = match[1];
        }
        if (primaryCommitHashToFetch) {
            console.log(`BPA: Found commit hash ${primaryCommitHashToFetch} via regex in issue ${id}.`);
        }
      }

      if (primaryCommitHashToFetch) {
        try {
          console.log(`BPA: Fetching details for commit ${primaryCommitHashToFetch} linked to issue ${id}.`);
          const commitDetails = await this.chromiumApi.getCommitDetails(primaryCommitHashToFetch);
          const commitDiffText = await this.chromiumApi.getCommitDiff(primaryCommitHashToFetch);

          associatedCommitInfo = "\n\n--- Associated Commit Details ---\n";
          associatedCommitInfo += `Commit: ${commitDetails.commit}\n`;
          associatedCommitInfo += `Message: ${commitDetails.message.substring(0, 1000)}...\n`; // Increased message length

          if (commitDetails.tree_diff && commitDetails.tree_diff.length > 0) {
            associatedCommitInfo += "Files changed:\n";
            commitDetails.tree_diff.slice(0, 5).forEach(fileEntry => {
              associatedCommitInfo += `  - ${fileEntry.filename} (${fileEntry.status}, +${fileEntry.additions || 0}/-${fileEntry.deletions || 0})\n`;
            });
            if (commitDetails.tree_diff.length > 5) associatedCommitInfo += "  ... (and more files)\n";
          }

          if (commitDiffText) {
            const maxDiffChars = this.config.maxDiffSummaryCharsForLLM || 500;
            associatedCommitInfo += "\nDiff Summary:\n";
            if (commitDiffText.length < maxDiffChars) {
              associatedCommitInfo += commitDiffText;
            } else {
              associatedCommitInfo += commitDiffText.substring(0, maxDiffChars) + "\n... (diff truncated) ...";
            }
          }
          associatedCommitInfo += "\n--- End Associated Commit Details ---";
        } catch (e) {
          console.warn(`BPA: Failed to get details for commit ${primaryCommitHashToFetch} linked to issue ${id}: ${(e as Error).message}`);
          associatedCommitInfo = `\n\n(Could not fetch details for potential commit ${primaryCommitHashToFetch})\n`;
        }
      }

      // Summarize key comments (optional enhancement)
      let keyCommentsSummary = "";
      if (details.comments && details.comments.length > 0) {
        const securityKeywords = ["vulnerability", "exploit", "root cause", "security impact", "uaf", "heap overflow"];
        const relevantComments = details.comments.filter(comment =>
            securityKeywords.some(kw => comment.content.toLowerCase().includes(kw))
        ).slice(0, 2); // Take top 2 relevant comments

        if (relevantComments.length > 0) {
            keyCommentsSummary = "\n\n--- Key Issue Comments ---\n";
            relevantComments.forEach(comment => {
                keyCommentsSummary += `Comment by ${comment.author} (${comment.timestamp}):\n${comment.content.substring(0, 300)}...\n---\n`;
            });
            keyCommentsSummary += "--- End Key Issue Comments ---\n";
        }
      }

      let commentsText = ""; // Main commentsText for prompt (currently empty, but structure is there)
      const systemPrompt = `You are an expert security analyst. Extract information to populate a BugPattern JSON object.
The BugPattern structure is: { id: string, name: string, description: string, cwe?: string, tags: string[], exampleGoodPractice?: string, exampleVulnerableCode?: string, source?: string, confidence?: 'High'|'Medium'|'Low', severity?: 'Critical'|'High'|'Medium'|'Low'|'Info' }
Focus on the main vulnerability described in the issue. If associated commit data is provided, use it to refine the pattern. Be concise. The 'name' should be a short title for the bug type.
'description' should explain the pattern. 'tags' can include terms like 'UAF', 'IPC', 'RaceCondition', etc.
'source' will be pre-filled. Output ONLY the JSON object.`;
      const userPrompt = `Analyze the following issue details (and associated commit if found, and key comments) and extract a concise BugPattern JSON object.
Issue Title: ${details.title}
Issue Description (first 1000 chars):
---
${details.description.substring(0, 1000)}
---${associatedCommitInfo}${keyCommentsSummary}
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
        this.generateAndStoreContextualAdviceForPattern(nP);
      }
      const entry = this.processedItemsHistory[id] || { lastAnalyzed: "", analysisTypes: [] };
      entry.lastAnalyzed = new Date().toISOString();
      if (!entry.analysisTypes.includes(this.ANALYSIS_TYPE_ISSUE)) entry.analysisTypes.push(this.ANALYSIS_TYPE_ISSUE);
      this.processedItemsHistory[id] = entry;
    } catch (e) { console.error(`BPA: Error processing issue ${id}`, e); }
  }

  private async generateAndStoreContextualAdviceForPattern(pattern: BugPattern): Promise<void> { // Made async
    if (!this.sharedContext.contextualAdvice) {
      this.sharedContext.contextualAdvice = [];
    }

    // New: Try to search for exact code snippet from exampleVulnerableCode
    if (pattern.exampleVulnerableCode) {
      const snippet = pattern.exampleVulnerableCode;
      // Basic suitability check for direct search (e.g., not too long, not too short)
      if (snippet.length > 10 && snippet.length < 150 && !snippet.includes('\n')) { // Single, reasonably sized line
        try {
          console.log(`BPA: Searching for exact snippet from pattern ${pattern.name}: "${snippet.substring(0,50)}..."`);
          const searchResults = await this.chromiumApi.searchCode({ query: `"${snippet}"`, limit: 5 }); // Exact phrase search

          if (searchResults.length > 0) {
            // Check if any result is outside what might be the source of the example itself (heuristic)
            // This is hard to do perfectly without knowing the source file of the pattern example.
            // For now, if we find any matches, we'll assume they are relevant additional locations.
            const locations = searchResults.map(r => `${r.file}:${r.line}`).slice(0,3);
            const exactMatchAdvice: RegexAdvice = {
              adviceId: `bpa-exactmatch-${pattern.id}-${Date.now()}`,
              sourceAgent: this.type,
              type: ContextualAdviceType.Regex,
              regexPattern: escapeRegExp(snippet), // Use the snippet itself as a regex pattern
              advice: `Pattern '${pattern.name}' (Severity: ${pattern.severity || 'N/A'}). An exact code snippet matching its vulnerable example ('${snippet.substring(0,50)}...') was found in locations like: ${locations.join(', ')}. These should be reviewed.`,
              description: `Exact code snippet match for pattern: ${pattern.name}`,
              priority: 8, // High priority for exact matches
              createdAt: new Date().toISOString(),
            };
            this.sharedContext.contextualAdvice.push(exactMatchAdvice);
            console.log(`BPA: Created exact match RegexAdvice for pattern ${pattern.name} based on snippet search.`);
          }
        } catch (e) {
          console.warn(`BPA: Error searching for exact code snippet for pattern ${pattern.name}: ${(e as Error).message}`);
        }
      }
    }


    // Try to generate a generalized regex from vulnerable code example (fallback/complementary)
    if (pattern.exampleVulnerableCode) {
      const potentialRegex = this.extractRegexFromExample(pattern.exampleVulnerableCode);
      if (potentialRegex) {
        // Avoid duplicating if the exact match advice already used the same pattern (less likely but possible)
        if (!this.sharedContext.contextualAdvice.find(a => a.type === ContextualAdviceType.Regex && (a as RegexAdvice).regexPattern === potentialRegex && a.adviceId.startsWith('bpa-exactmatch'))) {
          const regexAdvice: RegexAdvice = {
            adviceId: `bpa-rgx-${pattern.id}-${Date.now()}`,
            sourceAgent: this.type,
            type: ContextualAdviceType.Regex,
            regexPattern: potentialRegex,
            advice: `Potential vulnerability related to '${pattern.name}'. Description: ${pattern.description.substring(0,100)}... A generalized pattern derived from its example ('${potentialRegex}') might indicate this vulnerability. Severity: ${pattern.severity || 'N/A'}.`,
            description: `Generalized regex from vulnerable code example for pattern: ${pattern.name}`,
            priority: pattern.severity === 'Critical' || pattern.severity === 'High' ? 7 : 5, // Slightly lower than exact match
            createdAt: new Date().toISOString(),
          };
          this.sharedContext.contextualAdvice.push(regexAdvice);
        }
      }
    }

    // General advice based on the bug pattern (always add this)
    const generalAdvice: GeneralAdvice = {
      adviceId: `bpa-gen-${pattern.id}-${Date.now()}`,
      sourceAgent: this.type,
      type: ContextualAdviceType.General,
      advice: `Be aware of bug pattern '${pattern.name}' (Severity: ${pattern.severity || 'N/A'}). Description: ${pattern.description}. Tags: ${(pattern.tags || []).join(', ')}. This is relevant when reviewing code that might involve ${pattern.tags.join(', or ')}.`,
      keywords: [...(pattern.tags || []), pattern.name.toLowerCase()],
      description: `General advice for bug pattern: ${pattern.name}`,
      priority: pattern.severity === 'Critical' || pattern.severity === 'High' ? 7 : 5,
      createdAt: new Date().toISOString(),
    };
    this.sharedContext.contextualAdvice.push(generalAdvice);

    // Clean up old advice from this agent
    const maxBpaAdvice = this.config.maxContextualAdviceItemsPerAgentBPA || 30; // New config option
    const bpaAdviceEntries = this.sharedContext.contextualAdvice.filter(a => a.sourceAgent === this.type);
    if (bpaAdviceEntries.length > maxBpaAdvice) {
        bpaAdviceEntries.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        const adviceToRemove = bpaAdviceEntries.slice(maxBpaAdvice).map(a => a.adviceId);
        this.sharedContext.contextualAdvice = this.sharedContext.contextualAdvice.filter(a => !adviceToRemove.includes(a.adviceId));
    }
     console.log(`BPA: Generated contextual advice for pattern ${pattern.name}. Total BPA advice: ${this.sharedContext.contextualAdvice.filter(a => a.sourceAgent === this.type).length}`);
  }

  // Helper to attempt to extract a simple regex from code.
  // This is very basic and can be significantly improved.
  private extractRegexFromExample(code: string): string | undefined {
    // Look for function calls like: some_function(...) or object->method(...)
    const funcCallMatch = code.match(/(\b\w+(?:->|::)\w+\b\s*\(|\b\w+\s*\()/);
    if (funcCallMatch && funcCallMatch[1]) {
      // Escape special characters for regex and make it more general
      let pattern = funcCallMatch[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (pattern.endsWith('\\(')) { // if it's a function call
        pattern = pattern.slice(0, -2) + '\\s*\\('; // Allow space before parenthesis
      }
      return pattern;
    }
    // Look for assignments like: variable = vulnerable_source...
    const assignmentMatch = code.match(/(\b\w+\b\s*=\s*\b\w+\b)/);
    if (assignmentMatch && assignmentMatch[1]) {
        return assignmentMatch[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    return undefined;
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
