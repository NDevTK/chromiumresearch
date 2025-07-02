// src/agent/agents/proactive_bug_finder.ts
import { LLMCommunication } from '../llm_communication.js';
import { PersistentStorage } from '../persistent_storage.js';
import { ChromiumAPI, SearchResult } from '../../api.js';
import { ProactiveBugFinderConfig } from '../../agent_config.js';
import { computeSha256Hash } from '../../agent_utils.js';
import {
    SpecializedAgent,
    SpecializedAgentType,
    SharedAgentContextType,
    ProcessedItemsHistory,
    CodebaseUnderstandingAgent,
    ContextualAdvice,
    ContextualAdviceType,
    RegexAdvice,
    FilePathAdvice,
    GeneralAdvice
} from './types.js'; // Import from new types.ts
import { computeSha256Hash } from '../../agent_utils.js';

// --- ProactiveBugFinder ---
export class ProactiveBugFinder implements SpecializedAgent {
  public type = SpecializedAgentType.ProactiveBugFinding;
  private llmComms: LLMCommunication;
  private storage: PersistentStorage;
  private chromiumApi: ChromiumAPI;
  private sharedContext!: SharedAgentContextType;
  private config: ProactiveBugFinderConfig;
  private isActive: boolean = false;
  private isAnalyzing: boolean = false; // To prevent concurrent cycle runs
  // private analysisIntervalId?: NodeJS.Timeout; // Not used in current loop structure
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
    console.log("PBF: Continuous operation signaled to stop.");
  }

  public async getStatus(): Promise<string> {
    let s = `PBF: ${this.isActive?'Continuous - Running':'Idle/Stopped'}.`;
    s += ` ${this.isAnalyzing ? 'Currently Processing Item.' : 'Awaiting next item/discovery.'}`;
    if(this.lastAnalysisTimestamp)s+=` Last Item Processed At: ${this.lastAnalysisTimestamp.toLocaleTimeString()}.`;
    s+=` History: ${Object.keys(this.processedItemsHistory).length} files.`;
    return s;
  }

  private async runContinuousAnalysisLoop(): Promise<void> {
    console.log("PBF: Entered continuous analysis loop.");
    while (this.isActive) {
      if (this.isAnalyzing) {
        await new Promise(resolve => setTimeout(resolve, this.config.itemProcessingCheckIntervalMs || 1000));
        continue;
      }

      this.isAnalyzing = true;
      let workFound = false;

      try {
        await this.processPendingRequests();
        const candidateFile = await this.selectNextFileForHeuristicAnalysis();

        if (candidateFile) {
          workFound = true;
          console.log(`PBF: Selected file for heuristic analysis: ${candidateFile.file}`);
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
            const relevantAdvice = this.getRelevantContextualAdvice(targetFile.file, fileData.content);
            let adviceTextForPrompt = "";
            if (relevantAdvice.length > 0) {
                console.log(`PBF: Found ${relevantAdvice.length} relevant advice items for ${targetFile.file}. Top item: "${relevantAdvice[0].advice.substring(0, 50)}..." (ID: ${relevantAdvice[0].adviceId})`);
                adviceTextForPrompt = "\n\n--- Relevant Contextual Advice ---\n";
                relevantAdvice.forEach(advice => {
                    adviceTextForPrompt += `- (${advice.type} from ${advice.sourceAgent}): ${advice.advice}\n`;
                    if (advice.type === ContextualAdviceType.Regex && 'regexPattern' in advice) {
                         adviceTextForPrompt += `  (Consider if pattern "${(advice as RegexAdvice).regexPattern}" matches anywhere in the code.)\n`;
                    }
                });
                adviceTextForPrompt += "--- End Contextual Advice ---\n";
            }

            let cuaContextText = "";
            const cua = this.sharedContext.specializedAgents?.get(SpecializedAgentType.CodebaseUnderstanding) as CodebaseUnderstandingAgent | undefined;
            if (cua) {
                try {
                    console.log(`PBF: Fetching CUA context for ${targetFile.file} during continuous analysis.`);
                    const snippetForCua = fileData.content.length > 2000 ? fileData.content.substring(0, 2000) : fileData.content;
                    cuaContextText = await cua.provideContextForFile(targetFile.file, snippetForCua);
                    if (cuaContextText) {
                        cuaContextText = `\n\n--- Context from CodebaseUnderstandingAgent ---\n${cuaContextText}\n--- End CUA Context ---\n`;
                    }
                } catch (e) {
                    console.warn(`PBF: Failed to get CUA context for ${targetFile.file} in continuous loop: ${(e as Error).message}`);
                }
            }

            const { blameSummary, historySummary } = await this.getExtendedFileContextForLLM(targetFile.file, fileData.content);

            const analysisSystemPrompt = "You are an expert Chromium security auditor. Analyze the provided C++ code for vulnerabilities. Consider context from CodebaseUnderstandingAgent, contextual advice, blame information, and file history. Highlight if any of these were particularly relevant to your findings.";
            const analysisUserPrompt = `File: ${targetFile.file}\n${cuaContextText}${adviceTextForPrompt}${blameSummary}${historySummary}File content (first 4000 chars):\n\`\`\`cpp\n${fileData.content.substring(0,4000)}\n\`\`\`\n\nTask: Identify potential security vulnerabilities. Rate severity (Critical, High, Medium, Low). Be concise. If a specific pattern is risky globally, output: SEARCHABLE_PATTERN: <pattern_to_search_for_globally_in_codesearch>`;
            const llmAnalysis = await this.llmComms.sendMessage(analysisUserPrompt, analysisSystemPrompt);

            const findingData = {
              file: targetFile.file,
              analysis: llmAnalysis,
              snippet: fileData.content.substring(0, 500),
              relatedOccurrences: [],
              cuaContextUsed: !!cuaContextText,
              adviceUsed: relevantAdvice.map(a=>a.adviceId),
              blameUsed: !!(blameSummary && !blameSummary.includes("Could not retrieve blame")),
              historyUsed: !!(historySummary && !historySummary.includes("Could not retrieve file history"))
            };
            this.sharedContext.findings.push({
                sourceAgent: this.type, type: "PotentialVulnerability",
                data: findingData,
                timestamp: new Date()
            });

            this.extractAndStoreSearchablePattern(llmAnalysis, targetFile.file);

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
        }
      } catch (error) {
        console.error(`PBF: Error during continuous analysis iteration:`, error);
      } finally {
        this.isAnalyzing = false;
      }

      if (!workFound) {
        const idleDelayMs = this.config.idleCycleDelayMs || 5000;
        await new Promise(resolve => setTimeout(resolve, idleDelayMs));
      }
      await new Promise(resolve => setTimeout(resolve, this.config.interItemDelayMs || 100));
    }
    console.log("PBF: Exited continuous analysis loop because isActive is false.");
  }

  private async selectNextFileForHeuristicAnalysis(): Promise<SearchResult | undefined> {
    type CandidateFile = SearchResult & { score: number; reason: string };
    let potentialCandidates: CandidateFile[] = [];

    try {
        const query = `(path:${this.config.sensitivePathPatterns?.join(' OR path:')}) (security OR fix OR vuln OR warning OR critical)`;
        const recentCommits = await this.chromiumApi.searchCommits({ query, limit: this.config.maxCandidatesPerHeuristicQuery || 10 });

        if (recentCommits.log && recentCommits.log.length > 0) {
            for (const commit of recentCommits.log) {
                if (commit.files) {
                    for (const filePath of commit.files) {
                        if (!filePath.match(/\.(cc|h|cpp|js|ts|java|py)$/i) && !filePath.endsWith('.mojom')) continue;

                        let score = this.config.prioritizationScore?.recentClMention || 2;
                        if (this.config.sensitivePathPatterns?.some(p => filePath.includes(p))) {
                            score += this.config.prioritizationScore?.pathMatch || 5;
                        }
                        potentialCandidates.push({
                            file: filePath, line: 0, browserUrl: '', type: 'recent-commit-sensitive',
                            score,
                            reason: `Recent commit to sensitive area. Score: ${score}`
                        });
                    }
                }
            }
        }
    } catch (e) { console.warn(`PBF: Error gathering candidates from recent commits: ${(e as Error).message}`); }

    // Heuristic 2: Files in modules marked by CUA as having security risks (from existing insights stored in PBF's sharedContext)
    if (this.sharedContext?.codebaseInsights) {
      for (const modulePath in this.sharedContext.codebaseInsights) {
        const insight = this.sharedContext.codebaseInsights[modulePath];
        if (insight.commonSecurityRisks && insight.commonSecurityRisks.length > 0) {
          // Heuristic: Prioritize Key Files identified by CUA within this risky module
          if (insight.keyFiles && insight.keyFiles.length > 0) {
            for (const keyFile of insight.keyFiles) {
              if (!keyFile.filePath.match(/\.(cc|h|cpp|js|ts)$/i)) continue;

              const entry = this.processedItemsHistory[keyFile.filePath];
              const recentlyCheckedByHeuristic = entry && entry.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP) &&
                (new Date().getTime() - new Date(entry.lastAnalyzed).getTime()) < (this.config.recheckIntervalMs || 24 * 3600 * 1000);
              if (recentlyCheckedByHeuristic) continue;

              let score = this.config.prioritizationScore?.cuaKeyFileInRiskyModule || 6;
              const churnBonus = (keyFile.recentCommitSummary?.length || 0) * (this.config.prioritizationScore?.cuaKeyFileChurnBonus || 1);
              score += churnBonus;
              if (this.config.sensitivePathPatterns?.some(p => keyFile.filePath.includes(p))) {
                score += this.config.prioritizationScore?.pathMatch || 5;
              }

              // Create a SearchResult-like object for keyFile
              const candidateKeyFile: CandidateFile = {
                file: keyFile.filePath,
                line: 0, // Not applicable here, or could be line of a primary symbol if available
                browserUrl: '', // Construct if needed: `https://source.chromium.org/chromium/chromium/src/+/main:${keyFile.filePath}`
                type: 'cua-keyfile-risky-module',
                score,
                reason: `CUA KeyFile in risky module '${modulePath}'. Churn: ${keyFile.recentCommitSummary?.length || 0}. Risks: ${insight.commonSecurityRisks.join(', ')}. Score: ${score}`
              };
              potentialCandidates.push(candidateKeyFile);
            }
          }

          // Fallback: Search for other files in the risky module (existing logic, slightly lower base score)
          try {
            const filesInRiskyModule = await this.chromiumApi.searchCode({
              query: "",
              filePattern: `${modulePath}/`, // Ensure modulePath ends with / if it's a dir
              limit: (this.config.maxCandidatesPerHeuristicQuery || 5)
            });
            for (const searchResult of filesInRiskyModule) {
              if (!searchResult.file.match(/\.(cc|h|cpp|js|ts)$/i)) continue;
              if (potentialCandidates.find(pc => pc.file === searchResult.file)) continue; // Already added as a KeyFile

              const entry = this.processedItemsHistory[searchResult.file];
              const recentlyCheckedByHeuristic = entry && entry.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP) &&
                (new Date().getTime() - new Date(entry.lastAnalyzed).getTime()) < (this.config.recheckIntervalMs || 24 * 3600 * 1000);
              if (recentlyCheckedByHeuristic) continue;

              let score = (this.config.prioritizationScore?.cuaRiskMention || 4); // General file in risky module
              if (this.config.sensitivePathPatterns?.some(p => searchResult.file.includes(p))) {
                score += this.config.prioritizationScore?.pathMatch || 5;
              }
              potentialCandidates.push({
                ...searchResult, score,
                reason: `File in CUA-identified risky module '${modulePath}'. Risks: ${insight.commonSecurityRisks.join(', ')}. Score: ${score}`
              });
            }
          } catch (e) { console.warn(`PBF: Error searching general files in CUA risky module ${modulePath}: ${(e as Error).message}`); }
        }
      }
    }

    // New Heuristic: Reacting to CUA ModuleInsightUpdated Events
    const cuaModuleUpdateEvents = (this.sharedContext.recentEvents || []).filter(
        event => event.eventType === "ModuleInsightUpdated" &&
                 event.sourceAgent === SpecializedAgentType.CodebaseUnderstanding &&
                 !this.processedItemsHistory[event.eventId] // Check if PBF already processed this event
    );

    if (cuaModuleUpdateEvents.length > 0) {
        for (const event of cuaModuleUpdateEvents) {
            const eventData = event.data as { modulePath: string, summary?: string, commonSecurityRisks?: string[], lastAnalyzed: string };
            if (eventData.modulePath && eventData.commonSecurityRisks && eventData.commonSecurityRisks.length > 0) {
                console.log(`PBF: Reacting to CUA ModuleInsightUpdated event for risky module: ${eventData.modulePath}`);
                try {
                    const filesToConsider = await this.chromiumApi.searchCode({
                        query: "", // No specific content query
                        filePattern: `${eventData.modulePath}/`,
                        limit: (this.config.maxCandidatesPerHeuristicQuery || 3) * 2 // Fetch more to filter
                    });
                    for (const searchResult of filesToConsider) {
                        if (!searchResult.file.match(/\.(cc|h|cpp)$/i)) continue; // Client-side filter for C++ files

                        const entry = this.processedItemsHistory[searchResult.file];
                        const recentlyCheckedByHeuristic = entry && entry.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP) &&
                            (new Date().getTime() - new Date(entry.lastAnalyzed).getTime()) < (this.config.recheckIntervalMs || 24 * 3600 * 1000);
                        if (recentlyCheckedByHeuristic) continue; // Avoid re-adding if just scanned

                        let score = (this.config.prioritizationScore?.cuaRiskMention || 4) + 2; // Higher score for event-driven
                        if (this.config.sensitivePathPatterns?.some(p => searchResult.file.includes(p))) {
                            score += this.config.prioritizationScore?.pathMatch || 5;
                        }
                        // Add to potentialCandidates, ensuring not to duplicate if already added by another heuristic this cycle
                        if (!potentialCandidates.find(pc => pc.file === searchResult.file)) {
                            potentialCandidates.push({
                                ...searchResult, score,
                                reason: `EVENT DRIVEN: File in CUA-updated risky module '${eventData.modulePath}'. Risks: ${eventData.commonSecurityRisks.join(', ')}. Score: ${score}`
                            });
                        }
                    }
                } catch (e) { console.warn(`PBF: Error searching files from CUA event for ${eventData.modulePath}: ${(e as Error).message}`); }
            }
            // Mark event as processed by PBF by adding its ID to PBF's history with a specific analysis type
            this.processedItemsHistory[event.eventId] = { lastAnalyzed: new Date().toISOString(), analysisTypes: ["pbf_cua_event_reaction"] };
        }
    }

    // Heuristic 3: Files with specific risky keywords
    if (this.config.heuristicKeywords && this.config.heuristicKeywords.length > 0) {
        for (const keyword of this.config.heuristicKeywords.slice(0, 3)) { // Process a few keywords per cycle
            try {
                // Search for the keyword in C++ files.
                const keywordFiles = await this.chromiumApi.searchCode({
                    query: keyword,
                    language: "cpp", // This implies .cc, .h, .cpp
                    limit: (this.config.maxCandidatesPerHeuristicQuery || 5)
                });

                for (const searchResult of keywordFiles) {
                    // Client-side filter: only consider if the file is in a sensitive path (if defined)
                    if (this.config.sensitivePathPatterns && this.config.sensitivePathPatterns.length > 0) {
                        if (!this.config.sensitivePathPatterns.some(p => searchResult.file.startsWith(p))) {
                            continue; // Skip if not in a defined sensitive path
                        }
                    }
                     // Double check extension, though language filter should be primary
                    if (!searchResult.file.match(/\.(cc|h|cpp)$/i)) continue;


                    let score = this.config.prioritizationScore?.keywordInFile || 3;
                    if (this.config.sensitivePathPatterns?.some(p => searchResult.file.startsWith(p))) {
                    score += this.config.prioritizationScore?.pathMatch || 5;
                }
                potentialCandidates.push({
                    ...searchResult,
                    score,
                    reason: `File contains heuristic keyword. Score: ${score}`
                });
            }
        } catch (e) { console.warn(`PBF: Error searching files by heuristic keywords: ${(e as Error).message}`);}
    }

    if (Math.random() < (this.config.patternScanFrequency || 0.1)) {
        const highConfidencePatterns = (this.sharedContext.knownBugPatterns || [])
            .filter(p => typeof p !== 'string' && (p.confidence === 'High' || p.severity === 'Critical' || p.severity === 'High') && p.exampleVulnerableCode) as import('./types.js').BugPattern[]; // Explicit import for BugPattern

        if (highConfidencePatterns.length > 0) {
            const patternToScan = highConfidencePatterns[Math.floor(Math.random() * highConfidencePatterns.length)];
            const searchQuery = patternToScan.exampleVulnerableCode!.substring(0, 100);
            try {
                console.log(`PBF: Heuristic - Searching for files matching pattern: "${patternToScan.name}" (query: "${searchQuery}")`);
                const patternMatches = await this.chromiumApi.searchCode({ query: searchQuery, limit: 3 });
                for (const match of patternMatches) {
                    if (!match.file.match(/\.(cc|h|cpp)$/i)) continue;
                    potentialCandidates.push({
                        ...match,
                        score: (this.config.prioritizationScore?.knownPatternMatch || 5),
                        reason: `File matches known vulnerable pattern "${patternToScan.name}". Score: ${(this.config.prioritizationScore?.knownPatternMatch || 5)}`
                    });
                }
            } catch (e) { console.warn(`PBF: Error searching files by known pattern "${patternToScan.name}": ${(e as Error).message}`); }
        }
    }

    if (potentialCandidates.length === 0) {
        return undefined;
    }

    const viableCandidates = potentialCandidates.filter(cand => {
        const entry = this.processedItemsHistory[cand.file];
        const isStale = entry && (new Date().getTime() - new Date(entry.lastAnalyzed).getTime()) > (this.config.recheckIntervalMs || 7 * 24 * 3600 * 1000);
        return !entry || !entry.analysisTypes.includes(this.ANALYSIS_TYPE_HEURISTIC_SWEEP) || isStale;
    }).sort((a, b) => b.score - a.score);

    if (viableCandidates.length > 0) {
        console.log(`PBF: Selected candidate '${viableCandidates[0].file}' with score ${viableCandidates[0].score} (Reason: ${viableCandidates[0].reason.substring(0,100)}...). Total viable: ${viableCandidates.length}`);
        return viableCandidates[0];
    }
    return undefined;
  }

  public async analyzeSpecificFile(filePath: string, analysisType: string = this.ANALYSIS_TYPE_SPECIFIC_REQUEST, fileContent?: string): Promise<string> {
    if (!this.chromiumApi && !fileContent) return "Agent not ready (ChromiumAPI missing and no content provided).";
    if (!this.llmComms) return "Agent not ready (LLMCommunication missing).";

    try {
      let currentHash = "";
      let contentToAnalyze = fileContent;
      let snippet = "";

      if (!contentToAnalyze) {
        const fileData = await this.chromiumApi.getFile({ filePath });
        contentToAnalyze = fileData.content;
        currentHash = computeSha256Hash(contentToAnalyze);
        snippet = contentToAnalyze.substring(0, 500);
      } else {
        currentHash = computeSha256Hash(contentToAnalyze);
        snippet = contentToAnalyze.substring(0, 500);
      }

      const relevantAdvice = this.getRelevantContextualAdvice(filePath, contentToAnalyze);
      let adviceTextForPrompt = "";
      if (relevantAdvice.length > 0) {
          console.log(`PBF: Found ${relevantAdvice.length} relevant advice items for specific analysis of ${filePath}. Top item: "${relevantAdvice[0].advice.substring(0, 50)}..." (ID: ${relevantAdvice[0].adviceId})`);
          adviceTextForPrompt = "\n\n--- Relevant Contextual Advice ---\n";
          relevantAdvice.forEach(advice => {
              adviceTextForPrompt += `- (${advice.type} from ${advice.sourceAgent}): ${advice.advice}\n`;
              if (advice.type === ContextualAdviceType.Regex && 'regexPattern' in advice) {
                    adviceTextForPrompt += `  (Consider if pattern "${(advice as RegexAdvice).regexPattern}" matches anywhere in the code.)\n`;
              }
          });
          adviceTextForPrompt += "--- End Contextual Advice ---\n";
      }

      let cuaContext = "";
      const cua = this.sharedContext.specializedAgents?.get(SpecializedAgentType.CodebaseUnderstanding) as CodebaseUnderstandingAgent | undefined;
      if (cua) {
        try {
          console.log(`PBF: Fetching CUA context for ${filePath} during specific analysis.`);
          // Use a smaller snippet for CUA context if full content is large
          const snippetForCua = contentToAnalyze!.length > 2000 ? contentToAnalyze!.substring(0, 2000) : contentToAnalyze!;
          cuaContext = await cua.provideContextForFile(filePath, snippetForCua);
          if (cuaContext) {
            cuaContext = `\n\n--- Context from CodebaseUnderstandingAgent ---\n${cuaContext}\n--- End CUA Context ---\n`;
          }
        } catch (e) {
          console.warn(`PBF: Failed to get CUA context for ${filePath}: ${(e as Error).message}`);
        }
      }

      const { blameSummary, historySummary } = await this.getExtendedFileContextForLLM(filePath, contentToAnalyze!);

      const systemPromptForPBF = "You are an expert Chromium security auditor. Analyze the provided C++ code for vulnerabilities. Consider context from CodebaseUnderstandingAgent, contextual advice, blame information, and file history. Highlight if any of these were particularly relevant to your findings.";
      const analysisPrompt = `File: ${filePath}\n${cuaContext}${adviceTextForPrompt}${blameSummary}${historySummary}File content (or relevant part):\n\`\`\`cpp\n${contentToAnalyze!.substring(0,4000)}\n\`\`\`\n\nTask: Identify potential security vulnerabilities. Rate severity (Critical, High, Medium, Low). Be concise. If a specific pattern is risky globally, output: SEARCHABLE_PATTERN: <pattern_to_search_for_globally_in_codesearch>`;
      const analysis = await this.llmComms.sendMessage(analysisPrompt, systemPromptForPBF);

      const findingData = {
        file:filePath,
        analysis:analysis,
        snippet:snippet,
        cuaContextUsed: !!cuaContext,
        adviceUsed: relevantAdvice.map(a=>a.adviceId),
        blameUsed: !!(blameSummary && !blameSummary.includes("Could not retrieve blame")),
        historyUsed: !!(historySummary && !historySummary.includes("Could not retrieve file history"))
      };
      this.sharedContext.findings.push({ sourceAgent:this.type, type:"SpecificFileAnalysis", data:findingData, timestamp:new Date() });

      this.extractAndStoreSearchablePattern(analysis, filePath);

      if (analysis.toLowerCase().includes("critical") || analysis.toLowerCase().includes("high severity")) {
        const eventId = `evt-pbf-${Date.now()}`;
        this.sharedContext.recentEvents.push({
          eventId,
          eventType: "HighSeverityVulnerabilityFound",
          sourceAgent: this.type,
          data: { ...findingData, findingId: this.sharedContext.findings.length -1 },
          timestamp: new Date().toISOString()
        });
        if (this.sharedContext.recentEvents.length > 20) {
            this.sharedContext.recentEvents.shift();
        }
      }

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
    ).sort((a,b) => (a.priority ?? 100) - (b.priority ?? 100));

    if (pendingRequests.length === 0) return;
    console.log(`PBF: Found ${pendingRequests.length} pending request(s).`);

    for (const request of pendingRequests.slice(0, 1)) {
      console.log(`PBF: Processing request ${request.requestId} (${request.taskType})`);
      request.status = "in_progress";
      request.updatedAt = new Date().toISOString();

      try {
        switch (request.taskType) {
          case "analyze_file_for_vulnerabilities":
            if (!request.params.filePath || typeof request.params.filePath !== 'string') {
              throw new Error("Missing or invalid filePath parameter for analyze_file_for_vulnerabilities");
            }
            // Pass fileContent if available in params (e.g. from a workflow)
            request.result = await this.analyzeSpecificFile(
                request.params.filePath,
                this.ANALYSIS_TYPE_SPECIFIC_REQUEST,
                request.params.fileContent as string | undefined
            );
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
      const reqIndex = this.sharedContext.requests.findIndex(r => r.requestId === request.requestId);
      if (reqIndex !== -1) this.sharedContext.requests[reqIndex] = request;
    }
  }

  private getRelevantContextualAdvice(filePath: string, fileContent?: string): ContextualAdvice[] {
    if (!this.sharedContext.contextualAdvice || this.sharedContext.contextualAdvice.length === 0) {
      return [];
    }

    const advice: ContextualAdvice[] = [];

    for (const currentAdvice of this.sharedContext.contextualAdvice) {
      try {
        switch (currentAdvice.type) {
          case ContextualAdviceType.FilePath:
            const fpAdvice = currentAdvice as FilePathAdvice;
            if (fpAdvice.pathPattern.endsWith('/')) { // It's a directory/prefix pattern
              if (filePath.startsWith(fpAdvice.pathPattern)) {
                advice.push(fpAdvice);
              }
            } else { // It's an exact file path pattern
              if (filePath === fpAdvice.pathPattern) {
                advice.push(fpAdvice);
              }
            }
            break;
          case ContextualAdviceType.Regex:
            if (fileContent) {
              const rgxAdvice = currentAdvice as RegexAdvice;
              try {
                const regex = new RegExp(rgxAdvice.regexPattern, 'gm'); // global, multiline
                if (regex.test(fileContent)) {
                  advice.push(rgxAdvice);
                }
              } catch (e) {
                console.warn(`PBF: Invalid regex pattern in RegexAdvice ${rgxAdvice.adviceId}: "${rgxAdvice.regexPattern}". Error: ${(e as Error).message}`);
              }
            }
            break;
          case ContextualAdviceType.General:
            if (fileContent) {
              const genAdvice = currentAdvice as GeneralAdvice;
              if (genAdvice.keywords && genAdvice.keywords.some(kw => fileContent.toLowerCase().includes(kw.toLowerCase()))) {
                advice.push(genAdvice);
              } else if (!genAdvice.keywords) { // If no keywords, it's general advice to always consider (maybe too broad)
                // For now, only add general advice if keywords match.
              }
            }
            break;
        }
      } catch (e) {
        console.warn(`PBF: Error applying contextual advice ${currentAdvice.adviceId} to ${filePath}: ${(e as Error).message}`);
      }
    }
    // Sort by priority (descending) then by date (newest first)
    advice.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0) || new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return advice.slice(0, 5); // Return top 5 relevant advice items
  }

  private extractAndStoreSearchablePattern(llmAnalysis: string, sourceFilePath: string): void {
    const lines = llmAnalysis.split('\n');
    const patternPrefix = "SEARCHABLE_PATTERN:";
    for (const line of lines) {
      if (line.trim().startsWith(patternPrefix)) {
        const extractedPattern = line.trim().substring(patternPrefix.length).trim();
        if (extractedPattern) {
          console.log(`PBF: Extracted searchable pattern: "${extractedPattern}" from analysis of ${sourceFilePath}`);
          const newAdvice: RegexAdvice = {
            adviceId: `pbf-selfgen-${Date.now()}-${computeSha256Hash(extractedPattern).substring(0,8)}`,
            sourceAgent: this.type,
            type: ContextualAdviceType.Regex,
            regexPattern: extractedPattern, // Assuming LLM provides a valid regex string or a string to be used as literal search
            advice: `Previously identified potentially risky pattern by PBF during analysis of ${sourceFilePath}: '${extractedPattern}'. Verify if this new instance is also problematic or shares characteristics.`,
            description: `Self-generated pattern from PBF analysis of ${sourceFilePath}`,
            priority: 7, // Fairly high priority for self-discovered patterns
            createdAt: new Date().toISOString(),
          };
          if (!this.sharedContext.contextualAdvice) this.sharedContext.contextualAdvice = [];

          // Avoid adding duplicate patterns from the same source file analysis if PBF somehow outputs many
          const alreadyExists = this.sharedContext.contextualAdvice.some(
            adv => adv.type === ContextualAdviceType.Regex &&
                   (adv as RegexAdvice).regexPattern === extractedPattern &&
                   adv.description?.includes(sourceFilePath) && // simple check
                   adv.sourceAgent === this.type
          );

          if (!alreadyExists) {
            this.sharedContext.contextualAdvice.push(newAdvice);
            console.log(`PBF: Added new self-generated RegexAdvice: ${newAdvice.adviceId}`);
          } else {
            console.log(`PBF: Self-generated pattern "${extractedPattern}" from ${sourceFilePath} likely already added.`);
          }
          // Only take the first one for now to avoid too much noise from one analysis
          break;
        }
      }
    }
  }

  private async getExtendedFileContextForLLM(filePath: string, fileContent: string): Promise<{blameSummary: string, historySummary: string}> {
    let blameSummary = "";
    let historySummary = "";

    // 1. Get Blame for suspicious lines (simplified: for now, just first few lines with "UNSAFE", "TODO", "XXX")
    try {
      const maxBlameLines = this.config.maxBlameContextLinesForLLM || 2;
      const suspiciousLineNumbers: number[] = [];
      const lines = fileContent.split('\n');
      const criticalKeywords = ["UNSAFE", "reinterpret_cast", "TODO", "XXX", "DCHECK", "NOTREACHED"]; // Example keywords

      for (let i = 0; i < lines.length && suspiciousLineNumbers.length < maxBlameLines * 5; i++) { // Scan more lines initially
        if (criticalKeywords.some(kw => lines[i].toUpperCase().includes(kw))) {
          suspiciousLineNumbers.push(i + 1); // Line numbers are 1-based
        }
      }

      if (suspiciousLineNumbers.length > 0) {
        const blameInfo = await this.chromiumApi.getBlame(filePath);
        if (blameInfo && blameInfo.length > 0) {
          blameSummary = "\n\n--- Blame Information (for potentially relevant lines) ---\n";
          let addedBlameCount = 0;
          for (const lineNum of suspiciousLineNumbers) {
            if (addedBlameCount >= maxBlameLines) break;
            const lineBlame = blameInfo.find(b => b.line === lineNum);
            if (lineBlame) {
              blameSummary += `Line ${lineBlame.line} (Commit: ${lineBlame.rev.substring(0,7)}, Author: ${lineBlame.author}, Date: ${lineBlame.date}): ${lineBlame.content.trim()}\n`;
              addedBlameCount++;
            }
          }
          blameSummary += "--- End Blame Information ---\n";
        }
      }
    } catch (e) {
      console.warn(`PBF: Error getting blame info for ${filePath}: ${(e as Error).message}`);
      blameSummary = "\n\n(Could not retrieve blame information)\n";
    }

    // 2. Get File Commit History
    try {
      const maxHistoryCommits = this.config.maxFileHistoryCommitsForLLM || 3;
      const historyData = await this.chromiumApi.searchCommits({ query: `path:${filePath}`, limit: maxHistoryCommits });
      if (historyData && historyData.log && historyData.log.length > 0) {
        historySummary = "\n\n--- Recent File History ---\n";
        historyData.log.forEach(commit => {
          historySummary += `- ${commit.commit.substring(0,7)}: ${commit.message.split('\n')[0].substring(0, 70)}... (Author: ${commit.author?.email}, Date: ${commit.author?.time})\n`;
        });
        historySummary += "--- End Recent File History ---\n";
      }
    } catch (e) {
      console.warn(`PBF: Error getting file history for ${filePath}: ${(e as Error).message}`);
      historySummary = "\n\n(Could not retrieve file history)\n";
    }
    return { blameSummary, historySummary };
  }
}
