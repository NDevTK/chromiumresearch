// src/agent/agents/codebase_understanding_agent.ts
import { LLMCommunication } from '../llm_communication.js';
import { PersistentStorage } from '../persistent_storage.js';
import { ChromiumAPI, SearchResult } from '../../api.js';
import { CodebaseUnderstandingConfig } from '../../agent_config.js';
import {
    SpecializedAgent,
    SpecializedAgentType,
    SharedAgentContextType,
    ProcessedItemsHistory,
    CodebaseModuleInsight,
    AnalyzedCommitInfo,
    KeyFileWithSymbols,
    ContextualAdvice,
    ContextualAdviceType,
    FilePathAdvice,
    RegexAdvice,
    GeneralAdvice,
    SymbolInfo
} from './types.js'; // Import from new types.ts

export class CodebaseUnderstandingAgent implements SpecializedAgent {
  public type = SpecializedAgentType.CodebaseUnderstanding;
  private llmComms: LLMCommunication;
  private storage: PersistentStorage;
  private chromiumApi: ChromiumAPI;
  private isActive: boolean = false;
  private isAnalyzing: boolean = false; // To prevent concurrent cycle runs
  // private analysisIntervalId?: NodeJS.Timeout; // Not used
  private lastModuleAnalysis?: Date;
  private sharedContext!: SharedAgentContextType;
  private config: CodebaseUnderstandingConfig;
  private processedItemsHistory: ProcessedItemsHistory = {};
  private readonly ANALYSIS_TYPE_MODULE = "cua_module_analysis";

  constructor( llmComms: LLMCommunication, chromiumApi: ChromiumAPI, sharedContext: SharedAgentContextType, config: CodebaseUnderstandingConfig ) {
    this.llmComms = llmComms; this.chromiumApi = chromiumApi; this.config = config;
    this.storage = new PersistentStorage('CodebaseUnderstanding_data');
    this.setSharedContext(sharedContext); console.log("Codebase Understanding agent initialized."); this.loadState();
  }

  public setSharedContext(context: SharedAgentContextType): void {
    this.sharedContext = context;
    if(!this.sharedContext.codebaseInsights) this.sharedContext.codebaseInsights = {};
    if(!this.sharedContext.contextualAdvice) this.sharedContext.contextualAdvice = [];
  }

  private async loadState(): Promise<void> {
    const state = await this.storage.loadData<{
        lastAnalysis?: string;
        insights?: Record<string, CodebaseModuleInsight>;
        processedItemsHistory?: ProcessedItemsHistory;
        contextualAdviceCUA?: ContextualAdvice[];
    }>();
    if (state) {
      if (state.lastAnalysis) this.lastModuleAnalysis = new Date(state.lastAnalysis);
      if (state.insights) this.sharedContext.codebaseInsights = state.insights;
      this.processedItemsHistory = state.processedItemsHistory || {};

      // Load and merge contextual advice
      const loadedAdvice = state.contextualAdviceCUA || [];
      const existingAdviceIds = new Set(this.sharedContext.contextualAdvice?.map(a => a.adviceId) || []);
      loadedAdvice.forEach(advice => {
        if (!existingAdviceIds.has(advice.adviceId)) {
          this.sharedContext.contextualAdvice?.push(advice);
          existingAdviceIds.add(advice.adviceId);
        }
      });
      console.log(`CUA: Loaded ${Object.keys(this.sharedContext.codebaseInsights).length} insights, ${Object.keys(this.processedItemsHistory).length} processed modules. Loaded ${loadedAdvice.length} CUA-specific contextual advice items.`);
    }
  }

  private async saveState(): Promise<void> {
    const maxItems = this.config.maxProcessedModuleHistory || 50;
    const keys = Object.keys(this.processedItemsHistory);
    if (keys.length > maxItems) {
        const sorted = keys.sort((a,b) => new Date(this.processedItemsHistory[a].lastAnalyzed).getTime() - new Date(this.processedItemsHistory[b].lastAnalyzed).getTime());
        for(let i=0; i < keys.length - maxItems; i++) delete this.processedItemsHistory[sorted[i]];
    }

    // Filter and save only CUA-generated advice
    const cuaGeneratedAdvice = this.sharedContext.contextualAdvice?.filter(a => a.sourceAgent === this.type) || [];

    await this.storage.saveData({
        lastAnalysis: this.lastModuleAnalysis?.toISOString(),
        insights: this.sharedContext.codebaseInsights,
        processedItemsHistory: this.processedItemsHistory,
        contextualAdviceCUA: cuaGeneratedAdvice
    });
    console.log(`CUA: Saved state. CUA-specific advice items saved: ${cuaGeneratedAdvice.length}`);
  }

  public async start(): Promise<void> {
    if (this.isActive) return;
    this.isActive = true;
    this.isAnalyzing = false;
    console.log("CUA: Continuous operation started.");
    this.runContinuousModuleAnalysisLoop().catch(e => {
        console.error("CUA: ContinuousModuleAnalysisLoop encountered critical error and exited:", e);
        this.isActive = false;
    });
  }

  public async stop(): Promise<void> {
    this.isActive = false;
    console.log("CUA: Continuous operation signaled to stop.");
  }

  public async getStatus(): Promise<string> {
    let s = `CUA: ${this.isActive?'Continuous - Running':'Idle/Stopped'}. Insights: ${Object.keys(this.sharedContext.codebaseInsights).length}.`;
    s += ` ${this.isAnalyzing ? 'Processing Module.' : 'Awaiting next module/discovery.'}`;
    if(this.lastModuleAnalysis) s+=` Last Module Processed At: ${this.lastModuleAnalysis.toLocaleTimeString()}.`;
    s+=` Processed History: ${Object.keys(this.processedItemsHistory).length} modules.`;
    return s;
  }

  // private parseOwnersFileContent(content: string): string[] { // No longer needed
  //   const owners: string[] = [];
  //   const lines = content.split('\n');
  //   for (const line of lines) {
  //     const contentLine = line.replace(/^\s*\d+\s*/, '');
  //     const trimmedLine = contentLine.trim();
  //     if (trimmedLine.startsWith('#') || trimmedLine === '') continue;
  //     if (trimmedLine.startsWith('per-file')) continue;
  //     if (trimmedLine === '*') continue;
  //     if (trimmedLine.includes('@')) {
  //       owners.push(trimmedLine.split(' ')[0].split(',')[0]);
  //     } else if (trimmedLine) {
  //       if (!trimmedLine.includes(' ') && !trimmedLine.includes(':')) {
  //       }
  //     }
  //   }
  //   return owners.filter(owner => owner.includes('@'));
  // }

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
        await this.processPendingRequests();
        const moduleToAnalyze = await this.selectNextModuleToAnalyzeForContinuousRun();
        if (moduleToAnalyze) {
          workFoundThisIteration = true;
          console.log(`CUA: Selected module for analysis: ${moduleToAnalyze}`);
          await this.performSingleModuleAnalysis(moduleToAnalyze);
        }
      } catch (error) {
        console.error("CUA: Error during continuous module analysis iteration:", error);
      } finally {
        this.isAnalyzing = false;
      }

      if (!workFoundThisIteration) {
        const idleDelayMs = this.config.idleCycleDelayMsCUA || 30000;
        await new Promise(resolve => setTimeout(resolve, idleDelayMs));
      }
      await new Promise(resolve => setTimeout(resolve, this.config.interItemDelayMsCUA || 500));
    }
    console.log("CUA: Exited continuous module analysis loop because isActive is false.");
  }

  public async performSingleModuleAnalysis(modulePath: string): Promise<void> {
    console.log(`CUA: Starting analysis for specific module: ${modulePath}`);
    const historyEntry = this.processedItemsHistory[modulePath];
    if (historyEntry && historyEntry.analysisTypes.includes(this.ANALYSIS_TYPE_MODULE)) {
      const lastAnalyzedDate = new Date(historyEntry.lastAnalyzed);
      const stalenessThresholdDays = this.config.moduleInsightStalenessDays || 30;
      if ((new Date().getTime() - lastAnalyzedDate.getTime()) / (1000 * 3600 * 24) < stalenessThresholdDays) {
        console.log(`CUA: Module ${modulePath} analyzed recently (${lastAnalyzedDate.toLocaleDateString()}). Skipping deep re-analysis unless forced.`);
        this.lastModuleAnalysis = new Date();
        return;
      }
    }

    try {
      const targetModulePathClean = modulePath.endsWith('/') ? modulePath.slice(0, -1) : modulePath;
      let primaryOwners: string[] = [];
      try {
        // Use a dummy file name in the module path to get directory-level owners
        primaryOwners = await this.chromiumApi.getOwners(`${targetModulePathClean}/.dummy_file_for_module_owners`);
        console.log(`CUA: Successfully fetched ${primaryOwners.length} module owners for ${targetModulePathClean}`);
      } catch (e) {
        console.warn(`CUA: Error fetching module owners for ${targetModulePathClean}:`, (e as Error).message);
      }

      let mojoInterfaces: SearchResult[] = [];
      try {
        // Search for "interface" within the module path, then client-filter
        const rawMojoResults = await this.chromiumApi.searchCode({
          query: "interface", // Search for the keyword "interface"
          filePattern: `${targetModulePath}/`, // Search within the module directory
          limit: 30 // Fetch more initially to allow for client-side filtering
        });
        mojoInterfaces = rawMojoResults.filter(
          r => r.file.endsWith('.mojom') && r.content.includes('interface')
        ).slice(0, 10); // Apply original limit after filtering
      } catch (e) { console.error(`CUA: Error searching Mojo interfaces for ${targetModulePath}:`, e); }

      let ipcHandlers: SearchResult[] = [];
      try {
        // Search for "IPC_MESSAGE_HANDLER" within the module path, then client-filter
        const rawIpcResults = await this.chromiumApi.searchCode({
          query: "IPC_MESSAGE_HANDLER", // Search for the keyword
          filePattern: `${targetModulePath}/`, // Search within the module directory
          // language: "cpp", // This could also help narrow down server-side
          limit: 50 // Fetch more initially for client-side filtering
        });
        ipcHandlers = rawIpcResults.filter(
          r => (r.file.endsWith('.cc') || r.file.endsWith('.h') || r.file.endsWith('.cpp')) && r.content.includes('IPC_MESSAGE_HANDLER')
        ).slice(0, 10); // Apply original limit
      } catch (e) { console.error(`CUA: Error searching IPC handlers for ${targetModulePath}:`, e); }

      let recentCommitsRaw: any = { log: [] };
      try {
        recentCommitsRaw = await this.chromiumApi.searchCommits({ query: `${targetModulePath}`, limit: 5 });
      } catch (e) { console.error(`CUA: Error searching commits for ${targetModulePath}:`, e); }

      const recentCommits: AnalyzedCommitInfo[] = (recentCommitsRaw.log || []).map((commit: any) => ({
        cl: commit.commit,
        subject: commit.message.split('\n')[0],
        date: commit.author?.time,
        author: commit.author?.email,
      }));

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

Output a JSON object matching the CodebaseModuleInsight structure.
For "keyFiles", you will be given files with their paths, owners, and recent commit summaries. Your main task for keyFiles is to provide their "description" and "primaryPurpose".
Focus on:
"summary": (string) - Overall module summary.
"keyFiles": [{ "filePath": string (pre-identified), "description": string (your task), "primaryPurpose": string (your task), "owners": string[] (pre-identified), "recentCommitSummary": string[] (pre-identified) }] (Describe 3-5 key files provided in the input data)
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

      let initialKeyFiles: KeyFileWithSymbols[] = insightData.keyFiles || [];

      // Step 2: Iterate through key files to identify and enrich symbols, get owners, and history
      for (let keyFile of initialKeyFiles) {
        if (!keyFile.filePath) continue;

        // Get specific owners for the key file
        try {
          keyFile.owners = await this.chromiumApi.getOwners(keyFile.filePath);
        } catch (e) {
          console.warn(`CUA: Error fetching owners for key file ${keyFile.filePath}: ${(e as Error).message}`);
          keyFile.owners = [];
        }

        // Get recent commit history for the key file
        try {
          const historyLimit = this.config.maxCommitsForKeyFileHistoryCUA || 3;
          const historyData = await this.chromiumApi.searchCommits({ query: `path:${keyFile.filePath}`, limit: historyLimit });
          if (historyData && historyData.log && historyData.log.length > 0) {
            keyFile.recentCommitSummary = historyData.log.map(commit =>
              `${commit.commit.substring(0,7)}: ${commit.message.split('\n')[0].substring(0, 70)}... (Author: ${commit.author?.email}, Date: ${commit.author?.time})`
            );
          } else {
            keyFile.recentCommitSummary = [];
          }
        } catch (e) {
          console.warn(`CUA: Error fetching commit history for key file ${keyFile.filePath}: ${(e as Error).message}`);
          keyFile.recentCommitSummary = [];
        }

        keyFile.identifiedSymbols = keyFile.identifiedSymbols || [];

        try {
          console.log(`CUA: Identifying symbols for key file: ${keyFile.filePath}`);
          const fileData = await this.chromiumApi.getFile({ filePath: keyFile.filePath});
          if (!fileData || !fileData.content) continue;

          const symbolIdPromptSystem = "You are a code analyzer. Identify up to 2 prominent class or function definition names from the provided C++ code snippet. Output as a JSON array of strings: [\"SymbolName1\", \"SymbolName2\"]. If none, output [].";
          const symbolIdPromptUser = `Code from ${keyFile.filePath} (first 2000 chars):\n${fileData.content.substring(0, 2000)}\n\nIdentify prominent class/function definition names (max 2):`;
          let symbolNames: string[] = [];
          try {
            const llmSymbolResponse = await this.llmComms.sendMessage(symbolIdPromptUser, symbolIdPromptSystem);
            symbolNames = JSON.parse(llmSymbolResponse);
          } catch (e) {
            console.warn(`CUA: Failed to parse symbol names from LLM for ${keyFile.filePath}: ${e}`);
          }

          for (const symbolName of symbolNames.slice(0, 2)) {
            if (!symbolName || typeof symbolName !== 'string') continue;
            try {
              console.log(`CUA: Calling findSymbol for ${symbolName} in ${keyFile.filePath}`);
              const symbolDetails = await this.chromiumApi.findSymbol(symbolName, keyFile.filePath);
              let defLocation: string | undefined = undefined;
              if (symbolDetails.definition) {
                defLocation = `${symbolDetails.definition.file}:${symbolDetails.definition.line}`;
              } else if (symbolDetails.symbolResults && symbolDetails.symbolResults.length > 0) {
                defLocation = `${symbolDetails.symbolResults[0].file}:${symbolDetails.symbolResults[0].line}`;
              }
              const symbolInfo: SymbolInfo = {
                name: symbolName,
                type: symbolDetails.classResults.length > 0 ? 'class' : (symbolDetails.functionResults.length > 0 ? 'function' : 'symbol'),
                definitionLocation: defLocation,
                referenceCount: symbolDetails.estimatedUsageCount,
                description: `A symbol named ${symbolName}. Definition: ${defLocation || 'N/A'}. Estimated Usages: ${symbolDetails.estimatedUsageCount || 0}.`,
                definitionBlame: undefined // Initialize
              };

              // Get blame for the definition line
              if (defLocation) {
                try {
                  const lineNumStr = defLocation.split(':').pop();
                  if (lineNumStr) {
                    const lineNum = parseInt(lineNumStr, 10);
                    const blameData = await this.chromiumApi.getBlame(keyFile.filePath);
                    const lineBlame = blameData.find(b => b.line === lineNum);
                    if (lineBlame) {
                      symbolInfo.definitionBlame = {
                        rev: lineBlame.rev,
                        author: lineBlame.author,
                        date: lineBlame.date,
                      };
                    }
                  }
                } catch (blameError) {
                  console.warn(`CUA: Error getting blame for symbol ${symbolName} in ${keyFile.filePath} at ${defLocation}: ${(blameError as Error).message}`);
                }
              }
              keyFile.identifiedSymbols.push(symbolInfo);
            } catch (e) {
              console.warn(`CUA: Error calling findSymbol for ${symbolName} in ${keyFile.filePath}: ${(e as Error).message}`);
            }
          }
        } catch (fileError) {
          console.error(`CUA: Error processing key file ${keyFile.filePath} for symbols: ${fileError}`);
        }
      }

      const finalInsight: CodebaseModuleInsight = {
        modulePath: targetModulePathClean,
        summary: insightData.summary || "Summary not generated.",
        primaryOwners: primaryOwners,
        keyFiles: initialKeyFiles, // Now enriched with symbols
        interactionPoints: insightData.interactionPoints || [],
        keyTechnologies: insightData.keyTechnologies || [],
        commonSecurityRisks: insightData.commonSecurityRisks || [],
        recentSignificantCommits: recentCommits,
        documentationLinks: insightData.documentationLinks || [`https://source.chromium.org/chromium/chromium/src/+/main:${targetModulePath}/README.md`],
        lastAnalyzed: new Date().toISOString(),
      };

      this.sharedContext.codebaseInsights[targetModulePath] = finalInsight;
      this.processedItemsHistory[targetModulePath] = {
        lastAnalyzed: finalInsight.lastAnalyzed,
        analysisTypes: [this.ANALYSIS_TYPE_MODULE],
      };

      this.generateAndStoreContextualAdvice(finalInsight);

      this.lastModuleAnalysis = new Date();
      await this.saveState();
      console.log(`CUA: Analysis complete for module ${targetModulePath}. Insight and advice stored.`);

      this.sharedContext.findings.push({
        sourceAgent: this.type,
        type: "ModuleInsightUpdated",
        data: { modulePath: targetModulePath, summary: finalInsight.summary.substring(0,150)+"...", lastAnalyzed: finalInsight.lastAnalyzed },
        timestamp: new Date()
      });

    } catch (error) {
      console.error(`CUA: Error during module analysis cycle for ${targetModulePath}:`, error);
    } finally {
      this.isAnalyzing = false;
    }
  }

  private async selectNextModuleToAnalyzeForContinuousRun(): Promise<string | undefined> {
    const exampleModules = this.config.exampleModulesForCUA || ["components/safe_browsing/core/browser", "services/network", "content/browser/renderer_host", "components/history", "device/fido"];

    // Prefer modules not yet processed at all
    const notYetProcessed = exampleModules.filter(m => !this.processedItemsHistory[m]);
    if (notYetProcessed.length > 0) return notYetProcessed[0];

    // Fallback: find the oldest analyzed module from example list that is stale
    let oldestStaleDate = new Date();
    let oldestStaleModule: string | undefined = undefined;
    const stalenessThresholdDays = this.config.moduleInsightStalenessDays || 30;

    for (const mod of exampleModules) { // Iterate over exampleModules, not all processedItemsHistory
        const entry = this.processedItemsHistory[mod]; // entry could be undefined if not in example list but in history
        if (!entry) { // Should have been caught by notYetProcessed if in exampleModules
             // This case implies `mod` from `exampleModules` was somehow not in `processedItemsHistory`
             // which is unexpected if `notYetProcessed` was empty.
             // However, to be safe, if it's an example module and has no history, it's a candidate.
            return mod;
        }
        const analyzedDate = new Date(entry.lastAnalyzed);
        if ((new Date().getTime() - analyzedDate.getTime()) / (1000 * 3600 * 24) >= stalenessThresholdDays) {
            if (analyzedDate < oldestStaleDate) {
                oldestStaleDate = analyzedDate;
                oldestStaleModule = mod;
            }
        }
    }
    if (oldestStaleModule) return oldestStaleModule;
    return undefined;
  }

  public async processPendingRequests(): Promise<void> {
    if (!this.sharedContext || !this.sharedContext.requests) return;
    const pendingRequests = this.sharedContext.requests.filter(
      req => req.targetAgentType === this.type && req.status === "pending"
    ).sort((a,b) => (a.priority ?? 100) - (b.priority ?? 100));

    if (pendingRequests.length === 0) return;
    console.log(`CUA: Found ${pendingRequests.length} pending request(s).`);

    for (const request of pendingRequests.slice(0, 1)) {
      console.log(`CUA: Processing request ${request.requestId} (${request.taskType})`);
      request.status = "in_progress";
      request.updatedAt = new Date().toISOString();
      try {
        switch (request.taskType) {
          case "get_module_insight":
            if (!request.params.modulePath || typeof request.params.modulePath !== 'string') {
              throw new Error("Missing or invalid modulePath parameter for get_module_insight");
            }
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
    const parts = filePath.split('/');
    if (parts.length > 1) {
      parts.pop();
      if (parts.join('/').startsWith("src/")) return parts.join('/');
      if (parts.length > 2 && ["components", "services", "content", "third_party_blink"].includes(parts[0])) {
         return parts.join('/');
      }
      if (parts.length > 1) return parts.join('/');
    }
    return filePath;
  }

  // This was named getInsightForModule - renamed to avoid conflict with taskType
  public getModuleInsightFromContext(modulePathOrFilePath: string): CodebaseModuleInsight | undefined {
    // TODO: If it's a file path, derive module path first
    const modulePath = modulePathOrFilePath.includes('/') && modulePathOrFilePath.match(/\.\w+$/)
        ? this.getParentModulePath(modulePathOrFilePath)
        : modulePathOrFilePath;
    return this.sharedContext.codebaseInsights[modulePath];
  }

  public async provideContextForFile(filePath: string, codeSnippet?: string): Promise<string> {
    console.log(`CUA: Providing context for file: ${filePath}`);
    try {
      let rawFileContent = `Could not fetch raw content for ${filePath}.`;
      try {
        // HACK: Reinstate direct fetch for raw file content for LLM,
        // as getFile() by default (without range) returns line-numbered content.
        const rawFileResponse = await fetch(`https://chromium.googlesource.com/chromium/src/+/main/${filePath}?format=TEXT`);
        if (rawFileResponse.ok) {
            const base64Content = await rawFileResponse.text();
            rawFileContent = Buffer.from(base64Content, 'base64').toString('utf-8');
        } else {
          console.warn(`CUA: Failed to fetch raw content for ${filePath} via direct fetch. Status: ${rawFileResponse.status}`);
        }
      } catch (fetchError) {
        console.error(`CUA: Error during direct fetch for raw content of ${filePath}:`, fetchError);
      }

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
      const userPrompt = `${contextPrompt}File Content (first 4000 chars):\n\`\`\`\n${rawFileContent.substring(0, 4000)}\n\`\`\`\n\nSummarize the file's role and key aspects:`;

      const llmSummary = await this.llmComms.sendMessage(userPrompt, systemPrompt);
      return llmSummary;

    } catch (error) {
      console.error(`CUA: Error providing context for file ${filePath}:`, error);
      return `Sorry, I encountered an error trying to get context for ${filePath}: ${(error as Error).message}`;
    }
  }

  private generateAndStoreContextualAdvice(insight: CodebaseModuleInsight): void {
    if (!this.sharedContext.contextualAdvice) {
      this.sharedContext.contextualAdvice = [];
    }

    // 1. FilePathAdvice for the module path
    const moduleAdvice: FilePathAdvice = {
      adviceId: `cua-fp-${insight.modulePath}-${Date.now()}`,
      sourceAgent: this.type,
      type: ContextualAdviceType.FilePath,
      pathPattern: insight.modulePath,
      advice: `This module (${insight.modulePath}) deals with: ${insight.summary.substring(0, 100)}... Key technologies: ${(insight.keyTechnologies || []).join(', ')}. Common risks: ${(insight.commonSecurityRisks || []).join(', ')}.`,
      priority: 7,
      createdAt: new Date().toISOString(),
    };
    this.sharedContext.contextualAdvice.push(moduleAdvice);

    // 2. RegexAdvice or GeneralAdvice from key technologies or common security risks
    (insight.keyTechnologies || []).forEach(tech => {
      let regexPattern: string | undefined;
      let generalAdvice: string | undefined;
      const adviceBase = `Module ${insight.modulePath} uses ${tech}.`;

      if (tech.toLowerCase().includes("mojo")) {
        regexPattern = `(\\w+)::\\w*MojomTraits`; // Example regex for Mojo traits
        generalAdvice = `${adviceBase} Pay attention to Mojo interface definitions (*.mojom files), message validation, and data serialization/deserialization. Look for potential issues in StructTraits or TypeConverter implementations.`;
      } else if (tech.toLowerCase().includes("ipc")) {
        regexPattern = `IPC_MESSAGE_HANDLER[_CONTENTS*]?\\s*\\(`; // Example regex for IPC message handlers
        generalAdvice = `${adviceBase} Scrutinize IPC message handlers (IPC_MESSAGE_HANDLER) for proper validation of untrusted data from other processes. Check for integer overflows, out-of-bounds accesses, and correct message routing.`;
      }

      if (regexPattern) {
        const advice: RegexAdvice = {
          adviceId: `cua-rgx-${insight.modulePath}-${tech}-${Date.now()}`,
          sourceAgent: this.type,
          type: ContextualAdviceType.Regex,
          regexPattern: regexPattern,
          advice: generalAdvice || `${adviceBase} When you see code matching '${regexPattern}', consider related security implications of ${tech}.`,
          description: `Regex for ${tech} usage in ${insight.modulePath}`,
          priority: 6,
          createdAt: new Date().toISOString(),
        };
        this.sharedContext.contextualAdvice.push(advice);
      } else if (generalAdvice) {
        const advice: GeneralAdvice = {
          adviceId: `cua-gen-${insight.modulePath}-${tech}-${Date.now()}`,
          sourceAgent: this.type,
          type: ContextualAdviceType.General,
          advice: generalAdvice,
          keywords: [tech.toLowerCase(), insight.modulePath],
          description: `General advice for ${tech} in ${insight.modulePath}`,
          priority: 5,
          createdAt: new Date().toISOString(),
        };
        this.sharedContext.contextualAdvice.push(advice);
      }
    });

    (insight.commonSecurityRisks || []).forEach(risk => {
      const advice: GeneralAdvice = {
        adviceId: `cua-risk-${insight.modulePath}-${risk.substring(0,10)}-${Date.now()}`,
        sourceAgent: this.type,
        type: ContextualAdviceType.General,
        advice: `Module ${insight.modulePath} has a common security risk: ${risk}. Be vigilant for patterns related to this risk when reviewing code in this module.`,
        keywords: [risk.toLowerCase().replace(/\s+/g, '_'), insight.modulePath],
        description: `Security risk: ${risk} in ${insight.modulePath}`,
        priority: 8, // Higher priority for identified risks
        createdAt: new Date().toISOString(),
      };
      this.sharedContext.contextualAdvice.push(advice);
    });

    // 3. Advice from Key Symbols with Blame
    insight.keyFiles.forEach(keyFile => {
      (keyFile.identifiedSymbols || []).forEach(symbol => {
        if (symbol.definitionBlame && symbol.definitionLocation) {
          const blame = symbol.definitionBlame;
          const adviceText = `In ${keyFile.filePath}, symbol '${symbol.name}' (defined around line ${symbol.definitionLocation.split(':').pop()}) was last modified by commit ${blame.rev.substring(0,7)} (Author: ${blame.author}, Date: ${blame.date}). This context might be relevant when reviewing its usage or implementation. Original definition line: ${symbol.description?.split('Definition: ')[1]?.split('.')[0]}`;

          const symbolAdvice: GeneralAdvice = {
            adviceId: `cua-symblame-${symbol.name}-${keyFile.filePath.replace(/[\/\.]/g, '-')}-${Date.now()}`,
            sourceAgent: this.type,
            type: ContextualAdviceType.General,
            advice: adviceText,
            keywords: [symbol.name, keyFile.filePath.split('/').pop() || keyFile.filePath],
            description: `Blame context for symbol ${symbol.name} in ${keyFile.filePath}`,
            priority: 4, // Lower priority than module-level risks, but still useful context
            createdAt: new Date().toISOString(),
          };
          this.sharedContext.contextualAdvice.push(symbolAdvice);
        }
      });
    });


    // Clean up old advice from this agent to prevent unbounded growth
    // Keep only the latest N pieces of advice from CUA
    const maxCuaAdvice = this.config.maxContextualAdviceItemsPerAgentCUA || 20; // Default was 50, let's use the config value or a fallback.

    // 4. Module-level advice from commit history analysis
    if (insight.recentSignificantCommits && insight.recentSignificantCommits.length > 0) {
        const pathFrequency: Record<string, number> = {};
        const themeKeywords = ["refactor", "fix", "bug", "deprecate", "add", "new", "performance", "security", "cleanup", "update"];
        const themeFrequency: Record<string, number> = {};

        insight.recentSignificantCommits.forEach(commit => {
            // Path churn (simplified: look at first path segment within module)
            (commit.keyFilesChanged || []).forEach(filePath => {
                if (filePath.startsWith(insight.modulePath)) {
                    const relativePath = filePath.substring(insight.modulePath.length).split('/').filter(p => p);
                    if (relativePath.length > 0) {
                        const subPath = insight.modulePath + (insight.modulePath.endsWith('/') ? '' : '/') + relativePath[0];
                        pathFrequency[subPath] = (pathFrequency[subPath] || 0) + 1;
                    }
                }
            });
            // Theme keywords
            themeKeywords.forEach(theme => {
                if (commit.subject.toLowerCase().includes(theme)) {
                    themeFrequency[theme] = (themeFrequency[theme] || 0) + 1;
                }
            });
        });

        const sortedPaths = Object.entries(pathFrequency).sort((a,b) => b[1] - a[1]);
        if (sortedPaths.length > 0 && sortedPaths[0][1] > 1) { // Only if a path mentioned more than once
            const topPaths = sortedPaths.slice(0, 2).map(p => p[0]);
            const pathChurnAdvice: GeneralAdvice = {
                adviceId: `cua-churn-${insight.modulePath.replace(/[\/\.]/g, '-')}-${Date.now()}`,
                sourceAgent: this.type, type: ContextualAdviceType.General,
                advice: `Module ${insight.modulePath} has seen recent commit activity concentrated in sub-paths like: ${topPaths.join(', ')}. Consider these areas for focused review.`,
                keywords: [insight.modulePath, ...topPaths],
                description: `Path churn analysis for ${insight.modulePath}`, priority: 5, createdAt: new Date().toISOString(),
            };
            this.sharedContext.contextualAdvice.push(pathChurnAdvice);
        }

        const sortedThemes = Object.entries(themeFrequency).sort((a,b) => b[1] - a[1]);
        if (sortedThemes.length > 0 && sortedThemes[0][1] > 1) {
            const topThemes = sortedThemes.slice(0, 2).map(t => t[0]);
            const themeAdvice: GeneralAdvice = {
                adviceId: `cua-themes-${insight.modulePath.replace(/[\/\.]/g, '-')}-${Date.now()}`,
                sourceAgent: this.type, type: ContextualAdviceType.General,
                advice: `Recent commit themes for module ${insight.modulePath} include: '${topThemes.join("', '")}'. This might indicate ongoing work in these areas.`,
                keywords: [insight.modulePath, ...topThemes],
                description: `Commit theme analysis for ${insight.modulePath}`, priority: 4, createdAt: new Date().toISOString(),
            };
            this.sharedContext.contextualAdvice.push(themeAdvice);
        }
    }

    const cuaAdviceEntries = this.sharedContext.contextualAdvice.filter(a => a.sourceAgent === this.type);
    if (cuaAdviceEntries.length > maxCuaAdvice) {
        cuaAdviceEntries.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()); // Sort newest first
        const adviceToRemove = cuaAdviceEntries.slice(maxCuaAdvice).map(a => a.adviceId);
        this.sharedContext.contextualAdvice = this.sharedContext.contextualAdvice.filter(a => !adviceToRemove.includes(a.adviceId));
    }

    console.log(`CUA: Generated ${this.sharedContext.contextualAdvice.filter(a => a.sourceAgent === this.type).length} contextual advice items for module ${insight.modulePath}.`);
  }
}
