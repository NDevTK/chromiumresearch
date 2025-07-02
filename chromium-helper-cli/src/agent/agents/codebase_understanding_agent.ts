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
    CodebaseModuleInsight, // For type hints
    AnalyzedCommitInfo,    // For type hints
    KeyFileWithSymbols     // For type hints
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

  private parseOwnersFileContent(content: string): string[] {
    const owners: string[] = [];
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmedLine = line.trim();
      if (trimmedLine.startsWith('#') || trimmedLine === '') continue;
      if (trimmedLine.startsWith('per-file')) continue;
      if (trimmedLine === '*') continue;
      if (trimmedLine.includes('@')) {
        owners.push(trimmedLine.split(' ')[0]);
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
      const targetModulePath = modulePath;
      let primaryOwners: string[] = [];
      try {
          const rawOwnersContentResponse = await fetch(`https://chromium.googlesource.com/chromium/src/+/main/${ownersResults[0].file}?format=TEXT`);
          if (rawOwnersContentResponse.ok) {
            const base64Content = await rawOwnersContentResponse.text();
            const rawOwnersContent = Buffer.from(base64Content, 'base64').toString('utf-8');
            primaryOwners = this.parseOwnersFileContent(rawOwnersContent);
          } else {
            console.warn(`CUA: Failed to fetch raw OWNERS content for ${ownersResults[0].file} via direct fetch.`);
          }
      } catch (e) { console.error(`CUA: Error fetching or parsing OWNERS for ${targetModulePath}:`, e); }

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

      let initialKeyFiles: KeyFileWithSymbols[] = insightData.keyFiles || [];

      // Step 2: Iterate through key files to identify and enrich symbols
      for (let keyFile of initialKeyFiles) {
        if (!keyFile.filePath) continue;
        keyFile.identifiedSymbols = keyFile.identifiedSymbols || []; // Ensure array exists

        try {
          console.log(`CUA: Identifying symbols for key file: ${keyFile.filePath}`);
          const fileData = await this.chromiumApi.getFile({ filePath: keyFile.filePath});
          if (!fileData || !fileData.content) continue;

          // Step 3a: LLM call or Regex to identify 1-2 prominent symbols in this file's content
          // For simplicity, let's assume an LLM call. This could be slow.
          // A regex for `class Foo` or `void Bar()` could be a faster first pass.
          const symbolIdPromptSystem = "You are a code analyzer. Identify up to 2 prominent class or function definition names from the provided C++ code snippet. Output as a JSON array of strings: [\"SymbolName1\", \"SymbolName2\"]. If none, output [].";
          const symbolIdPromptUser = `Code from ${keyFile.filePath} (first 2000 chars):\n${fileData.content.substring(0, 2000)}\n\nIdentify prominent class/function definition names (max 2):`;
          let symbolNames: string[] = [];
          try {
            const llmSymbolResponse = await this.llmComms.sendMessage(symbolIdPromptUser, symbolIdPromptSystem);
            symbolNames = JSON.parse(llmSymbolResponse);
          } catch (e) {
            console.warn(`CUA: Failed to parse symbol names from LLM for ${keyFile.filePath}: ${e}`);
          }

          // Step 3b & 3c: For each identified symbol, call findSymbol and populate SymbolInfo
          for (const symbolName of symbolNames.slice(0, 2)) { // Limit to 2 symbols per file
            if (!symbolName || typeof symbolName !== 'string') continue;
            try {
              console.log(`CUA: Calling findSymbol for ${symbolName} in ${keyFile.filePath}`);
              const symbolDetails = await this.chromiumApi.findSymbol(symbolName, keyFile.filePath);

              let defLocation: string | undefined = undefined;
              if (symbolDetails.definition) {
                defLocation = `${symbolDetails.definition.file}:${symbolDetails.definition.line}`;
              } else if (symbolDetails.symbolResults && symbolDetails.symbolResults.length > 0) {
                // Fallback to first symbolResult if direct definition not found
                defLocation = `${symbolDetails.symbolResults[0].file}:${symbolDetails.symbolResults[0].line}`;
              }


              const symbolInfo: SymbolInfo = {
                name: symbolName,
                type: symbolDetails.classResults.length > 0 ? 'class' : (symbolDetails.functionResults.length > 0 ? 'function' : 'symbol'),
                definitionLocation: defLocation,
                referenceCount: symbolDetails.estimatedUsageCount,
                // Description could be a summary of findSymbol results or another LLM call if needed
                description: `A symbol named ${symbolName}. Definition: ${defLocation || 'N/A'}. Estimated Usages: ${symbolDetails.estimatedUsageCount || 0}.`
              };
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
        modulePath: targetModulePath,
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

      this.lastModuleAnalysis = new Date();
      await this.saveState();
      console.log(`CUA: Analysis complete for module ${targetModulePath}. Insight stored.`);

      this.sharedContext.findings.push({
        sourceAgent: this.type,
        type: "ModuleInsightUpdated",
        data: { modulePath: targetModulePath, summary: newInsight.summary.substring(0,150)+"...", lastAnalyzed: newInsight.lastAnalyzed },
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
}
