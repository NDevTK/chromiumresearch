// Contains the main LLM researcher logic
import { LLMCommunication, LLMConfig, LLMProviderType } from './llm_communication.js';
import { PersistentStorage } from './persistent_storage.js';
import {
  SpecializedAgent,
  ProactiveBugFinder,
  BugPatternAnalysisAgent,
  CodebaseUnderstandingAgent,
  GenericTaskAgent,
  GenericTaskAgentConfig,
  SpecializedAgentType
} from './specialized_agents.js';
import { ChromiumAPI } from '../api.js';
import { loadConfig as loadChromiumHelperConfig, CHConfig } from '../config.js';
import { AgentConfig, loadAgentConfig } from '../agent_config.js';


export class LLMResearcher {
  private agentConfig!: AgentConfig; // To be loaded async
  private llmComms: LLMCommunication;
  private storage: PersistentStorage;
  private specializedAgents: Map<SpecializedAgentType, SpecializedAgent>;
  private chromiumApi!: ChromiumAPI; // Definite assignment assertion, will be set in async constructor/init
  private sharedAgentContext: SharedAgentContextType; // Use the specific type here

  // Private constructor to force initialization via static async method
  private constructor(agentConfig: AgentConfig) { // Accept agentConfig here
    this.agentConfig = agentConfig; // Store it
    // Initialize LLM communication and storage synchronously
    // LLMConfig now comes from agentConfig
    const llmApiConfig: LLMConfig = {
      provider: LLMProviderType.Ollama, // TODO: Make provider configurable if supporting OpenAI too
      baseUrl: this.agentConfig.llm.ollamaBaseUrl,
      model: this.agentConfig.llm.ollamaModel,
      temperature: this.agentConfig.llm.defaultTemperature,
      maxTokens: this.agentConfig.llm.defaultMaxTokens,
      // apiKey: process.env.OPENAI_API_KEY, // Only if using OpenAI & configured
    };
    this.llmComms = new LLMCommunication(llmApiConfig, this.agentConfig.llm.cacheMaxSize); // Pass cache size
    this.storage = new PersistentStorage('LLMResearcher_main');
    this.specializedAgents = new Map();
    // Initialize with the correct type
    this.sharedAgentContext = {
      findings: [],
      requests: [],
      knownBugPatterns: [],
      codebaseInsights: {},
    };
    // Note: chromiumApi is not initialized here yet.
  }

  public static async create(): Promise<LLMResearcher> {
    const agentConfig = await loadAgentConfig(); // Load config first
    const researcher = new LLMResearcher(agentConfig); // Pass it to constructor
    await researcher.initializeAsyncComponents();
    return researcher;
  }

  private async initializeAsyncComponents(): Promise<void> {
    // Note: agentConfig is already loaded and available via this.agentConfig
    try {
      const chHelperConfig = await loadChromiumHelperConfig(); // Main CLI config for API keys etc.
      this.chromiumApi = new ChromiumAPI(chHelperConfig.apiKey);
      this.chromiumApi.setDebugMode(process.env.CH_AGENT_DEBUG === 'true');
      console.log("ChromiumAPI initialized for LLMResearcher.");

      // Now that chromiumApi is initialized, we can create specialized agents that depend on it.
      this.initializeSpecializedAgents();
      this.initializeWorkflows(); // Initialize/register workflows
      await this.loadResearcherData(); // Load persistent data
      console.log("LLM Researcher fully initialized.");

    } catch (error) {
      console.error("Failed to initialize LLMResearcher's async components:", error);
      // Decide how to handle this - throw, or operate in a degraded mode?
      // For now, if ChromiumAPI fails, many features will be broken.
      throw new Error("LLMResearcher async initialization failed.");
    }
  }

  private initializeWorkflows(): void {
    // --- Define "Basic CL Audit" Workflow ---
    const basicClAuditWorkflow: WorkflowDefinition = {
      id: "basic-cl-audit",
      description: "Performs a basic audit of a Chromium CL: fetches CL info, changed files, and asks LLM for a quick security review of the diffs.",
      steps: [
        {
          name: "Fetch CL Status",
          description: "Fetches basic information and status for the given CL.",
          requiredParams: ["clNumber"],
          action: async (params) => {
            const clStatus = await this.chromiumApi.getGerritCLStatus(params.clNumber);
            // Return as JSON string; this allows the workflow runner to merge these outputs
            // into the 'mergedParams' object for subsequent steps if the output is a valid JSON object.
            return JSON.stringify({
              clSubject: clStatus.subject,
              clStatus: clStatus.status,
              clOwner: clStatus.owner.email,
              clUpdated: clStatus.updated,
              clLink: `https://chromium-review.googlesource.com/c/${params.clNumber}`
            });
          }
        },
        {
          name: "Fetch CL Diff",
          description: "Fetches the diff for the CL.",
          requiredParams: ["clNumber"],
          action: async (params) => {
            const diffData = await this.chromiumApi.getGerritCLDiff({ clNumber: params.clNumber });
            // For simplicity, just summarize file changes. A real workflow might iterate per file.
            const changedFiles = Object.keys(diffData.filesData || {}).join(', ');
            // Store the full diff data in mergedParams for the next step.
            // The return string is a summary for the report.
            return JSON.stringify({ changedFilesSummary: `Files changed: ${changedFiles}`, clDiffData: diffData.filesData });
          }
        },
        {
            name: "LLM Security Review of Diff",
            description: "Asks the LLM to perform a brief security review of the code changes.",
            requiredParams: ["clSubject", "clDiffData"],
            action: async (params) => {
                let diffSummaryForLlm = `Review CL: "${params.clSubject}".\n`;
                let fileCount = 0;
                for (const filePath in params.clDiffData) {
                    if (fileCount < 3) { // Limit to 3 files for this basic review to keep it short
                        const fileDiff = params.clDiffData[filePath];
                        if (fileDiff.content) {
                             // Only take 'b' (added/modified lines) for brevity, and limit length
                            const addedOrModifiedLines = fileDiff.content
                                .filter((line: any) => line.b && !line.a) // lines added or where only 'b' exists (new content)
                                .map((line: any) => line.b)
                                .join('\n');
                            if (addedOrModifiedLines.length > 0) {
                                diffSummaryForLlm += `--- File: ${filePath} ---\n${addedOrModifiedLines.substring(0, 1000)}\n...\n`;
                                fileCount++;
                            }
                        }
                    } else {
                        diffSummaryForLlm += `... and more files.\n`;
                        break;
                    }
                }
                if (!fileCount) return "No textual diff content found to review.";

                let knownPatternsContext = "";
                if (this.sharedAgentContext.knownBugPatterns && this.sharedAgentContext.knownBugPatterns.length > 0) {
                    knownPatternsContext = "\n\nConsider these known bug patterns during your review (summarized):\n";
                    this.sharedAgentContext.knownBugPatterns.slice(0, 5).forEach((p: any) => { // Show top 5
                        const patternDetail = (typeof p === 'string') ? p : `${p.name}: ${p.description.substring(0,100)}... (Severity: ${p.severity || 'N/A'})`;
                        knownPatternsContext += `- ${patternDetail}\n`;
                    });
                }

                const llmPrompt = `Perform a brief security review of the following code changes from a Chromium CL. Focus on common C++ pitfalls, IPC issues, or web security concerns. ${knownPatternsContext}\nBe concise. \n\n${diffSummaryForLlm}`;
                const review = await this.llmComms.sendMessage(llmPrompt, "You are a Chromium security reviewer AI.");
                return review;
            }
        }
      ],
      defaultParams: {}
    };
    this.registerWorkflow(basicClAuditWorkflow);

    // --- Define "Targeted File Audit" Workflow ---
    const targetedFileAuditWorkflow: WorkflowDefinition = {
      id: "targeted-file-audit",
      description: "Performs a detailed security analysis of a specific file: gathers context, scans for vulnerabilities, checks against known patterns, and synthesizes a report.",
      steps: [
        {
          name: "Fetch File Content & Initial Context",
          description: "Fetches file content and gets module/file context using CodebaseUnderstandingAgent.",
          requiredParams: ["filePath"],
          action: async (params) => {
            const filePath = params.filePath;
            const cuAgent = this.specializedAgents.get(SpecializedAgentType.CodebaseUnderstanding) as CodebaseUnderstandingAgent | undefined;
            let contextSummary = `Analysis for file: ${filePath}\n`;
            let fileContent = "";

            try {
              const fileData = await this.chromiumApi.getFile({ filePath });
              fileContent = fileData.content;
              contextSummary += `File Content (first 500 chars):\n${fileContent.substring(0, 500)}...\n\n`;
            } catch (e) {
              return JSON.stringify({ error: `Failed to fetch file ${filePath}: ${(e as Error).message}`, fileContent: "", moduleContext: "" });
            }

            if (cuAgent) {
              const insight = await cuAgent.provideContextForFile(filePath); // This returns a string from LLM
              contextSummary += `Codebase Context:\n${insight}\n`;
              return JSON.stringify({ fileContent, moduleContext: insight, reportSection_Context: contextSummary});
            } else {
              contextSummary += "CodebaseUnderstandingAgent not available for deeper context.\n";
              return JSON.stringify({ fileContent, moduleContext: "N/A", reportSection_Context: contextSummary });
            }
          }
        },
        {
          name: "Proactive Vulnerability Scan",
          description: "Analyzes the file content for potential vulnerabilities using ProactiveBugFinder logic and LLM, informed by context.",
          requiredParams: ["filePath", "fileContent", "moduleContext"],
          action: async (params) => {
            const pbfAgent = this.specializedAgents.get(SpecializedAgentType.ProactiveBugFinding) as ProactiveBugFinder | undefined;
            let scanResults = "";
            if (pbfAgent) {
              // The existing analyzeSpecificFile fetches content again.
              // TODO: Optimization: Modify analyzeSpecificFile to optionally accept fileContent to avoid re-fetch.
              scanResults = await pbfAgent.analyzeSpecificFile(params.filePath);
            } else {
              // Fallback to direct LLM call if PBF agent not available
              console.warn("Targeted File Audit: ProactiveBugFinder agent not available, using direct LLM call for scan.");
              const systemPrompt = "You are a security code auditor. Analyze the provided code from a Chromium file, considering its module context, for potential security vulnerabilities. Focus on common C++ pitfalls, IPC issues, or web security concerns. Be concise.";
              // Ensure moduleContext is a string for the prompt. It might be an object if not handled carefully by previous step's stringify.
              const contextString = typeof params.moduleContext === 'string' ? params.moduleContext : JSON.stringify(params.moduleContext);
              const analysisPrompt = `File: ${params.filePath}\nModule Context:\n${contextString}\n\nCode (first 4000 chars):\n${params.fileContent.substring(0,4000)}\n\nIdentify potential vulnerabilities or areas needing closer inspection:`;
              scanResults = await this.llmComms.sendMessage(analysisPrompt, systemPrompt);
            }
            return JSON.stringify({ potentialVulnerabilities: scanResults, reportSection_Scan: `Vulnerability Scan Results:\n${scanResults}\n` });
          }
        },
        {
          name: "Pattern Matching",
          description: "Checks identified issues against known bug patterns using BugPatternAnalysisAgent.",
          requiredParams: ["potentialVulnerabilities"], // Takes the text output from previous step
          action: async (params) => {
            const bpaAgent = this.specializedAgents.get(SpecializedAgentType.BugPatternAnalysis) as BugPatternAnalysisAgent | undefined;
            let patternMatches = "BugPatternAnalysisAgent not available or no specific patterns matched.";
            if (bpaAgent && params.potentialVulnerabilities) {
              // Use getContextualAdvice with the summary of potential vulnerabilities
              patternMatches = await bpaAgent.getContextualAdvice(params.potentialVulnerabilities.substring(0, 2000)); // Send a snippet of the vulnerabilities found
            }
            return JSON.stringify({ matchedPatterns: patternMatches, reportSection_Patterns: `Pattern Matching Results:\n${patternMatches}\n` });
          }
        },
        {
          name: "Synthesize Report",
          description: "Combines all findings into a comprehensive security report for the file.",
          requiredParams: ["filePath", "reportSection_Context", "reportSection_Scan", "reportSection_Patterns"],
          action: async (params) => {
            const synthesisPrompt = `
Synthesize a security report for the Chromium file: ${params.filePath}
Based on the following sections:

1. Context and File Overview:
${params.reportSection_Context}

2. Vulnerability Scan Details:
${params.reportSection_Scan}

3. Known Pattern Matches:
${params.reportSection_Patterns}

Provide a final summary and overall assessment.
If specific vulnerabilities were found, list them clearly.
If no major issues, state that, but mention any minor concerns or areas for attention.
Be factual and concise.
`;
            const finalReport = await this.llmComms.sendMessage(synthesisPrompt, "You are an AI security analyst compiling a report.");
            return finalReport; // This is the final output of the workflow
          }
        }
      ],
      defaultParams: {}
    };
    this.registerWorkflow(targetedFileAuditWorkflow);

    // TODO: Define more workflows like "New API Security Check"
    console.log("Workflows initialized.");
  }

  private initializeSpecializedAgents(): void {
    if (!this.chromiumApi) {
      console.warn("ChromiumAPI not initialized. Skipping specialized agent creation that depend on it.");
      return;
    }
    if (!this.agentConfig) {
      console.error("AgentConfig not loaded. Cannot initialize specialized agents.");
      throw new Error("AgentConfig not available during specialized agent initialization.");
    }

    // Pass necessary dependencies to agents, including the shared context and their specific configs
    const bugFinder = new ProactiveBugFinder(
      this.llmComms,
      this.chromiumApi,
      this.sharedAgentContext,
      this.agentConfig.proactiveBugFinder
    );
    this.specializedAgents.set(SpecializedAgentType.ProactiveBugFinding, bugFinder);

    const patternAnalyzer = new BugPatternAnalysisAgent(
      this.llmComms,
      this.chromiumApi,
      this.sharedAgentContext,
      this.agentConfig.bugPatternAnalysis
    );
    this.specializedAgents.set(SpecializedAgentType.BugPatternAnalysis, patternAnalyzer);

    const codebaseUnderstander = new CodebaseUnderstandingAgent(
      this.llmComms,
      this.chromiumApi,
      this.sharedAgentContext,
      this.agentConfig.codebaseUnderstanding
    );
    this.specializedAgents.set(SpecializedAgentType.CodebaseUnderstanding, codebaseUnderstander);

    console.log("Specialized agents (ProactiveBugFinder, BugPatternAnalysisAgent, CodebaseUnderstandingAgent) initialized with shared context and agent configurations.");

    // Optionally, auto-start some agents
    // bugFinder.start();
  }

  private async loadResearcherData(): Promise<void> {
    const data = await this.storage.loadData<{ lastQuery?: string }>();
    if (data) {
      console.log("LLMResearcher: Loaded data - ", data);
      // Example: Restore some state from 'data'
      if (data.lastQuery) {
        // console.log("Last query was:", data.lastQuery);
      }
    }
  }

  private async saveResearcherData(dataToSave: object): Promise<void> {
    await this.storage.saveData(dataToSave);
    console.log("LLMResearcher: Data saved.");
  }

  // private initializeSpecializedAgents(): void {
  //   const bugFinder = new ProactiveBugFinder(/* pass chromiumApi, llmComms */);
  //   this.specializedAgents.set(SpecializedAgentType.ProactiveBugFinding, bugFinder);
  //   // TODO: Initialize other agents (BugPatternAnalysis, CodebaseUnderstanding)
  //   // TODO: Start agents (e.g., bugFinder.start())
  //   console.log("Specialized agents initialized (placeholder).");
  // }

  public async processQuery(query: string, conversationHistory: string[] = []): Promise<string> {
    console.log(`Researcher processing query: ${query}`);

    // Basic conversation history (can be improved)
    // const historyContext = conversationHistory.join("\n");
    const systemPrompt = `You are a lead AI security researcher for Chromium. Your goal is to assist the user in finding vulnerabilities and understanding the codebase.
You have access to specialized AI agents:
- ProactiveBugFinder: Actively searches for bugs.
- BugPatternAnalysis: Learns from past bugs to identify risky patterns.
- CodebaseUnderstanding: Builds knowledge about how Chromium code works.
Be concise and helpful. You can use tools by prefixing commands with '!' (e.g., !search query, !start-agent ProactiveBugFinding).
The user is interacting with you via a CLI chatbot.`;

    let enrichedQuery = query;
    let agentContributions = "";

    // --- Attempt to leverage specialized agents ---

    // 1. Leverage BugPatternAnalysisAgent's knowledge from shared context
    if (this.sharedAgentContext.knownBugPatterns && this.sharedAgentContext.knownBugPatterns.length > 0) {
      // Provide a summary of a few patterns if query seems relevant
      if (query.toLowerCase().includes("pattern") || query.toLowerCase().includes("vulnerability type")) {
        const patternSample = this.sharedAgentContext.knownBugPatterns.slice(0, 3).map((p: any) => p.description || p).join("\n - ");
        agentContributions += `\n[Context from BugPatternAnalysis]:\nRecent Bug Patterns:\n - ${patternSample}\n`;
      }
    }
    // If user asks for advice on a code snippet, we'd ideally extract the snippet and use bpaAgent.getContextualAdvice(snippet)
    // This part of specific invocation can remain or be enhanced.

    // 2. Leverage CodebaseUnderstandingAgent's knowledge from shared context
    const fileUnderstandQueryMatch = query.match(/(?:understand|info on|context for) (?:file|path|module) ([\w\/.-]+)/i);
    if (fileUnderstandQueryMatch && fileUnderstandQueryMatch[1]) {
      const filePathOrModule = fileUnderstandQueryMatch[1];
      const insightsContext = this.sharedAgentContext.codebaseInsights; // No cast needed now

      let insight = insightsContext[filePathOrModule];
      if (!insight) {
        const parentKey = Object.keys(insightsContext).find(k => filePathOrModule.startsWith(k + '/'));
        if (parentKey) insight = insightsContext[parentKey];
      }

      if (insight) {
        let insightSummary = `\n[Context from CodebaseUnderstanding for ${insight.modulePath}]:\nSummary: ${insight.summary.substring(0, 300)}...\n`;
        if (insight.keyFiles && insight.keyFiles.length > 0) {
          insightSummary += `Key Files: ${insight.keyFiles.slice(0,2).map(f => f.filePath).join(', ')}...\n`;
        }
        if (insight.commonSecurityRisks && insight.commonSecurityRisks.length > 0) {
          insightSummary += `Common Risks: ${insight.commonSecurityRisks.slice(0,2).join(', ')}...\n`;
        }
        agentContributions += insightSummary;
      } else {
        agentContributions += `\n[CodebaseUnderstanding]: No immediate detailed insight for ${filePathOrModule} in shared context. You can try tasking the agent to analyze it.\n`;
      }
    }

    // 3. Include recent findings if query is general (e.g., "any new findings?", "latest security alerts")
    if (query.toLowerCase().includes("latest findings") || query.toLowerCase().includes("new vulnerabilities") || query.toLowerCase().includes("security status")) {
        if (this.sharedAgentContext.findings && this.sharedAgentContext.findings.length > 0) {
            agentContributions += "\n[Recent Agent Findings]:\n";
            // Show last 2-3 findings
            this.sharedAgentContext.findings.slice(-3).forEach(finding => {
                agentContributions += `- ${finding.sourceAgent} (${finding.type}): ${JSON.stringify(finding.data).substring(0,150)}...\n`;
            });
        }
    }


    // Add agent contributions to the main query for the LLM, if any
    if (agentContributions) {
      enrichedQuery = `${query}\n\nRelevant information from active agents and shared context:\n${agentContributions}`;
      console.log("LLMResearcher: Enriched query with agent contributions from shared context.");
    }

    try {
      const llmResponse = await this.llmComms.sendMessage(enrichedQuery, systemPrompt);

      await this.saveResearcherData({ lastQuery: query, lastResponseTimestamp: new Date().toISOString(), enrichedQueryProvided: !!agentContributions });

      // TODO: Post-process LLM response, potentially trigger tools or other agents based on response.
      // For example, if LLM suggests analyzing a file, it could auto-task ProactiveBugFinder.

    // Log recent findings from shared context for debugging/visibility
    if (this.sharedAgentContext.findings.length > 0) {
        // console.log(`LLMResearcher: Recent findings in shared context: ${JSON.stringify(this.sharedAgentContext.findings.slice(-3))}`);
    }

      return llmResponse;
    } catch (error) {
      console.error("Error processing query in LLMResearcher:", error);
      return "Sorry, I encountered an error trying to process your request.";
    }
  }

  public async invokeTool(toolCommand: string): Promise<string> {
    // Example: !search some_function_name
    // Example: !file src/main.c --lines 10-20
    console.log(`Researcher attempting to invoke tool: ${toolCommand}`);

    const [command, ...args] = toolCommand.split(' ');
    const commandName = command.startsWith('!') ? command.substring(1) : command;

    // TODO: Integrate properly with chromium-helper-cli's command execution
    // This is a very simplified placeholder.
    // In reality, you'd map `commandName` and `args` to actual functions/API calls
    // of the chromium-helper-cli.

    // Basic argument parsing for demonstration. A real CLI might use a library like yargs.
    // Example: !search "foo bar" -l cpp --limit 10
    //          commandName = search, queryArg = "foo bar", options = { l: "cpp", limit: "10" }
    let queryArg = "";
    const options: Record<string, string | boolean> = {};
    let currentOptionKey: string | null = null;
    const remainingArgs:string[] = [];

    // Simple parser: assumes options like -l <value> or --option <value> or --flag
    // and the main query argument is the first non-option part.
    // This is a simplified parser. For complex scenarios, a dedicated library would be better.

    let mainArg = "";
    const commandArgs = [...args]; // Clone args to safely manipulate

    // Extract main argument (query, filepath, ID), which is typically the first non-option.
    // Handle quoted main arguments first.
    if (commandArgs.length > 0) {
        if ((commandArgs[0].startsWith('"') && commandArgs[0].endsWith('"')) ||
            (commandArgs[0].startsWith("'") && commandArgs[0].endsWith("'"))) {
            mainArg = commandArgs.shift()!.slice(1, -1);
        } else if (commandArgs[0].startsWith('"')) {
            let currentQuery = commandArgs.shift()!.slice(1);
            while (commandArgs.length > 0 && !commandArgs[0].endsWith('"')) {
                currentQuery += " " + commandArgs.shift();
            }
            if (commandArgs.length > 0 && commandArgs[0].endsWith('"')) {
                currentQuery += " " + commandArgs.shift()!.slice(0, -1);
            }
            mainArg = currentQuery;
        } else if (!commandArgs[0].startsWith("-")) {
             mainArg = commandArgs.shift()!;
        }
    }

    // Process remaining arguments for options
    for (let i = 0; i < commandArgs.length; i++) {
        const arg = commandArgs[i];
        if (arg.startsWith('--')) {
            const optionName = arg.substring(2);
            if (i + 1 < commandArgs.length && !commandArgs[i+1].startsWith('-')) {
                options[optionName] = commandArgs[i+1];
                i++;
            } else {
                options[optionName] = true;
            }
        } else if (arg.startsWith('-')) {
            const optionChar = arg.substring(1);
            if (i + 1 < commandArgs.length && !commandArgs[i+1].startsWith('-')) {
                options[optionChar] = commandArgs[i+1];
                i++;
            } else {
                options[optionChar] = true;
            }
        } else {
            // If it's not an option, and mainArg is not set yet (e.g. options came first)
            if (!mainArg) mainArg = arg;
            else remainingArgs.push(arg); // Or treat as part of a subcommand's arguments
        }
    }
    // For commands like 'cl', the 'mainArg' is the CL number, and 'remainingArgs' might hold subcommand + its options
    // This part still needs more robust parsing for subcommands.

    try {
      switch (commandName) {
        case 'search':
          if (!mainArg) return "Usage: !search <query> [options like -l lang, --limit N]";
          const searchResults = await this.chromiumApi.searchCode({
            query: mainArg,
            language: options.l as string || options.language as string,
            limit: options.limit ? parseInt(options.limit as string) : undefined,
            caseSensitive: !!(options.c || options['case-sensitive']),
            filePattern: options.p as string || options['file-pattern'] as string,
          });
          return `Search Results for "${mainArg}":\n${JSON.stringify(searchResults.slice(0,5), null, 2)}\n(Found ${searchResults.length} results, showing first 5 if available)`;

        case 'file':
          if (!mainArg) return "Usage: !file <filepath> [--start N --end M]";
          const fileResult = await this.chromiumApi.getFile({
            filePath: mainArg,
            lineStart: options.start ? parseInt(options.start as string) : undefined,
            lineEnd: options.end ? parseInt(options.end as string) : undefined,
          });
          return `File: ${fileResult.filePath} (Lines: ${fileResult.displayedLines}/${fileResult.totalLines})\n${fileResult.content}\nBrowser URL: ${fileResult.browserUrl}`;

        case 'issue':
            if (!mainArg) return "Usage: !issue <id_or_url>";
            const issueResult = await this.chromiumApi.getIssue(mainArg);
            return `Issue ${issueResult.issueId}:\nTitle: ${issueResult.title}\nStatus: ${issueResult.status}\nURL: ${issueResult.browserUrl}\nDescription (partial):\n${(issueResult.description || issueResult.comments?.[0]?.content || 'N/A').substring(0,300)}...`;

        case 'cl': // Example: !cl <cl_number_or_url> diff --file "path/to/file.cc"
            if (!mainArg) return "Usage: !cl <cl_number_or_url> [status|diff|comments|file|bots] [options]";
            // Subcommand is now in remainingArgs[0] if present, options follow.
            const subCommand = remainingArgs.length > 0 ? remainingArgs.shift()! : 'status';

            // Re-parse options for the subcommand from remainingArgs
            const subOptions: Record<string, string | boolean> = {};
            for (let i = 0; i < remainingArgs.length; i++) {
                const arg = remainingArgs[i];
                 if (arg.startsWith('--')) {
                    const optionName = arg.substring(2);
                    if (i + 1 < remainingArgs.length && !remainingArgs[i+1].startsWith('-')) {
                        subOptions[optionName] = remainingArgs[i+1]; i++; }
                    else { subOptions[optionName] = true; }
                } else if (arg.startsWith('-')) {
                    const optionChar = arg.substring(1);
                    if (i + 1 < remainingArgs.length && !remainingArgs[i+1].startsWith('-')) {
                        subOptions[optionChar] = remainingArgs[i+1]; i++; }
                    else { subOptions[optionChar] = true; }
                }
            }

            switch(subCommand) {
                case 'status':
                    const status = await this.chromiumApi.getGerritCLStatus(mainArg);
                    return `CL ${status.id} Status: ${status.status}\nSubject: ${status.subject}\nUpdated: ${status.updated}`;
                case 'diff':
                    const diff = await this.chromiumApi.getGerritCLDiff({
                        clNumber: mainArg,
                        filePath: subOptions.file as string, // Use subOptions
                        patchset: subOptions.patchset ? parseInt(subOptions.patchset as string) : undefined
                    });
                    return `CL ${diff.clId} Diff (Patchset ${diff.patchset}):\nShowing ${diff.filePath ? 'file ' + diff.filePath : Object.keys(diff.filesData || {}).length + ' changed files'}\n${diff.diffData ? JSON.stringify(diff.diffData.content.slice(0,3), null, 2) + "\n..." : "No specific file diff requested or available." }`;
                // Add more cl subcommands: comments, file, bots
                default:
                    return `Unknown CL subcommand: ${subCommand}. Available: status, diff. Original args for cl: ${args.join(" ")}`;
            }

        // Add more tool mappings here for other ChromiumAPI methods
        default:
          return `Unknown tool command: ${commandName}. Available tools: search, file, issue, cl.`;
      }
    } catch (error) {
        console.error(`Error invoking tool ${commandName}:`, error);
        return `Error invoking tool ${commandName}: ${(error as Error).message}`;
    }
  }

  // --- Specialized Agent Management ---
  public async startAgent(agentType: SpecializedAgentType): Promise<string> {
    const agent = this.specializedAgents.get(agentType);
    if (agent) {
      await agent.start();
      return `${agentType} started.`;
    }
    return `Agent type ${agentType} not found.`;
  }

  public async stopAgent(agentType: SpecializedAgentType): Promise<string> {
    const agent = this.specializedAgents.get(agentType);
    if (agent) {
      await agent.stop();
      return `${agentType} stopped.`;
    }
    return `Agent type ${agentType} not found.`;
  }

  public async getAgentStatus(agentIdOrType: SpecializedAgentType | string): Promise<string> {
    // Check if it's a generic task ID first
    if (this.runningGenericTasks.has(agentIdOrType)) {
      const agent = this.runningGenericTasks.get(agentIdOrType);
      return agent!.getStatus(); // agent is guaranteed to be there due to .has() check
    }
    // Otherwise, assume it's a SpecializedAgentType
    const agent = this.specializedAgents.get(agentIdOrType as SpecializedAgentType);
    if (agent) {
      return agent.getStatus();
    }
    return `Agent type or ID '${agentIdOrType}' not found.`;
  }

  public async getResearcherStatus(): Promise<string> {
    let status = "LLM Researcher Status:\n";
    status += `- LLM Communication: ${this.llmComms ? 'Initialized' : 'Not Initialized'}\n`;
    status += `- Persistent Storage: ${this.storage ? 'Initialized' : 'Not Initialized'}\n`;

    status += "\n--- Predefined Specialized Agents ---\n";
    if (this.specializedAgents.size === 0) {
      status += "  No predefined specialized agents initialized.\n";
    } else {
      for (const [type, agent] of this.specializedAgents) {
        status += `  - ${type}: ${await agent.getStatus()}\n`;
      }
    }

    status += "\n--- Running/Completed Generic Tasks ---\n";
    if (this.runningGenericTasks.size === 0) {
      status += "  No generic tasks currently active or completed this session.\n";
    } else {
      for (const [id, agent] of this.runningGenericTasks) {
        status += `  - ID ${id}: ${await agent.getStatus()}\n`;
      }
    }
    return status;
  }


  // TODO: Add methods for:
  // - Dynamically creating agents (more complex)
  // - More sophisticated interaction with specialized agents (e.g., tasking, data retrieval)

  // --- Generic Task Agent Management ---
  private runningGenericTasks: Map<string, GenericTaskAgent> = new Map();

  // --- Workflow Management ---
  // Define types for workflows
  type WorkflowStepAction = (params: any) => Promise<string>; // Action can be any async function returning a string summary

  interface WorkflowStep {
    name: string;
    description: string;
    action: WorkflowStepAction;
    requiredParams?: string[]; // Parameters needed for this step's action
  }

  interface WorkflowDefinition {
    id: string;
    description: string;
    steps: WorkflowStep[];
    defaultParams?: Record<string, any>; // Default parameters for the workflow
  }

  private definedWorkflows: Map<string, WorkflowDefinition> = new Map();


  public async createAndRunGenericTask(config: GenericTaskAgentConfig): Promise<string> {
    if (!config.taskDescription || !config.llmPrompt) {
      return "Error: Generic task config must include 'taskDescription' and 'llmPrompt'.";
    }

    const agent = new GenericTaskAgent(this.llmComms, config, this.sharedAgentContext);
    this.runningGenericTasks.set(agent.id, agent);

    // Not awaiting start here, as it's a one-shot execution.
    // The user can check status using !agent-status <GenericTaskAgentID>
    agent.start().then(() => {
      console.log(`GenericTaskAgent [${agent.id}] execution finished.`);
      // Optionally, could have a callback or event system here if the researcher needs to be actively notified.
      // For now, results are polled via getAgentStatus or a specific getTaskResult command.
    }).catch(e => {
        console.error(`Error during GenericTaskAgent [${agent.id}] execution: `, e);
    });

    return `GenericTaskAgent [${agent.id}] created and started for task: "${config.taskDescription}". Check status with !agent-status ${agent.id}`;
  }

  public async getGenericTaskResult(taskId: string): Promise<string> {
    const agent = this.runningGenericTasks.get(taskId);
    if (!agent) {
      return `No generic task found with ID: ${taskId}`;
    }
    // Ensure it's a GenericTaskAgent, though map storage implies it.
    if (!(agent instanceof GenericTaskAgent)) {
        return `Agent ${taskId} is not a GenericTaskAgent.`;
    }

    const status = await agent.getStatus();
    if (status.includes("Active/Running")) {
      return `Task ${taskId} is still running.`;
    }
    const result = agent.getResult();
    const error = agent.getError();

    if (error) {
      return `Task ${taskId} failed: ${error}`;
    }
    if (result !== null) {
      return `Task ${taskId} completed. Result:\n${result}`;
    }
    return `Task ${taskId} status: ${status}. No result yet, or task did not produce one.`;
  }

  // --- Workflow Execution ---
  public registerWorkflow(definition: WorkflowDefinition): void {
    if (this.definedWorkflows.has(definition.id)) {
      console.warn(`Workflow with ID ${definition.id} is already registered. Overwriting.`);
    }
    this.definedWorkflows.set(definition.id, definition);
    console.log(`Workflow registered: ${definition.id} - ${definition.description}`);
  }

  public async runWorkflow(workflowId: string, params: Record<string, any>): Promise<string> {
    const workflow = this.definedWorkflows.get(workflowId);
    if (!workflow) {
      return `Workflow with ID '${workflowId}' not found. Available: ${Array.from(this.definedWorkflows.keys()).join(', ')}`;
    }

    console.log(`Starting workflow: ${workflow.id} with params: ${JSON.stringify(params)}`);
    let fullReport = `Workflow Report for: ${workflow.id} (${workflow.description})\n`;
    fullReport += `Parameters: ${JSON.stringify(params)}\n\n`;

    const mergedParams = { ...workflow.defaultParams, ...params };

    for (const step of workflow.steps) {
      fullReport += `--- Step: ${step.name} ---\n`;
      console.log(`Executing step: ${step.name}`);

      // Check for required parameters for the step
      if (step.requiredParams) {
        for (const reqParam of step.requiredParams) {
          if (!(reqParam in mergedParams)) {
            const errorMsg = `Error: Missing required parameter '${reqParam}' for step '${step.name}' in workflow '${workflowId}'.`;
            console.error(errorMsg);
            fullReport += `${errorMsg}\nWorkflow terminated prematurely.\n`;
            return fullReport;
          }
        }
      }

      try {
        const stepResult = await step.action(mergedParams);
        fullReport += `Description: ${step.description}\nResult:\n${stepResult}\n\n`;
        // Check if stepResult (potentially JSON string) contains data to merge into params for subsequent steps
        try {
            const stepOutputData = JSON.parse(stepResult);
            if (typeof stepOutputData === 'object' && stepOutputData !== null) {
                // console.log(`Merging output from step ${step.name} into workflow params:`, stepOutputData);
                Object.assign(mergedParams, stepOutputData); // Merge results for next steps
            }
        } catch (e) {
            // Not JSON, or not an object, so don't attempt to merge.
        }

      } catch (error) {
        const errorMsg = `Error during step '${step.name}': ${(error as Error).message}`;
        console.error(errorMsg, (error as Error).stack);
        fullReport += `Error: ${errorMsg}\nWorkflow execution halted.\n`;
        return fullReport; // Halt workflow on error
      }
    }

    fullReport += "--- Workflow Completed Successfully ---\n";
    console.log(`Workflow ${workflow.id} completed.`);
    return fullReport;
  }

  public getAvailableWorkflows(): string {
    if (this.definedWorkflows.size === 0) {
      return "No workflows defined.";
    }
    let info = "Available workflows:\n";
    this.definedWorkflows.forEach(wf => {
      info += `- ${wf.id}: ${wf.description}\n`;
      // wf.steps.forEach(step => {
      //   info += `  - Step: ${step.name} (${step.description})\n`;
      // });
    });
    return info;
  }
}
