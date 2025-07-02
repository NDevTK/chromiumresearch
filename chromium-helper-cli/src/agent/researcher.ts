// Contains the main LLM researcher logic
import { LLMCommunication, LLMConfig, LLMProviderType } from './llm_communication.js';
import { PersistentStorage } from './persistent_storage.js';

// --- Workflow Management Types ---
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
import {
  SpecializedAgent,
  ProactiveBugFinder,
  BugPatternAnalysisAgent,
  CodebaseUnderstandingAgent,
  GenericTaskAgent,
  SpecializedAgentType,
  SharedAgentContextType,
  KeyFileWithSymbols,
  BugPattern, // Added BugPattern for explicit typing
  AgentRequest // Added AgentRequest for explicit typing
} from './agents/index.js'; // Updated path to barrel file
import { ChromiumAPI } from '../api.js';
import { loadConfig as loadChromiumHelperConfig, Config as CHConfig } from '../config.js';
import { AgentConfig, loadAgentConfig, GenericTaskAgentConfig } from '../agent_config.js'; // Added GenericTaskAgentConfig import


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
    this.specializedAgents = new Map(); // This will store the actual agent instances
    // Initialize sharedAgentContext, including a placeholder for specializedAgents map
    this.sharedAgentContext = {
      findings: [],
      requests: [],
      knownBugPatterns: [],
      codebaseInsights: {},
      recentEvents: [],
      specializedAgents: this.specializedAgents // Share the map
    };
    // Note: chromiumApi is not initialized here yet.
  }

  public static async create(): Promise<LLMResearcher> {
    const agentConfig = await loadAgentConfig(); // Load config first
    const researcher = new LLMResearcher(agentConfig); // Pass it to constructor
    // IMPORTANT: Initialize async components which includes creating agent instances
    // and thus populating this.specializedAgents (which is referenced by this.sharedAgentContext.specializedAgents)
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

      // Create specialized agents and populate this.specializedAgents.
      // Since this.sharedAgentContext.specializedAgents references this.specializedAgents,
      // it will be correctly populated once this method finishes.
      this.initializeSpecializedAgents();

      this.initializeWorkflows(); // Initialize/register workflows
      await this.loadResearcherData(); // Load persistent data
      console.log("LLM Researcher fully initialized.");

    } catch (error) {
      console.error("Failed to initialize LLMResearcher's async components:", error);
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

    // --- Define "Deep Dive CL Analysis" Workflow ---
    const deepDiveClAnalysisWorkflow: WorkflowDefinition = {
      id: "deep-dive-cl-analysis",
      description: "Performs an in-depth analysis of a Chromium CL: status, diffs, comments, related issues, trybots, and synthesizes a report.",
      defaultParams: {
        maxFilesToDiffReview: 3,
        maxCommentsToConsider: 10,
      },
      steps: [
        {
          name: "Fetch CL Status & Basic Info",
          description: "Fetches basic CL information including subject, status, owner, and commit message.",
          action: async (params) => {
            const clStatus = await this.chromiumApi.getGerritCLStatus(params.clNumber);
            const commitMessage = clStatus.revisions?.[clStatus.current_revision]?.commit?.message || "Commit message not found.";
            return JSON.stringify({
              clSubject: clStatus.subject,
              clStatus: clStatus.status,
              clOwner: clStatus.owner?.email || "N/A",
              clUpdated: clStatus.updated,
              clLink: `https://chromium-review.googlesource.com/c/${params.clNumber}`,
              commitMessage: commitMessage,
              reportSection_BasicInfo: `CL Basic Info:\nSubject: ${clStatus.subject}\nStatus: ${clStatus.status}\nOwner: ${clStatus.owner?.email}\nUpdated: ${clStatus.updated}\nLink: ${clStatus.link}\nCommit Message (first 200 chars):\n${commitMessage.substring(0,200)}...\n`
            });
          }
        },
        {
          name: "Fetch CL Comments & Identify Potential Issues",
          description: "Fetches CL comments, summarizes them, and extracts mentioned issue IDs.",
          requiredParams: ["clNumber", "commitMessage", "maxCommentsToConsider"],
          action: async (params) => {
            const commentsData = await this.chromiumApi.getGerritCLComments({ clNumber: params.clNumber });
            let commentsSummary = `CL Comments (Top ${Math.min(commentsData.length, params.maxCommentsToConsider)} of ${commentsData.length}):\n`;
            const relevantComments = commentsData.slice(0, params.maxCommentsToConsider);
            relevantComments.forEach((comment: any) => {
              commentsSummary += `  - ${comment.author?.name} (${comment.updated}): "${comment.message.substring(0, 100).replace(/\n/g, ' ')}..." (File: ${comment.file || 'N/A'})\n`;
            });
            if (commentsData.length === 0) commentsSummary = "No comments found.\n";

            // Basic issue ID parsing (e.g., Bug: 12345, Fixed: chromium:12345)
            const issueRegex = /(?:Bug|Fixed|Issue|Problem|Resolves|Addresses)[\s:=#]*(?:chromium[:\/])?(\d{6,})/gi;
            let mentionedIssueIds: string[] = [];
            let match;
            const textToSearch = params.commitMessage + "\n" + relevantComments.map((c:any) => c.message).join("\n");
            while ((match = issueRegex.exec(textToSearch)) !== null) {
              if (!mentionedIssueIds.includes(match[1])) mentionedIssueIds.push(match[1]);
            }
            return JSON.stringify({
              mentionedIssueIds,
              reportSection_Comments: commentsSummary
            });
          }
        },
        {
          name: "Fetch Details for Mentioned Issues",
          description: "Fetches details for any issue IDs mentioned in the CL's commit message or comments.",
          requiredParams: ["mentionedIssueIds"],
          action: async (params) => {
            let issuesDetails = "Related Issues:\n";
            if (params.mentionedIssueIds && params.mentionedIssueIds.length > 0) {
              for (const issueId of params.mentionedIssueIds.slice(0, 2)) { // Limit to 2 issues for brevity
                try {
                  const issue = await this.chromiumApi.getIssue(issueId);
                  issuesDetails += `  - Issue ${issue.issueId}: ${issue.title} (Status: ${issue.status})\n    ${(issue.description || issue.comments?.[0]?.content || '').substring(0,100)}...\n`;
                } catch (e) { issuesDetails += `  - Failed to fetch Issue ${issueId}: ${(e as Error).message}\n`; }
              }
            } else { issuesDetails += "  No specific issues mentioned or found.\n"; }
            return JSON.stringify({ reportSection_RelatedIssues: issuesDetails });
          }
        },
        {
          name: "Fetch CL Diff & Select Files for Review",
          description: "Fetches the CL's diff and selects a subset of files for detailed review.",
          requiredParams: ["clNumber", "maxFilesToDiffReview"],
          action: async (params) => {
            const diffData = await this.chromiumApi.getGerritCLDiff({ clNumber: params.clNumber });
            const changedFiles = Object.keys(diffData.filesData || {}).filter(f => f !== "/COMMIT_MSG");
            // Simple selection: first N files (can be improved with heuristics)
            const filesForReview = changedFiles.slice(0, params.maxFilesToDiffReview);
            return JSON.stringify({
              clDiffData: diffData.filesData, // Pass full diff data for next step
              reportSection_ChangedFiles: `Changed Files Summary: ${changedFiles.length} files changed. Reviewing up to ${params.maxFilesToDiffReview} of them.\nSelected for review: ${filesForReview.join(', ') || 'None'}\n`
            });
          }
        },
        {
          name: "LLM Security Review of Selected File Diffs",
          description: "Performs an LLM-based security review of the diffs for selected files.",
          requiredParams: ["clSubject", "clDiffData", "maxFilesToDiffReview", "sharedAgentContext"], // Assuming filesForReview was part of clDiffData or handled implicitly
          action: async (params) => {
            let diffReviewSummaries = "LLM Diff Review Highlights:\n";
            const filesToReview = Object.keys(params.clDiffData || {}).filter(f => f !== "/COMMIT_MSG").slice(0, params.maxFilesToDiffReview);

            if (filesToReview.length === 0) {
              diffReviewSummaries += "  No files selected or available for diff review.\n";
            } else {
              for (const filePath of filesToReview) {
                const fileDiff = params.clDiffData[filePath];
                if (fileDiff?.content) {
                  const addedOrModifiedLines = fileDiff.content
                    .filter((line: any) => line.b && !line.a)
                    .map((line: any) => line.b.substring(0,200)) // Limit line length
                    .join('\n');

                  if (addedOrModifiedLines.length > 0) {
                    const llmPrompt = `Security review of diff for file "${filePath}" in CL "${params.clSubject}". Focus on common C++ pitfalls, IPC issues, web security. Diff (added/modified lines only, max 1000 chars):\n${addedOrModifiedLines.substring(0,1000)}\n\nKnown bug patterns to consider: ${params.sharedAgentContext.knownBugPatterns.slice(0,3).map((p:any)=>typeof p === 'string' ? p : p.name).join(', ')}. Be concise.`;
                    const review = await this.llmComms.sendMessage(llmPrompt, "You are a Chromium security reviewer AI.");
                    diffReviewSummaries += `  - ${filePath}: ${review.substring(0, 200)}...\n`;
                  } else {
                    diffReviewSummaries += `  - ${filePath}: No textual additions/modifications to review.\n`;
                  }
                }
              }
            }
            return JSON.stringify({ reportSection_DiffReviews: diffReviewSummaries });
          }
        },
        {
          name: "Fetch Trybot Status",
          description: "Fetches the trybot status for the CL.",
          requiredParams: ["clNumber"],
          action: async (params) => {
            const botResults = await this.chromiumApi.getGerritCLTrybotStatus({ clNumber: params.clNumber });
            let summary = `Trybot Status (Patchset ${botResults.patchset || 'latest'}):\n`;
            summary += `  LUCI URL: ${botResults.luciUrl || 'N/A'}\n`;
            summary += `  Stats: Total: ${botResults.totalBots}, Passed: ${botResults.passedBots}, Failed: ${botResults.failedBots}\n`;
            if (botResults.failedBots > 0 && botResults.bots) {
              summary += `  Failed bots: ${botResults.bots.filter((b:any) => b.status === 'FAILED').map((b:any)=>b.name).join(', ')}\n`;
            }
            return JSON.stringify({ reportSection_Trybots: summary });
          }
        },
        {
          name: "Synthesize Full Report",
          description: "Synthesizes all gathered information into a final comprehensive report using an LLM.",
          requiredParams: [
            "clNumber", "clSubject", "reportSection_BasicInfo", "reportSection_Comments",
            "reportSection_RelatedIssues", "reportSection_ChangedFiles",
            "reportSection_DiffReviews", "reportSection_Trybots"
          ],
          action: async (params) => {
            const synthesisPrompt = `
Synthesize a comprehensive analysis report for Chromium CL: ${params.clNumber} ("${params.clSubject}")
Based on the following sections:

${params.reportSection_BasicInfo}
${params.reportSection_Comments}
${params.reportSection_RelatedIssues}
${params.reportSection_ChangedFiles}
${params.reportSection_DiffReviews}
${params.reportSection_Trybots}

Provide a final summary, overall assessment (e.g., potential risks, confidence in the CL), and any actionable insights or red flags. Be factual and concise.
`;
            const finalReport = await this.llmComms.sendMessage(synthesisPrompt, "You are an AI security analyst compiling a CL review report.");
            return finalReport; // This is the final output of the workflow
          }
        }
      ]
    };
    this.registerWorkflow(deepDiveClAnalysisWorkflow);

    // TODO: Define more workflows like "New API Security Check"

    // --- Define "Security Audit Module" Workflow ---
    const securityAuditModuleWorkflow: WorkflowDefinition = {
      id: "security-audit-module",
      description: "Performs a security audit of a Chromium module: CUA for insight, PBF for vulnerability scan of key files, BPAA for pattern analysis, and LLM for final report.",
      defaultParams: {
        maxFilesToScanByPBF: 3, // Max key files PBF will be asked to scan from CUA insight
      },
      steps: [
        {
          name: "Get Module Insight (CUA)",
          description: "Fetches or generates an insight for the specified module using CodebaseUnderstandingAgent.",
          requiredParams: ["modulePath"],
          action: async (params) => {
            const cua = this.sharedAgentContext.specializedAgents?.get(SpecializedAgentType.CodebaseUnderstanding) as CodebaseUnderstandingAgent | undefined;
            if (!cua) return JSON.stringify({ error: "CodebaseUnderstandingAgent not available.", moduleInsight: null, keyFilesForPBF: [] });

            // Ensure CUA analyzes/updates the module
            await cua.performSingleModuleAnalysis(params.modulePath);
            const insight = this.sharedAgentContext.codebaseInsights[params.modulePath];
            if (!insight) return JSON.stringify({ error: `Failed to get insight for module ${params.modulePath}.`, moduleInsight: null, keyFilesForPBF: [] });

            // Select key files for PBF to scan (e.g., based on description length, or specific markers if CUA adds them)
            const keyFilesForPBF = (insight.keyFiles || [])
                .sort((a,b) => (b.description?.length || 0) - (a.description?.length || 0)) // Simplistic: longer description = more important
                .slice(0, params.maxFilesToScanByPBF || 3)
                .map(kf => kf.filePath);

            return JSON.stringify({
              moduleInsight: insight,
              keyFilesForPBF,
              reportSection_CUA: `CUA Insight for ${params.modulePath}:\nSummary: ${insight.summary}\nCommon Risks: ${(insight.commonSecurityRisks || []).join(', ')}\nKey Files Identified: ${(insight.keyFiles || []).map(f=>f.filePath).join(', ')}\n`
            });
          }
        },
        {
          name: "Vulnerability Scan of Key Files (PBF)",
          description: "Uses ProactiveBugFinder to scan selected key files from the module for vulnerabilities.",
          requiredParams: ["modulePath", "keyFilesForPBF", "moduleInsight"], // moduleInsight for context if PBF uses it
          action: async (params) => {
            const pbf = this.sharedAgentContext.specializedAgents?.get(SpecializedAgentType.ProactiveBugFinding) as ProactiveBugFinder | undefined;
            if (!pbf) return JSON.stringify({ error: "ProactiveBugFinder agent not available.", pbfScanResults: [] });

            let pbfScanResults: Array<{file: string, analysis: string}> = [];
            let reportSection_PBF = "PBF Scan Results:\n";

            if (!params.keyFilesForPBF || params.keyFilesForPBF.length === 0) {
                reportSection_PBF += "  No key files identified by CUA for PBF scan.\n";
            } else {
                for (const filePath of params.keyFilesForPBF) {
                    try {
                        console.log(`Workflow 'security-audit-module': PBF scanning ${filePath}`);
                        // PBF's analyzeSpecificFile now takes context from CUA via shared context,
                        // but we could also pass moduleInsight data explicitly if needed.
                        const analysis = await pbf.analyzeSpecificFile(filePath);
                        pbfScanResults.push({ file: filePath, analysis });
                        reportSection_PBF += `  File: ${filePath}\n    Analysis: ${analysis.substring(0, 200)}...\n`;
                    } catch (e) {
                        const errorMsg = `Error scanning file ${filePath} with PBF: ${(e as Error).message}`;
                        console.error(errorMsg);
                        pbfScanResults.push({ file: filePath, analysis: errorMsg });
                        reportSection_PBF += `  File: ${filePath}\n    Error: ${errorMsg}\n`;
                    }
                }
            }
            return JSON.stringify({ pbfScanResults, reportSection_PBF });
          }
        },
        {
          name: "Bug Pattern Analysis (BPAA)",
          description: "Uses BugPatternAnalysisAgent to check PBF findings against known patterns or extract new ones.",
          requiredParams: ["pbfScanResults"],
          action: async (params) => {
            const bpaa = this.sharedAgentContext.specializedAgents?.get(SpecializedAgentType.BugPatternAnalysis) as BugPatternAnalysisAgent | undefined;
            if (!bpaa) return JSON.stringify({ error: "BugPatternAnalysisAgent not available.", bpaaAnalysis: "BPAA not available." });

            let bpaaCombinedAnalysis = "";
            if (params.pbfScanResults && params.pbfScanResults.length > 0) {
                for (const finding of params.pbfScanResults) {
                    if (finding.analysis && !finding.analysis.startsWith("Error:")) {
                         // Get contextual advice for the analysis snippet
                        const advice = await bpaa.getContextualAdvice(finding.analysis.substring(0,1000)); // Send PBF analysis text
                        bpaaCombinedAnalysis += `  For PBF finding in ${finding.file}:\n    BPAA Advice: ${advice}\n`;
                        // TODO: Potentially trigger BPAA to try and extract a new pattern if PBF output is detailed enough
                    }
                }
            }
            if (!bpaaCombinedAnalysis) bpaaCombinedAnalysis = "No significant PBF findings to analyze with BPAA or BPAA provided no specific advice.";

            return JSON.stringify({
              bpaaAnalysis: bpaaCombinedAnalysis,
              reportSection_BPAA: `BPAA Analysis of PBF Findings:\n${bpaaCombinedAnalysis}\n`
            });
          }
        },
        {
          name: "Synthesize Module Security Report (LLM)",
          description: "Combines all gathered information (CUA insight, PBF scans, BPAA analysis) into a final security report for the module using an LLM.",
          requiredParams: ["modulePath", "reportSection_CUA", "reportSection_PBF", "reportSection_BPAA"],
          action: async (params) => {
            const synthesisPrompt = `
Synthesize a comprehensive security audit report for Chromium module: "${params.modulePath}"
Based on the following sections:

1. Codebase Understanding Agent (CUA) Insight:
${params.reportSection_CUA}

2. Proactive Bug Finder (PBF) Scan of Key Files:
${params.reportSection_PBF}

3. Bug Pattern Analysis Agent (BPAA) Review:
${params.reportSection_BPAA}

Provide a final summary, overall assessment of the module's security posture, key risks identified, and any actionable recommendations. Be factual and concise.
`;
            const finalReport = await this.llmComms.sendMessage(synthesisPrompt, "You are an AI security analyst compiling a module audit report.");
            return finalReport; // This is the final output of the workflow
          }
        }
      ]
    };
    this.registerWorkflow(securityAuditModuleWorkflow);

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
    const systemPrompt = `You are a lead AI security researcher for Chromium. Your goal is to assist the user by finding vulnerabilities, understanding the codebase, and retrieving specific information using available tools.
You have access to specialized AI agents (ProactiveBugFinder, BugPatternAnalysis, CodebaseUnderstanding) and a suite of information retrieval tools.
Available tools (invoked by the system if you suggest them in the correct format):
- !search <query> [options]: Searches Chromium code.
- !file <filepath> [--start N --end M]: Retrieves file content.
- !issue <id_or_url>: Fetches information about a specific issue.
- !gerrit <cl_number_or_url> [status|diff|comments|file|bots] [options]: Retrieves CL details (Gerrit).
- !agent-status <agent_type_or_id>: Checks the status of a specialized agent or generic task.
- !list-agent-requests: Lists active or recent inter-agent requests.

Interactions:
1. DIRECT COMMAND: If the query directly maps to a tool (e.g., "search for X"), prefix the command with 'EXECUTE_COMMAND: '.
   Example: User: "search for Browser::Create" -> AI: EXECUTE_COMMAND: !search Browser::Create
2. SUGGEST COMMAND: If unsure, suggest the command to the user.
   Example: User: "how to see CL 123 comments?" -> AI: You can use \`!gerrit 123 comments\`.
3. DELEGATE TASK: If the query is a complex task suitable for a specialized agent (ProactiveBugFinder, BugPatternAnalysis, CodebaseUnderstanding), formulate a delegation request. Output it on a new line, prefixed with 'DELEGATE_TASK: '. The JSON should include "targetAgentType", "taskType", and "params".
   Available specialized agents and their common taskTypes:
     - ProactiveBugFinder:
       - taskType: "analyze_file_for_vulnerabilities", params: {"filePath": "path/to/file.cc"}
     - BugPatternAnalysisAgent:
       - taskType: "get_contextual_advice_for_snippet", params: {"codeSnippet": "code..."}
     - CodebaseUnderstandingAgent:
       - taskType: "get_module_insight", params: {"modulePath": "components/foo"}
       - taskType: "provide_context_for_file", params: {"filePath": "path/to/file.cc"}
   Example: User: "analyze components/foo/bar.cc for bugs"
   AI: I will ask the ProactiveBugFinder agent to analyze that file.
   DELEGATE_TASK: {"targetAgentType": "ProactiveBugFinding", "taskType": "analyze_file_for_vulnerabilities", "params": {"filePath": "components/foo/bar.cc"}, "userQuery": "analyze components/foo/bar.cc for bugs"}
4. SUGGEST WORKFLOW: If the query matches a known complex task that has a defined workflow (e.g., "audit CL 12345"), suggest running the workflow.
   Example: User: "audit CL 12345" -> AI: You can use the 'basic-cl-audit' workflow for this. Try: !workflow basic-cl-audit '{"clNumber": "12345"}'
5. SYNTHESIZE_OVERVIEW: If the user asks for a security overview, summary of issues, or to correlate information about a specific file, module, or topic (e.g., "summarize security issues for file X", "what do we know about module Y?", "correlate findings for 'mojo vulnerability'"), use this action. Output it on a new line, prefixed with 'SYNTHESIZE_OVERVIEW: '. The value should be a short JSON string indicating the topic and type, e.g., '{"topic": "path/to/file.cc", "type": "file"}'.
   Example: User: "Summarize security issues for chrome/browser/foo.cc"
   AI: I will gather and synthesize information for that file.
   SYNTHESIZE_OVERVIEW: {"topic": "chrome/browser/foo.cc", "type": "file"}
6. GENERAL QUERY: For other questions, first consider if information from the 'sharedAgentContext' (recent findings, module insights, bug patterns) can answer the query. If so, synthesize an answer from that context. Otherwise, provide a general helpful textual response.

Prioritize using tools, delegating to agents, suggesting workflows, or synthesizing overviews over general answers if the user's intent can be met by these more specific actions.
Always be concise. The user is interacting with you via a CLI chatbot.`;

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
        const insightsContext = this.sharedAgentContext.codebaseInsights;
        let insightContribution = ""; // Changed variable name for clarity

        const cuaAgent = this.specializedAgents.get(SpecializedAgentType.CodebaseUnderstanding) as CodebaseUnderstandingAgent | undefined;

        // Heuristic: if path contains '.', assume it's a file and try on-demand analysis.
        // Otherwise, assume it's a module path and look for pre-computed insights.
        if (filePathOrModule.includes('.') && cuaAgent) {
            console.log(`LLMResearcher: User query matches file understanding for: ${filePathOrModule}. Invoking CUA.provideContextForFile.`);
            // This is an async call, so processQuery must handle it.
            // Since processQuery is already async, we can await here.
            const fileContext = await cuaAgent.provideContextForFile(filePathOrModule);
            insightContribution = `\n[Context from CodebaseUnderstanding for ${filePathOrModule} (On-Demand)]:\n${fileContext}\n`;
        } else if (insightsContext[filePathOrModule]) { // It's a module path with an existing insight
            const insight = insightsContext[filePathOrModule];
            let summary = `\n[Context from CodebaseUnderstanding for ${insight.modulePath}]:\nSummary: ${insight.summary.substring(0, 300)}...\n`;
            if (insight.primaryOwners && insight.primaryOwners.length > 0) {
                summary += `Primary Owners: ${insight.primaryOwners.join(', ')}\n`;
            }
            if (insight.keyFiles && insight.keyFiles.length > 0) {
                summary += `Key Files: ${insight.keyFiles.slice(0,2).map((f: KeyFileWithSymbols) => f.filePath).join(', ')}...\n`;
            }
            if (insight.commonSecurityRisks && insight.commonSecurityRisks.length > 0) {
                summary += `Common Risks: ${insight.commonSecurityRisks.slice(0,2).join(', ')}...\n`;
            }
            insightContribution = summary;
        } else if (cuaAgent) { // Module path, no pre-computed insight, but CUA exists
             console.log(`LLMResearcher: No pre-computed insight for module ${filePathOrModule}. CUA exists but not auto-triggering module analysis for this query.`);
             insightContribution = `\n[CodebaseUnderstanding]: No pre-computed insight for module ${filePathOrModule}. Analysis can be triggered if needed (e.g., via a dedicated command or if CUA runs its cycle).\n`;
        } else { // No CUA agent active or no specific file/module query
            insightContribution = `\n[CodebaseUnderstanding]: No insight available for ${filePathOrModule} and CodebaseUnderstandingAgent is not active.\n`;
        }
        agentContributions += insightContribution;
    }

    // 3. Include recent findings if query is general (e.g., "any new findings?", "latest security alerts")
    if (query.toLowerCase().includes("latest findings") || query.toLowerCase().includes("new vulnerabilities") || query.toLowerCase().includes("security status")) {
        if (this.sharedAgentContext.findings && this.sharedAgentContext.findings.length > 0) {
            agentContributions += "\n[Recent Agent Findings]:\n";
            // Show last 2-3 findings
            this.sharedAgentContext.findings.slice(-3).forEach((finding: { sourceAgent: string, type: string, data: any, timestamp: Date }) => { // Typed 'finding'
                agentContributions += `- ${finding.sourceAgent} (${finding.type}): ${JSON.stringify(finding.data).substring(0,150)}...\n`;
            });
        }
    }


    // Add agent contributions to the main query for the LLM, if any
    if (agentContributions) {
      enrichedQuery = `${query}\n\nRelevant information from active agents and shared context:\n${agentContributions}`;
    }

    // Add high-confidence/severity bug patterns to context for LLM awareness
    if (this.sharedAgentContext.knownBugPatterns && this.sharedAgentContext.knownBugPatterns.length > 0) {
      const highImpactPatterns = this.sharedAgentContext.knownBugPatterns
        .filter(p => typeof p !== 'string' && (p.confidence === 'High' || p.severity === 'Critical' || p.severity === 'High'))
        .slice(0, 5) // Limit to top 5 for brevity
        .map(p => `- ${(p as BugPattern).name}: ${(p as BugPattern).description.substring(0,100)}... (Severity: ${(p as BugPattern).severity || 'N/A'}, Conf: ${(p as BugPattern).confidence || 'N/A'})`)
        .join("\n");

      if (highImpactPatterns) {
        const patternContext = `\n\nKey Known Bug Patterns (High Impact):\n${highImpactPatterns}\nConsider these patterns when analyzing user queries related to vulnerabilities or code review.`;
        if (enrichedQuery === query) { // No other agent contributions yet
            enrichedQuery = `${query}${patternContext}`;
        } else { // Append to existing contributions
            enrichedQuery += patternContext;
        }
        console.log("LLMResearcher: Enriched query with key bug patterns.");
      }
    }

    if (enrichedQuery !== query) { // Log if query was enriched at all
        console.log("LLMResearcher: Query enriched for LLM.");
    }


    try {
      let llmResponse = await this.llmComms.sendMessage(enrichedQuery, systemPrompt);

      await this.saveResearcherData({ lastQuery: query, lastResponseTimestamp: new Date().toISOString(), enrichedQueryProvided: enrichedQuery !== query });

      const executeCommandPrefix = "EXECUTE_COMMAND: ";
      const delegateTaskPrefix = "DELEGATE_TASK: ";
      const synthesizeOverviewPrefix = "SYNTHESIZE_OVERVIEW: "; // New prefix
      const lines = llmResponse.split('\n');
      let commandToExecute: string | null = null;
      let taskToDelegate: any = null;
      let synthesisRequest: {topic: string, type: "file" | "module" | "general"} | null = null; // New request type
      let conversationalPart = "";
      let responseToSendToUser = "";

      for (let i = 0; i < lines.length; i++) {
        const currentLine = lines[i];
        if (currentLine.startsWith(executeCommandPrefix)) {
          commandToExecute = currentLine.substring(executeCommandPrefix.length).trim();
          conversationalPart = lines.slice(0, i).join('\n').trim();
          break;
        } else if (currentLine.startsWith(delegateTaskPrefix)) {
          try {
            const taskJsonString = currentLine.substring(delegateTaskPrefix.length).trim();
            taskToDelegate = JSON.parse(taskJsonString);
            conversationalPart = lines.slice(0, i).join('\n').trim();
            if (lines.length > i + 1) conversationalPart += "\n" + lines.slice(i + 1).join("\n");
          } catch (e) {
            console.error("LLMResearcher: Failed to parse DELEGATE_TASK JSON:", e, currentLine);
            taskToDelegate = null; conversationalPart = llmResponse;
          }
          break;
        } else if (currentLine.startsWith(synthesizeOverviewPrefix)) {
          try {
            const synthesisJsonString = currentLine.substring(synthesizeOverviewPrefix.length).trim();
            synthesisRequest = JSON.parse(synthesisJsonString);
            conversationalPart = lines.slice(0, i).join('\n').trim();
             if (lines.length > i + 1) conversationalPart += "\n" + lines.slice(i + 1).join("\n");
          } catch (e) {
            console.error("LLMResearcher: Failed to parse SYNTHESIZE_OVERVIEW JSON:", e, currentLine);
            synthesisRequest = null; conversationalPart = llmResponse;
          }
          break;
        }
      }

      if (commandToExecute) {
        console.log(`LLM suggested command: ${commandToExecute}. Executing...`);
        const toolOutput = await this.invokeTool(commandToExecute);
        responseToSendToUser = (conversationalPart ? conversationalPart + "\n" : "") + `Tool Output:\n${toolOutput}`;
      } else if (taskToDelegate && taskToDelegate.targetAgentType && taskToDelegate.taskType && taskToDelegate.params) {
        const requestId = `req-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
        const newRequest: AgentRequest = { // Ensure AgentRequest fields are correctly populated
          requestId,
          targetAgentType: taskToDelegate.targetAgentType as SpecializedAgentType,
          taskType: taskToDelegate.taskType,
          params: taskToDelegate.params,
          requestingAgentId: "ChatbotLLM",
          status: "pending",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          priority: taskToDelegate.priority || 50,
        };
        this.sharedAgentContext.requests.push(newRequest);
        console.log(`LLMResearcher: Delegated task ${requestId} to ${newRequest.targetAgentType} for task ${newRequest.taskType}.`);

        let delegationMessage = `Task delegated to ${newRequest.targetAgentType} with ID: ${requestId}.`;
        delegationMessage += `\nTask Type: ${newRequest.taskType}.`;
        delegationMessage += `\nUse '!list-agent-requests --id ${requestId}' or '!agent-status ${requestId}' to track.`;

        if (conversationalPart.trim()) {
            responseToSendToUser = conversationalPart + `\n${delegationMessage}`;
        } else {
            responseToSendToUser = `I've tasked the ${newRequest.targetAgentType} agent with: ${newRequest.taskType} (Params: ${JSON.stringify(newRequest.params).substring(0,50)}...). \n${delegationMessage}`;
        }
      } else if (synthesisRequest && synthesisRequest.topic && synthesisRequest.type) {
        console.log(`LLMResearcher: Synthesizing overview for topic "${synthesisRequest.topic}" (type: ${synthesisRequest.type}).`);
        const gatheredContext = await this.gatherContextForSynthesis(synthesisRequest.topic, synthesisRequest.type);
        const synthesisSystemPrompt = "You are an AI security analyst. Synthesize the provided information into a coherent security overview for the user. Highlight key risks, vulnerabilities, or important contextual points. Be clear and concise.";
        const synthesisUserPrompt = `${gatheredContext}\n\nPlease provide a synthesized security overview based on the information above for topic: "${synthesisRequest.topic}".`;

        const synthesizedReport = await this.llmComms.sendMessage(synthesisUserPrompt, synthesisSystemPrompt);
        responseToSendToUser = (conversationalPart ? conversationalPart + "\n" : "") + `Synthesized Overview for "${synthesisRequest.topic}":\n${synthesizedReport}`;
      }
       else {
        // No command, no delegation, just a general LLM response
        responseToSendToUser = llmResponse;
      }

      // Log recent findings from shared context for debugging/visibility (optional)
      // if (this.sharedAgentContext.findings.length > 0) {
      //   console.log(`LLMResearcher: Recent findings: ${JSON.stringify(this.sharedAgentContext.findings.slice(-3))}`);
      // }

      return responseToSendToUser;
    } catch (error) {
      console.error("Error processing query in LLMResearcher:", error);
      return "Sorry, I encountered an error trying to process your request.";
    }
  }

  public async invokeTool(toolCommand: string): Promise<string> {
          targetAgentType: taskToDelegate.targetAgentType as SpecializedAgentType,
          taskType: taskToDelegate.taskType,
          params: taskToDelegate.params,
          requestingAgentId: "ChatbotLLM", // Or LLMResearcher
          status: "pending",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          priority: taskToDelegate.priority || 50, // Default priority
        };
        this.sharedAgentContext.requests.push(newRequest);
        console.log(`LLMResearcher: Delegated task ${requestId} to ${newRequest.targetAgentType} for task ${newRequest.taskType}.`);

        // Construct user message
        // The conversationalPart might already be the AI's explanation (e.g., "I will ask the PBF agent...")
        // If not, generate a default one.
        let delegationMessage = `Task delegated to ${newRequest.targetAgentType} with ID: ${requestId}.`;
        delegationMessage += `\nTask Type: ${newRequest.taskType}.`;
        delegationMessage += `\nUse '!list-agent-requests --id ${requestId}' or '!agent-status ${requestId}' to track.`;

        if (conversationalPart.trim()) {
            responseToSendToUser = conversationalPart + `\n${delegationMessage}`;
        } else {
            // Construct a default conversational part if LLM didn't provide one
            responseToSendToUser = `I've tasked the ${newRequest.targetAgentType} agent with: ${newRequest.taskType} (Params: ${JSON.stringify(newRequest.params).substring(0,50)}...). \n${delegationMessage}`;
        }

      } else {
        // No command, no delegation, just a general LLM response
        responseToSendToUser = llmResponse;
      }

      // Log recent findings from shared context for debugging/visibility (optional)
      // if (this.sharedAgentContext.findings.length > 0) {
      //   console.log(`LLMResearcher: Recent findings: ${JSON.stringify(this.sharedAgentContext.findings.slice(-3))}`);
      // }

      return responseToSendToUser;
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

        case 'gerrit': // Changed 'cl' to 'gerrit'
            if (!mainArg) return "Usage: !gerrit <cl_number_or_url> [status|diff|comments|file|bots] [options]";
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
                case 'comments':
                    // Define a simple type for comment structure based on usage
                    type GerritComment = {
                        author?: { name?: string };
                        updated?: string;
                        message: string;
                        file?: string;
                        patch_set?: number
                    };
                    const commentsResult = await this.chromiumApi.getGerritCLComments({ clNumber: mainArg });
                    let commentsSummary = `CL ${mainArg} Comments (${commentsResult.length} total):\n`;
                    commentsResult.slice(0, 5).forEach((comment: GerritComment) => {
                        commentsSummary += `  - ${comment.author?.name || 'Unknown author'} (${comment.updated || 'N/A'}): "${comment.message.substring(0, 100).replace(/\n/g, ' ')}..." (File: ${comment.file || 'N/A'}, Patchset: ${comment.patch_set || 'N/A'})\n`;
                    });
                    if (commentsResult.length > 5) commentsSummary += `  ... and ${commentsResult.length - 5} more comments.\n`;
                    if (commentsResult.length === 0) commentsSummary = `No comments found for CL ${mainArg}.`;
                    return commentsSummary;
                case 'file':
                    // Usage: !gerrit <cl_id> file <file_path> [--patchset <ps_id>]
                    const filePathArg = remainingArgs.length > 0 ? remainingArgs.shift()! : null;
                    if (!filePathArg) return `Usage: !gerrit ${mainArg} file <file_path> [--patchset <ps_id>]`;

                    // Re-parse options for the 'file' subcommand from the *new* remainingArgs
                    const fileSubOptions: Record<string, string | boolean> = {};
                    for (let i = 0; i < remainingArgs.length; i++) {
                        const arg = remainingArgs[i];
                        if (arg.startsWith('--')) {
                            const optionName = arg.substring(2);
                            if (i + 1 < remainingArgs.length && !remainingArgs[i+1].startsWith('-')) {
                                fileSubOptions[optionName] = remainingArgs[i+1]; i++;
                            } else { fileSubOptions[optionName] = true; }
                        } else if (arg.startsWith('-')) {
                            // Simple -p <val> parsing, extend if needed
                            const optionChar = arg.substring(1);
                             if (i + 1 < remainingArgs.length && !remainingArgs[i+1].startsWith('-')) {
                                fileSubOptions[optionChar] = remainingArgs[i+1]; i++;
                            } else { fileSubOptions[optionChar] = true; }
                        }
                    }

                    const fileContentResult = await this.chromiumApi.getGerritPatchsetFile({
                        clNumber: mainArg,
                        filePath: filePathArg,
                        patchset: fileSubOptions.patchset ? parseInt(fileSubOptions.patchset as string) : undefined
                    });
                    return `File: ${fileContentResult.filePath} (CL ${fileContentResult.clId}, Patchset ${fileContentResult.patchset})\n${fileContentResult.content}`;
                case 'bots':
                    // Usage: !cl <cl_id> bots [--patchset <ps_id>] [--failed-only]
                    // Re-parse options for the 'bots' subcommand from remainingArgs
                    const botSubOptions: Record<string, string | boolean> = {};
                    for (let i = 0; i < remainingArgs.length; i++) {
                        const arg = remainingArgs[i];
                        if (arg.startsWith('--')) {
                            const optionName = arg.substring(2);
                            if (i + 1 < remainingArgs.length && !remainingArgs[i+1].startsWith('-')) {
                                botSubOptions[optionName] = remainingArgs[i+1]; i++;
                            } else { botSubOptions[optionName] = true; }
                        } else if (arg.startsWith('-')) {
                             const optionChar = arg.substring(1);
                             if (i + 1 < remainingArgs.length && !remainingArgs[i+1].startsWith('-')) {
                                botSubOptions[optionChar] = remainingArgs[i+1]; i++;
                            } else { botSubOptions[optionChar] = true; }
                        }
                    }

                    const botResults = await this.chromiumApi.getGerritCLTrybotStatus({
                        clNumber: mainArg,
                        patchset: botSubOptions.patchset ? parseInt(botSubOptions.patchset as string) : undefined,
                        failedOnly: !!botSubOptions['failed-only']
                    });

                    let botsSummary = `CL ${botResults.clId} Trybot Status (Patchset ${botResults.patchset || 'latest'}, Run ID: ${botResults.runId || 'N/A'}):\n`;
                    botsSummary += `LUCI URL: ${botResults.luciUrl || 'N/A'}\n`;
                    botsSummary += `Total: ${botResults.totalBots}, Passed: ${botResults.passedBots}, Failed: ${botResults.failedBots}, Running: ${botResults.runningBots}, Canceled: ${botResults.canceledBots}\n`;
                    if (botResults.bots && botResults.bots.length > 0) {
                        botsSummary += "Bots:\n";
                        botResults.bots.slice(0, 10).forEach((bot: any) => { // Show up to 10 bots
                            botsSummary += `  - ${bot.name}: ${bot.status} (${bot.summary || 'No summary'})\n`;
                        });
                        if (botResults.bots.length > 10) {
                            botsSummary += `  ... and ${botResults.bots.length - 10} more bots.\n`;
                        }
                    } else {
                        botsSummary += botResults.message || "No specific bot details available.";
                    }
                    return botsSummary;
                default:
                    return `Unknown Gerrit subcommand: '${subCommand}'. Available: status, diff, comments, file, bots. Original args for gerrit: ${args.join(" ")}`;
            }

        // Add more tool mappings here for other ChromiumAPI methods
        default:
          return `Unknown tool command: '${commandName}'. Available tools: search, file, issue, gerrit.`;
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
        const missingParams: string[] = [];
        for (const reqParam of step.requiredParams) {
          if (!(reqParam in mergedParams) || mergedParams[reqParam] === undefined || mergedParams[reqParam] === null) {
            missingParams.push(reqParam);
          }
        }
        if (missingParams.length > 0) {
          let errorMsg = `Error: Missing required parameter(s) for step '${step.name}' in workflow '${workflowId}': ${missingParams.join(', ')}.`;
          errorMsg += `\nPlease provide these parameters. You can ask the AI to help you formulate the JSON parameters for the workflow.`;
          errorMsg += `\nExample: !workflow ${workflowId} '{"${missingParams[0]}": "value", ...}'`;
          console.error(errorMsg);
          fullReport += `${errorMsg}\nWorkflow terminated prematurely.\n`;
          return fullReport;
        }
      }

      try {
        const stepResult = await step.action(mergedParams); // This is expected to be a string, potentially JSON.
        fullReport += `Description: ${step.description}\nResult:\n${stepResult}\n\n`;

        // Attempt to parse stepResult as JSON and merge if it's an object.
        // This allows steps to output structured data that subsequent steps can easily use.
        try {
          const parsedResult = JSON.parse(stepResult);
          if (typeof parsedResult === 'object' && parsedResult !== null && !Array.isArray(parsedResult)) {
            console.log(`Workflow '${workflow.id}', Step '${step.name}': Output was valid JSON object. Merging into workflow parameters.`);
            Object.assign(mergedParams, parsedResult);
          } else {
            // console.log(`Workflow '${workflow.id}', Step '${step.name}': Output was JSON but not an object, or was an array. Storing as string under step name.`);
            // If it's valid JSON but not an object (e.g. a string, number, array), store it under a key like "stepName_output"
            // For simplicity, we'll only merge objects directly. Other JSON types could be stored if needed:
            // mergedParams[`${step.name}_output`] = parsedResult;
          }
        } catch (e) {
          // Output was not valid JSON, so it remains a simple string result.
          // console.log(`Workflow '${workflow.id}', Step '${step.name}': Output was not JSON. Handled as plain string.`);
          // Optionally, store the plain string result under a specific key if needed by subsequent steps,
          // but the primary mechanism is merging JSON objects.
        }

      } catch (error) {
        const errorMsg = `Error during step '${step.name}': ${(error as Error).message}`;
        console.error(errorMsg, (error as Error).stack);
        fullReport += `Error: ${errorMsg}\nWorkflow execution halted.\n`;
        return fullReport; // Halt workflow on error
      }
    }

    fullReport += "\n--- Workflow Completed Successfully ---\n";
    // The last step's result is often the main synthesis, so we ensure it's prominent.
    // If the last step's result was merged into params (e.g. as a JSON object), this won't re-print it,
    // but if it was a final string (like a report), it's already in fullReport.
    // We can add a concluding message.
    fullReport += `Final output for workflow ${workflow.id} is detailed above.`;
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

  public listAgentRequests(filters?: { status?: string; agentType?: SpecializedAgentType | string; id?: string }): string {
    if (!this.sharedAgentContext || !this.sharedAgentContext.requests || this.sharedAgentContext.requests.length === 0) {
      return "No agent requests found in the shared context.";
    }

    let filteredRequests = [...this.sharedAgentContext.requests];

    if (filters?.id) {
      filteredRequests = filteredRequests.filter(req => req.requestId === filters.id);
    }
    if (filters?.status) {
      filteredRequests = filteredRequests.filter(req => req.status.toLowerCase() === filters.status?.toLowerCase());
    }
    if (filters?.agentType) {
      filteredRequests = filteredRequests.filter(req => req.targetAgentType.toLowerCase() === filters.agentType?.toLowerCase());
    }

    if (filteredRequests.length === 0) {
      return "No agent requests match the specified filters.";
    }

    // Sort by priority (lower first) then by creation date (most recent first for active, oldest first for completed/failed)
    const sortedRequests = filteredRequests.sort((a, b) => {
      const priorityDiff = (a.priority ?? 100) - (b.priority ?? 100);
      if (priorityDiff !== 0) return priorityDiff;
      if (a.status === "pending" || a.status === "in_progress") {
        return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(); // Recent pending first
      }
      return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(); // Oldest completed/failed first
    });

    let report = `Agent Requests (${sortedRequests.length} matching filter):\n`;
    report += `  Applied Filters: ${filters ? JSON.stringify(filters) : 'None'}\n`;
    report += `  Use !list-agent-requests --status <pending|completed|failed> --agent <AgentType> --id <requestID>\n\n`;


    for (const req of sortedRequests) {
      report += `------------------------------------\n`;
      report += ` ID        : ${req.requestId}\n`;
      report += ` Target    : ${req.targetAgentType}\n`;
      report += ` Task      : ${req.taskType}\n`;
      report += ` Status    : ${req.status.toUpperCase()}\n`;
      report += ` Priority  : ${req.priority ?? 'N/A'}\n`;
      report += ` Created   : ${new Date(req.createdAt).toLocaleString()}\n`;
      report += ` Updated   : ${new Date(req.updatedAt).toLocaleString()}\n`;
      if (req.requestingAgentId) report += ` Requester : ${req.requestingAgentId}\n`;

      const paramsStr = JSON.stringify(req.params);
      report += ` Params    : ${paramsStr.substring(0, 80)}${paramsStr.length > 80 ? '...' : ''}\n`;

      if (req.status === "completed" && req.result) {
        const resultStr = typeof req.result === 'string' ? req.result : JSON.stringify(req.result);
        report += ` Result    : ${resultStr.substring(0, 120)}${resultStr.length > 120 ? '...' : ''}\n`;
      } else if (req.status === "failed" && req.error) {
        report += ` Error     : ${req.error}\n`;
      }
    }
    report += `------------------------------------\nTotal requests in context: ${this.sharedAgentContext.requests.length}\n`;
    return report;
  }

  private async gatherContextForSynthesis(topic: string, type: "file" | "module" | "general"): Promise<string> {
    let context = `Synthesizing information related to: ${topic} (type: ${type})\n`;
    const MAX_ITEMS = 3; // Max items per category to keep context manageable

    // 1. Findings from ProactiveBugFinder or other direct analyses
    if (this.sharedAgentContext.findings.length > 0) {
      const relevantFindings = this.sharedAgentContext.findings.filter(f =>
        (f.data.file && f.data.file.includes(topic)) ||
        (f.data.modulePath && f.data.modulePath.includes(topic)) ||
        (f.data.analysis && f.data.analysis.toLowerCase().includes(topic.toLowerCase())) ||
        (f.type.toLowerCase().includes(topic.toLowerCase()))
      ).slice(0 - MAX_ITEMS); // Get last MAX_ITEMS

      if (relevantFindings.length > 0) {
        context += "\n--- Relevant Recent Findings ---\n";
        relevantFindings.forEach(f => {
          context += `Source: ${f.sourceAgent}, Type: ${f.type}, Date: ${f.timestamp.toLocaleDateString()}\n`;
          if (f.data.file) context += `File: ${f.data.file}\n`;
          if (f.data.analysis) context += `Analysis Summary: ${f.data.analysis.substring(0, 200)}...\n`;
          else if (f.data.summary) context += `Summary: ${f.data.summary.substring(0,200)}...\n`;
          else context += `Data: ${JSON.stringify(f.data).substring(0,150)}...\n`;
          context += "---\n";
        });
      }
    }

    // 2. Codebase Insights from CodebaseUnderstandingAgent
    if (type === "file" || type === "module") {
        const modulePath = (type === "file") ? this.getParentModulePathForContext(topic) : topic;
        const insight = this.sharedAgentContext.codebaseInsights[modulePath];
        if (insight) {
            context += "\n--- Codebase Module Insight ---\n";
            context += `Module: ${insight.modulePath}\nSummary: ${insight.summary}\n`;
            if (insight.keyFiles) context += `Key Files: ${insight.keyFiles.slice(0,MAX_ITEMS).map(kf => kf.filePath).join(', ')}\n`;
            if (insight.commonSecurityRisks) context += `Common Security Risks: ${insight.commonSecurityRisks.join(', ')}\n`;
            context += "---\n";
        }
    }

    // 3. Known Bug Patterns from BugPatternAnalysisAgent
    if (this.sharedAgentContext.knownBugPatterns.length > 0) {
        const relevantPatterns = (this.sharedAgentContext.knownBugPatterns.filter(p => {
            if (typeof p === 'string') return p.toLowerCase().includes(topic.toLowerCase());
            return p.name.toLowerCase().includes(topic.toLowerCase()) ||
                   p.description.toLowerCase().includes(topic.toLowerCase()) ||
                   (p.tags || []).some(tag => tag.toLowerCase().includes(topic.toLowerCase()));
        }) as BugPattern[]).filter(p => p.confidence === 'High' || p.severity === 'Critical' || p.severity === 'High') // Filter by impact
        .slice(0, MAX_ITEMS);

        if (relevantPatterns.length > 0) {
            context += "\n--- Relevant Known Bug Patterns (High Impact) ---\n";
            relevantPatterns.forEach(p => {
                context += `Pattern: ${p.name} (Severity: ${p.severity || 'N/A'}, Confidence: ${p.confidence || 'N/A'})\nDescription: ${p.description.substring(0,150)}...\n`;
                context += "---\n";
            });
        }
    }
    return context;
  }

  // Helper to get module path for a file path (simplified)
  private getParentModulePathForContext(filePath: string): string {
      const parts = filePath.split('/');
      if (parts.length > 1) parts.pop(); // remove filename
      return parts.join('/');
  }

}
