import fs from 'node:fs/promises';
import path from 'node:path';

// Define the structure of the agent configuration
export interface AgentLLMConfig {
  ollamaModel: string;
  ollamaBaseUrl: string;
  cacheMaxSize: number;
  defaultTemperature: number;
  defaultMaxTokens: number;
}

export interface ProactiveBugFinderConfig {
  filesPerCycle: number;
  heuristicKeywords: string[];
  sensitivePathPatterns: string[];
  prioritizationScore: {
    pathMatch: number;
    keywordInFile: number;
    recentClMention: number;
    sensitivePathRecentCommitScore?: number;
  };
  maxProcessedFileHistory?: number; // Max number of file paths to remember
  heuristicScanIntervalMinutes?: number; // Interval for heuristic scans (less relevant now)
  idleCycleDelayMs?: number; // Delay when no work is found in continuous loop
  itemProcessingCheckIntervalMs?: number; // How often to check if current item is done
  interItemDelayMs?: number; // Small delay between processing items in the loop
  maxCandidatesPerHeuristicQuery?: number; // Max candidates to fetch in one heuristic check
  recheckIntervalMs?: number; // How long before a heuristically found file might be checked again
}

export interface BugPatternAnalysisConfig {
  commitsPerCycle: number; // Commits per pattern extraction cycle
  issuesPerCycle?: number; // Issues per issue analysis cycle (can default to commitsPerCycle)
  targetIssueSeverities?: string[]; // e.g., ["S0", "S1"]
  maxProcessedHistorySize?: number; // Max number of commit/issue IDs to remember
  patternExtractionIntervalMinutes?: number; // Interval for commit-based pattern extraction (less relevant)
  issueAnalysisIntervalMinutes?: number; // Interval for issue-based analysis (less relevant)
  idleCycleDelayMsBPA?: number; // Delay when no work is found in continuous loop for BPA
  itemProcessingCheckIntervalMsBPA?: number; // How often to check if current item is done for BPA
  interItemDelayMsBPA?: number; // Small delay between processing items in BPA loop
}

export interface CodebaseUnderstandingConfig {
  filesPerModuleCycle: number; // Files to analyze within a module during its detailed analysis
  maxModuleInsights: number; // Max number of module insights to retain
  maxProcessedModuleHistory?: number; // Max number of module paths to remember as analyzed
  moduleAnalysisIntervalMinutes?: number; // Interval for autonomous module analysis cycles (less relevant)
  moduleInsightStalenessDays?: number; // How many days before an insight is considered stale for re-analysis
  idleCycleDelayMsCUA?: number; // Delay when no work is found in continuous loop for CUA
  itemProcessingCheckIntervalMsCUA?: number; // How often to check if current item is done for CUA
  interItemDelayMsCUA?: number; // Small delay between processing items in CUA loop
  exampleModulesForCUA?: string[]; // Example modules CUA might cycle through
}

export interface GenericTaskAgentConfig {
  id?: string; // Optional ID, can be auto-generated
  taskDescription: string; // User-facing description of the task
  llmPrompt: string; // The actual prompt to be sent to the LLM
  // Potentially add context or other parameters LLM might need for the task
}

export interface AgentConfig {
  llm: AgentLLMConfig;
  proactiveBugFinder: ProactiveBugFinderConfig;
  bugPatternAnalysis: BugPatternAnalysisConfig;
  codebaseUnderstanding: CodebaseUnderstandingConfig;
}

// Default configuration values
const DEFAULT_AGENT_CONFIG: AgentConfig = {
  llm: {
    ollamaModel: process.env.OLLAMA_MODEL || 'llama3',
    ollamaBaseUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
    cacheMaxSize: 100,
    defaultTemperature: 0.7,
    defaultMaxTokens: 1500,
  },
  proactiveBugFinder: {
    filesPerCycle: 1, // Now processes one main item at a time in its loop
    heuristicKeywords: ['mojo', 'IPC_MESSAGE_HANDLER', 'RuntimeEnabledFeatures', 'unsafe_raw_ptr', 'reinterpret_cast'],
    sensitivePathPatterns: ['third_party/blink/renderer/core/', 'content/browser/', 'services/network/', 'components/security_interstitials/', 'net/'],
    prioritizationScore: { // This might be used for internal queue prioritization
      pathMatch: 5,
      keywordInFile: 3,
      recentClMention: 2,
      sensitivePathRecentCommitScore: 7,
    },
    maxProcessedFileHistory: 200, // Increased history
    heuristicScanIntervalMinutes: 5, // Kept for status, but loop is continuous
    idleCycleDelayMs: 10000, // 10 seconds delay when idle
    itemProcessingCheckIntervalMs: 1000, // 1 second check if busy
    interItemDelayMs: 200, // 0.2 seconds between items
    maxCandidatesPerHeuristicQuery: 5, // Fetch 5 potential candidates in one heuristic check
    recheckIntervalMs: 7 * 24 * 3600 * 1000, // Re-check a file heuristically after 7 days
  },
  bugPatternAnalysis: {
    commitsPerCycle: 1, // Processes one commit at a time in its new loop
    issuesPerCycle: 1,  // Processes one issue at a time
    targetIssueSeverities: ["S0", "S1", "High"],
    maxProcessedHistorySize: 250, // Slightly increased history
    patternExtractionIntervalMinutes: 10, // Less relevant, kept for status
    issueAnalysisIntervalMinutes: 10,     // Less relevant, kept for status
    idleCycleDelayMsBPA: 20000, // 20 seconds delay when idle
    itemProcessingCheckIntervalMsBPA: 1000, // 1 second check if busy
    interItemDelayMsBPA: 300, // 0.3 seconds between items
  },
  codebaseUnderstanding: {
    filesPerModuleCycle: 3, // During a specific module's deep dive (still relevant for performSingleModuleAnalysis)
    maxModuleInsights: 30, // Increased
    maxProcessedModuleHistory: 75, // Increased
    moduleAnalysisIntervalMinutes: 30, // Less relevant, kept for status
    moduleInsightStalenessDays: 30, // Default: Stale after 30 days
    idleCycleDelayMsCUA: 45000, // 45 seconds delay when idle
    itemProcessingCheckIntervalMsCUA: 1000, // 1 second check if busy
    interItemDelayMsCUA: 500, // 0.5 seconds between items
    exampleModulesForCUA?: [ // Provide a default list
        "components/safe_browsing/core/browser",
        "services/network",
        "content/browser/renderer_host",
        "components/history",
        "third_party/blink/renderer/core/editing",
        "net/disk_cache",
        "media/gpu"
    ]
  }
};

// Function to load agent configuration
// Similar to the main CLI's config loader, but for agent-specific settings.
export async function loadAgentConfig(configPath?: string): Promise<AgentConfig> {
  const filePath = configPath || path.join(process.cwd(), 'ch-agent-config.json');
  let userConfig: Partial<AgentConfig> = {};

  try {
    const fileContent = await fs.readFile(filePath, 'utf-8');
    userConfig = JSON.parse(fileContent) as Partial<AgentConfig>;
    console.log(`Agent configuration loaded from ${filePath}`);
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.warn(`Agent configuration file not found at ${filePath}. Using default agent configuration.`);
    } else {
      console.error(`Error reading or parsing agent configuration file ${filePath}:`, error);
      console.warn('Using default agent configuration due to error.');
    }
  }

  // Deep merge of default and user configs
  // For nested objects, ensure they are merged property by property
  const mergedConfig: AgentConfig = {
    llm: { ...DEFAULT_AGENT_CONFIG.llm, ...userConfig.llm },
    proactiveBugFinder: {
      ...DEFAULT_AGENT_CONFIG.proactiveBugFinder,
      ...(userConfig.proactiveBugFinder || {}),
      prioritizationScore: {
          ...DEFAULT_AGENT_CONFIG.proactiveBugFinder.prioritizationScore,
          ...(userConfig.proactiveBugFinder?.prioritizationScore || {})
      } // Ensure prioritizationScore itself is merged, including new optional fields
    },
    bugPatternAnalysis: {
      ...DEFAULT_AGENT_CONFIG.bugPatternAnalysis,
      ...userConfig.bugPatternAnalysis
      // targetIssueSeverities will be taken from userConfig if present, otherwise from DEFAULT_AGENT_CONFIG due to spread order.
    },
    codebaseUnderstanding: { ...DEFAULT_AGENT_CONFIG.codebaseUnderstanding, ...userConfig.codebaseUnderstanding },
  };

  return mergedConfig;
}
