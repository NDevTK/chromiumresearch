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
}

export interface BugPatternAnalysisConfig {
  commitsPerCycle: number;
  targetIssueSeverities?: string[]; // e.g., ["S0", "S1"]
  maxProcessedHistorySize?: number; // Max number of commit/issue IDs to remember
}

export interface CodebaseUnderstandingConfig {
  filesPerModuleCycle: number;
  maxModuleInsights: number;
  maxProcessedModuleHistory?: number; // Max number of module paths to remember as analyzed
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
    filesPerCycle: 3,
    heuristicKeywords: ['mojo', 'IPC_MESSAGE_HANDLER', 'RuntimeEnabledFeatures'],
    sensitivePathPatterns: ['third_party/blink/renderer/', 'content/browser/', 'services/network/'],
    prioritizationScore: {
      pathMatch: 5,
      keywordInFile: 3,
      recentClMention: 2,
      sensitivePathRecentCommitScore: 7,
    },
    maxProcessedFileHistory: 100,
  },
  bugPatternAnalysis: {
    commitsPerCycle: 2,
    targetIssueSeverities: ["S0", "S1"], // Default to high severities
    maxProcessedHistorySize: 200,
  },
  codebaseUnderstanding: {
    filesPerModuleCycle: 3,
    maxModuleInsights: 20,
    maxProcessedModuleHistory: 50,
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
