// Handles the interactive chat
import * as readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { LLMResearcher } from './researcher.js';
import { SpecializedAgentType } from './agents/index.js'; // Updated path to barrel file
import { GenericTaskAgentConfig } from '../agent_config.js';

export class Chatbot {
  private rl: readline.Interface;
  private researcher!: LLMResearcher; // Definite assignment assertion
  private conversationHistory: string[];

  // Private constructor, force async creation
  private constructor() {
    this.rl = readline.createInterface({ input, output });
    this.conversationHistory = [];
  }

  public static async create(): Promise<Chatbot> {
    const chatbot = new Chatbot();
    // LLMResearcher.create() is async and initializes ChromiumAPI
    chatbot.researcher = await LLMResearcher.create();
    return chatbot;
  }

  public async start(): Promise<void> {
    if (!this.researcher) {
      console.error("Chatbot cannot start: LLMResearcher not initialized.");
      return;
    }
    console.log("Welcome to the AI Researcher Chat!");
    console.log("Ask questions about ongoing research, the Chromium codebase, or invoke tools (e.g., !search <query>).");
    console.log("Type 'exit' or 'quit' to end the chat.");

    // eslint-disable-next-line no-constant-condition
    while (true) {
      const userInput = await this.rl.question('You: ');
      if (userInput.toLowerCase() === 'exit' || userInput.toLowerCase() === 'quit') {
        break;
      }

      this.conversationHistory.push(`User: ${userInput}`);
      if (this.conversationHistory.length > 10) { // Keep last 5 Q/A pairs
        this.conversationHistory.splice(0, this.conversationHistory.length - 10);
      }

      await this.handleUserInput(userInput);
    }
    this.rl.close();
    console.log("Exiting chat.");
  }

  private async handleUserInput(input: string): Promise<void> {
    let response: string;
    try {
      if (input.startsWith('!')) {
        // Extended tool/command handling for agent management
        const [command, ...args] = input.substring(1).split(' ');
        switch (command) {
          case 'start-agent':
            if (args.length > 0) {
              response = await this.researcher.startAgent(args[0] as SpecializedAgentType);
            } else {
              response = "Usage: !start-agent <AgentType>";
            }
            break;
          case 'stop-agent':
            if (args.length > 0) {
              response = await this.researcher.stopAgent(args[0] as SpecializedAgentType);
            } else {
              response = "Usage: !stop-agent <AgentType>";
            }
            break;
          case 'agent-status':
            if (args.length > 0) {
              response = await this.researcher.getAgentStatus(args[0] as SpecializedAgentType);
            } else {
              response = "Usage: !agent-status <AgentType>. Available: ProactiveBugFinding, BugPatternAnalysis, CodebaseUnderstanding";
            }
            break;
          case 'status': // General status
            response = await this.researcher.getResearcherStatus();
            break;
          case 'create-task':
            try {
              const taskArgsString = args.join(' ');
              const taskConfig = JSON.parse(taskArgsString) as GenericTaskAgentConfig;
              response = await this.researcher.createAndRunGenericTask(taskConfig);
            } catch (e) {
              response = `Error parsing task configuration: ${(e as Error).message}. Usage: !create-task {"taskDescription": "desc", "llmPrompt": "prompt for llm"}`;
            }
            break;
          case 'task-result':
            if (args.length > 0) {
              response = await this.researcher.getGenericTaskResult(args[0]);
            } else {
              response = "Usage: !task-result <taskId>";
            }
            break;
          case 'workflow': // New command: !workflow <workflowId> [json_params]
            if (args.length > 0) {
              const workflowId = args.shift()!; // First arg is workflowId
              let wfParams = {};
              if (args.length > 0) {
                try {
                  // Remaining args joined and parsed as JSON
                  wfParams = JSON.parse(args.join(' '));
                } catch (e) {
                  response = `Error parsing workflow parameters: ${(e as Error).message}. \nParameters should be a valid JSON string, enclosed in single quotes if it contains spaces. \nExample: !workflow ${workflowId} '{"key": "value", "anotherKey": 123}'`;
                  break;
                }
              }
              response = await this.researcher.runWorkflow(workflowId, wfParams);
            } else {
              response = `Usage: !workflow <workflowId> [json_params_string]. Available workflows:\n${await this.researcher.getAvailableWorkflows()}`;
            }
            break;
          case 'workflows': // New command: !workflows
             response = await this.researcher.getAvailableWorkflows();
             break;
          default:
            // Fallback to general tool invocation if not an agent management command
            // Also, specific agent status can be fetched via !agent-status <GenericTaskAgentID>
            if (command === 'agent-status' && args[0]?.startsWith('generic-task-')) {
                 response = await this.researcher.getAgentStatus(args[0] as any); // Agent ID is used directly
            } else if (command === 'list-agent-requests') {
                // Parse simple --key value arguments for filtering
                const filters: { status?: string; agentType?: SpecializedAgentType | string; id?: string } = {};
                for (let i = 0; i < args.length; i += 2) {
                    const key = args[i].startsWith('--') ? args[i].substring(2) : null;
                    const value = args[i+1];
                    if (key && value) {
                        if (key === 'status') filters.status = value;
                        else if (key === 'agent' || key === 'agentType') filters.agentType = value as SpecializedAgentType;
                        else if (key === 'id') filters.id = value;
                    } else {
                        response = "Invalid filter format for !list-agent-requests. Use --key value.";
                        break;
                    }
                }
                if (!response) { // if no error in parsing filters
                    response = await this.researcher.listAgentRequests(filters);
                }
            }
            else {
                response = await this.researcher.invokeTool(input);
            }
            break;
        }
      } else {
        response = await this.researcher.processQuery(input, this.conversationHistory);
      }
      console.log(`AI: ${response}`);
      this.conversationHistory.push(`AI: ${response}`);
    } catch (e) {
        const err = e as Error;
        console.error(`Chatbot error: ${err.message}`);
        // Attempt to provide a more specific error if available from the researcher/LLM
        if (err.cause) {
            console.error("Cause: ", err.cause);
        }
        console.log(`AI: Sorry, I encountered an issue: ${err.message}`);
    }
  }
}
