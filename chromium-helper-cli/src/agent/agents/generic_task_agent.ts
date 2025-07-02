// src/agent/agents/generic_task_agent.ts
import { LLMCommunication } from '../llm_communication.js';
import { GenericTaskAgentConfig } from '../../agent_config.js';
import {
    SpecializedAgent,
    SpecializedAgentType,
    SharedAgentContextType
} from './types.js'; // Import from new types.ts

export class GenericTaskAgent implements SpecializedAgent {
  public type = SpecializedAgentType.GenericTask;
  public id: string;
  private llmComms: LLMCommunication;
  private config: GenericTaskAgentConfig & { id: string }; // Ensure id is part of config type used internally
  private sharedContext?: SharedAgentContextType;
  private isActive: boolean = false;
  private result: string | null = null;
  private error: string | null = null;

  constructor(llmComms: LLMCommunication, config: GenericTaskAgentConfig, sharedContext?: SharedAgentContextType) {
    this.id = config.id || `generic-task-${Date.now()}-${Math.random().toString(36).substring(2,7)}`; // More unique ID
    this.llmComms = llmComms;
    this.config = { ...config, id: this.id }; // Store id in internal config
    if (sharedContext) this.setSharedContext(sharedContext);
    console.log(`GenericTaskAgent [${this.id}] initialized for task: ${this.config.taskDescription}`);
  }

  public setSharedContext(context: SharedAgentContextType): void { this.sharedContext = context; }

  async start(): Promise<void> {
    if (this.isActive) {
      console.warn(`GenericTaskAgent [${this.id}] is already active.`);
      return;
    }
    this.isActive = true;
    this.result = null;
    this.error = null;
    console.log(`GenericTaskAgent [${this.id}] started for task: "${this.config.taskDescription}".`);
    try {
      // Ensure llmPrompt and taskDescription are present, though constructor should ideally enforce this via config type
      if (!this.config.llmPrompt || !this.config.taskDescription) {
          throw new Error("GenericTaskAgent config missing llmPrompt or taskDescription.");
      }
      this.result = await this.llmComms.sendMessage(this.config.llmPrompt, `Executing task: ${this.config.taskDescription}`);
      console.log(`GenericTaskAgent [${this.id}] completed. Result preview: ${(this.result || "").substring(0, 100)}...`);
    } catch (e) {
      const err = e as Error;
      this.error = err.message;
      console.error(`GenericTaskAgent [${this.id}] failed: ${this.error}`);
    } finally {
      this.isActive = false;
    }
  }

  async stop(): Promise<void> {
    // For a one-shot task agent, stop might not do much if it's already completed or not started.
    // If it were a long-running generic task, cancellation logic would be here.
    this.isActive = false;
    console.log(`GenericTaskAgent [${this.id}] signalled to stop (if it was running).`);
  }

  async getStatus(): Promise<string> {
    let status = `GenericTaskAgent [${this.id}] (${this.config.taskDescription || 'No description'}): `;
    if (this.isActive) status += "Active/Running.";
    else if (this.result !== null) status += `Completed. Result: ${(this.result || "").substring(0,50)}...`;
    else if (this.error !== null) status += `Failed. Error: ${this.error}`;
    else status += "Idle/Pending.";
    return status;
  }

  public getResult(): string | null { return this.result; }
  public getError(): string | null { return this.error; }

  // processData and processPendingRequests are not typically used by GenericTaskAgent
  // as it's usually a one-shot LLM call.
  // public async processData?(data: unknown): Promise<void> {}
  // public async processPendingRequests?(): Promise<void> {}
}
