// For interacting with LLMs (OpenAI, Ollama)
import fetch, { Headers, RequestInit } from 'node-fetch';
import crypto from 'node:crypto';

export enum LLMProviderType {
  OpenAI = "OpenAI",
  Ollama = "Ollama",
}

export interface LLMConfig {
  provider: LLMProviderType;
  apiKey?: string; // Required for OpenAI
  baseUrl?: string; // Required for Ollama (e.g., http://localhost:11434) or self-hosted
  model: string;
  temperature?: number;
  maxTokens?: number;
}

interface ChatCompletionRequestMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

interface ChatCompletionRequestBody {
  model: string;
  messages: ChatCompletionRequestMessage[];
  temperature?: number;
  max_tokens?: number;
  // Add other OpenAI parameters as needed (stream, stop, etc.)
}

interface ChatCompletionResponseChoice {
  index: number;
  message: ChatCompletionRequestMessage;
  finish_reason: string;
}

interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: ChatCompletionResponseChoice[];
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}


export class LLMCommunication {
  private config: LLMConfig;
  private endpoint: string;
  private cache: Map<string, string>; // Cache: hash -> response
  private cacheMaxSize: number;
  // TODO: Implement persistent cache (e.g., to a file) for LLM responses for CLI tool.

  constructor(config: LLMConfig, cacheSize: number = 100) {
    this.config = {
        // Defaults from LLMConfig can be part of its definition or applied here
        temperature: config.temperature !== undefined ? config.temperature : 0.7,
        maxTokens: config.maxTokens !== undefined ? config.maxTokens : 1024,
        ...config
    };
    this.cache = new Map();
    this.cacheMaxSize = cacheSize;
    console.log(`LLMCommunication: Cache size set to ${this.cacheMaxSize}`);

    if (this.config.provider === LLMProviderType.Ollama) {
        if (!this.config.baseUrl) {
            throw new Error("Base URL is required for Ollama provider.");
        }
        this.endpoint = `${this.config.baseUrl.replace(/\/$/, "")}/v1/chat/completions`;
    } else { // OpenAI or other OpenAI-compatible
        this.endpoint = this.config.baseUrl
            ? `${this.config.baseUrl.replace(/\/$/, "")}/v1/chat/completions`
            : "https://api.openai.com/v1/chat/completions";
    }
    console.log(`LLMCommunication initialized for ${this.config.provider} (Model: ${this.config.model}) targeting endpoint: ${this.endpoint}`);
  }

  private generateCacheKey(prompt: string, systemContext?: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(prompt);
    if (systemContext) {
      hash.update(systemContext);
    }
    hash.update(this.config.model); // Model is part of the key
    return hash.digest('hex');
  }

  public async sendMessage(prompt: string, systemContext?: string): Promise<string> {
    const cacheKey = this.generateCacheKey(prompt, systemContext);
    if (this.cache.has(cacheKey)) {
      console.log(`LLMCommunication: Cache hit for key ${cacheKey.substring(0,10)}...`);
      return this.cache.get(cacheKey)!;
    }
    console.log(`LLMCommunication: Cache miss for key ${cacheKey.substring(0,10)}...`);


    const messages: ChatCompletionRequestMessage[] = [];
    if (systemContext) {
      messages.push({ role: "system", content: systemContext });
    }
    messages.push({ role: "user", content: prompt });

    const body: ChatCompletionRequestBody = {
      model: this.config.model,
      messages: messages,
      temperature: this.config.temperature,
      max_tokens: this.config.maxTokens,
    };

    const headers = new Headers({
      "Content-Type": "application/json",
    });

    if (this.config.provider === LLMProviderType.OpenAI && this.config.apiKey) {
      headers.append("Authorization", `Bearer ${this.config.apiKey}`);
    }
    // For Ollama, API key is typically not needed unless behind a proxy that requires it.

    console.log(`Sending to ${this.config.provider} model ${this.config.model}: User prompt: ${prompt.substring(0,100)}...`);

    try {
      const requestInit: RequestInit = {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(body),
      };

      const response = await fetch(this.endpoint, requestInit);

      if (!response.ok) {
        const errorBody = await response.text();
        console.error(`LLM API request failed with status ${response.status}: ${errorBody}`);
        throw new Error(`LLM API request failed: ${response.status} ${response.statusText} - ${errorBody}`);
      }

      const completion = await response.json() as ChatCompletionResponse;

      if (completion.choices && completion.choices.length > 0 && completion.choices[0].message) {
        const llmResponse = completion.choices[0].message.content.trim();
        // Add to cache
        if (this.cacheMaxSize > 0 && this.cache.size >= this.cacheMaxSize) {
            // Evict oldest entry (Map preserves insertion order)
            const oldestKey = this.cache.keys().next().value;
            this.cache.delete(oldestKey);
            console.log(`LLMCommunication: Cache full (max: ${this.cacheMaxSize}). Evicted oldest entry for key ${oldestKey.substring(0,10)}...`);
        }
        if (this.cacheMaxSize > 0) {
            this.cache.set(cacheKey, llmResponse);
            console.log(`LLMCommunication: Stored response in cache for key ${cacheKey.substring(0,10)}...`);
        }
        return llmResponse;
      } else {
        console.error("LLM response format unexpected or empty:", completion);
        throw new Error("LLM response format unexpected or empty.");
      }
    } catch (error) {
      console.error(`Error sending message to LLM: ${error}`);
      throw error;
    }
  }
}
