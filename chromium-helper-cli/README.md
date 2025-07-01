<div align="center">

![Chromium Helper Logo](logo.png)

</div>

# Chromium Helper CLI

A powerful command-line tool for searching and exploring Chromium and PDFium source code using Google's official APIs. Features comprehensive Gerrit integration, issue tracking, and support for both Chromium and PDFium projects.

## ✨ Features

- **🔍 Advanced Code Search** - Search Chromium and PDFium codebases with powerful syntax
- **🔧 Complete Gerrit Integration** - View CLs, comments, diffs, and file content for both projects
- **🤖 Try-Bot Status** - View LUCI try-bot results for Chromium and PDFium CLs
- **🐛 Issue Tracking** - Search and view Chromium issues with detailed information
- **📊 PDFium Support** - Full support for PDFium Gerrit operations and code search
- **🎨 Multiple Output Formats** - JSON, table, and plain text formats for different use cases
- **⚡ Fast & Reliable** - Uses official Google APIs for real-time data
- **🌐 Direct Links** - Every result includes clickable URLs to view code online
- **🤖 AI-Friendly** - Perfect for integration with AI systems, shell scripts, and automation

## 🚀 Quick Start

```bash
# Option 1: Use instantly (no installation needed!)
npx chromium-helper search "LOG(INFO)" --limit 5
npx chromium-helper gerrit status 6624568
npx chromium-helper issues search "memory leak" --limit 10

# Option 2: Install globally for short 'ch' alias
npm install -g chromium-helper

# Then use with short commands
ch search "memory leak" --case-sensitive --format json
ch gerrit status 6624568
ch pdfium status 130850
```

### 🤖 AI Assistant Integration

Works with any AI coding assistant (Claude, Cursor, Gemini, etc.):

```bash
# Tell your AI: "Run npx ch --ai to learn about chromium-helper"
npx ch --ai
```

![AI Assistant Demo](screenshot.png)

The AI will learn all commands and help you explore Chromium's codebase!

## 📦 Installation

### Option 1: Instant Usage with npx (Recommended)
**No installation required!** Just run any command:
```bash
npx chromium-helper search "Browser::Create" --format json
npx chromium-helper gerrit status 6624568
npx chromium-helper issues search "security" --limit 20
```

### Option 2: Global Installation 
For faster startup and short 'ch' alias:
```bash
npm install -g chromium-helper
# Now available as 'chromium-helper' and 'ch'
```

### Option 3: From Source
```bash
git clone https://github.com/hjanuschka/chromium-helper.git
cd chromium-helper/chromium-helper-cli
npm install && npm run build
npm link  # Optional: Make globally available
```

## 📖 Commands

### `search` - Search Chromium Source Code
Search for code patterns in the Chromium codebase.

```bash
ch search <query> [options]

# Aliases: s

Options:
  -c, --case-sensitive          Case sensitive search
  -l, --language <lang>         Filter by programming language (cpp, javascript, python, etc.)
  -p, --file-pattern <pattern>  File pattern filter (*.cc, *.h, chrome/browser/*, etc.)
  -t, --type <type>             Search type: content|function|class|symbol|comment
  --exclude-comments            Exclude comments from search results
  --limit <number>              Maximum number of results (default: 20)
```

**Examples:**
```bash
# Basic text search
ch search "LOG(INFO)"

# Function search
ch search "CreateWindow" --type function

# Class search in C++ headers  
ch search "Browser" --type class --file-pattern "*.h"

# Search excluding comments
ch search "TODO" --exclude-comments

# Language-specific search
ch search "addEventListener" --language javascript
```

### `symbol` - Find Symbol Definitions and Usage
Find where symbols (functions, classes, variables) are defined and used.

```bash
ch symbol <symbol> [options]

# Aliases: sym

Options:
  -f, --file <path>  File path context for symbol resolution
```

**Examples:**
```bash
# Find Browser symbol
ch symbol "Browser"

# Find with file context
ch symbol "CreateWindow" --file "chrome/browser/ui/browser.cc"
```

### `file` - Get File Content
Fetch the content of any file from Chromium source.

```bash
ch file <path> [options]

# Aliases: f

Options:
  -s, --start <line>  Starting line number
  -e, --end <line>    Ending line number
```

**Examples:**
```bash
# Get entire file
ch file "base/logging.h"

# Get specific line range
ch file "chrome/browser/ui/browser.h" --start 100 --end 200

# Get from line 50 to end
ch file "content/browser/browser_context.h" --start 50
```

### `owners` - Find OWNERS Files
Find OWNERS files for a given file path to identify code reviewers.

```bash
ch owners <path>

# Aliases: own
```

**Examples:**
```bash
# Find owners for a specific file
ch owners "chrome/browser/ui/browser.cc"

# Find owners for a directory
ch owners "third_party/blink/renderer/"
```

### `commits` - Search Commit History
Search commit messages and metadata in the Chromium repository.

```bash
ch commits <query> [options]

# Aliases: cm

Options:
  -a, --author <author>    Filter by author name or email
  --since <date>           Commits after date (YYYY-MM-DD)
  --until <date>           Commits before date (YYYY-MM-DD)
  --limit <number>         Maximum number of results (default: 20)
```

**Examples:**
```bash
# Search commit messages
ch commits "password manager"

# Search by author
ch commits "security fix" --author "chrome-security"

# Search in date range
ch commits "memory leak" --since "2023-01-01" --until "2023-12-31"
```

### `gerrit` - Gerrit Code Review Operations
Work with Chromium Gerrit code reviews.

```bash
ch gerrit <command> [options]

# Aliases: gr

Commands:
  status <cl>                Get CL status and test results
  comments <cl> [options]    Get CL review comments
  diff <cl> [options]        Get CL diff/changes
  file <cl> <path> [options] Get file content from CL patchset
  bots <cl> [options]        Get try-bot status for CL
```

**Examples:**
```bash
# Get CL status
ch gerrit status 6624568

# Get review comments
ch gerrit comments 6624568 --format json

# Get diff for specific file
ch gerrit diff 6624568 --file "base/logging.cc"

# Get file content from patchset
ch gerrit file 6624568 "base/logging.cc" --patchset 3

# Get try-bot status
ch gerrit bots 6624568
ch gerrit bots 6624568 --failed-only
```

### `pdfium` - PDFium Gerrit Operations
Work with PDFium Gerrit code reviews.

```bash
ch pdfium <command> [options]

# Aliases: pdf

Commands:
  status <cl>                Get PDFium CL status and test results
  comments <cl> [options]    Get PDFium CL review comments
  diff <cl> [options]        Get PDFium CL diff/changes
  file <cl> <path> [options] Get file content from PDFium CL patchset
  bots <cl> [options]        Get try-bot status for PDFium CL
```

**Examples:**
```bash
# Get PDFium CL status
ch pdfium status 130850

# Get PDFium review comments
ch pdfium comments 130850 --format json

# View PDFium file changes
ch pdfium diff 130850 --file "fpdfsdk/fpdf_view.cpp"

# Get PDFium file content
ch pdfium file 130850 "fpdfsdk/fpdf_view.cpp" --patchset 9

# Get PDFium try-bot status
ch pdfium bots 130850
ch pdfium bots 130850 --failed-only
```

### `issues` - Chromium Issue Operations
Search and view Chromium issues and bugs.

```bash
ch issues <command> [options]

# Aliases: bugs

Commands:
  get <id>                   Get specific issue details
  search <query> [options]   Search for issues
```

**Examples:**
```bash
# Search for issues
ch issues search "memory leak" --limit 10
ch issues search "pkasting" --start 20

# Get specific issue details
ch issues get 1493929
```

### `issue` - Get Chromium Issue Details
Get information about Chromium bugs and feature requests.

```bash
ch issue <id>

# Aliases: bug
```

**Examples:**
```bash
# Get issue details
ch issue 422768753

# Using full URL
ch issue "https://issues.chromium.org/issues/422768753"
```

## 🎨 Output Formats

Control output format with the global `--format` option:

### Plain Text (Default)
```bash
ch search "LOG(INFO)" --format plain
```
Human-readable format with colors and formatting.

### JSON
```bash
ch search "LOG(INFO)" --format json
```
Structured JSON for programmatic processing and AI systems.

### Table
```bash
ch search "LOG(INFO)" --format table
```
Tabular format for easy reading and comparison.

## ⚙️ Configuration

### Environment Variables
```bash
# Set custom API key
export CHROMIUM_SEARCH_API_KEY=your_api_key_here

# Disable colors
export NO_COLOR=1
```

### Config File
Create `~/.ch.json` or `.ch.json` in your project:

```json
{
  "apiKey": "your_api_key_here",
  "outputFormat": "json",
  "defaultLimit": 50
}
```

### Configuration Commands
```bash
# Show current configuration
ch config --show

# Set API key (future feature)
ch config --set-api-key "your_key"
```

## 🤖 AI and Shell Script Integration

Perfect for AI systems and shell scripts:

```bash
#!/bin/bash

# Search for security-related code
RESULTS=$(ch search "crypto" --language cpp --format json --limit 10)

# Process results with jq
echo "$RESULTS" | jq '.[] | select(.file | contains("security")) | .url'

# Find all Browser class definitions
ch symbol "Browser" --format json | jq '.classResults[].url'

# Get file content for analysis
ch file "base/security/security_context.h" --format json | \
  jq -r '.content' | head -20
```

## 📋 Use Cases

### For Developers
- **Code Discovery**: Find examples of how to use specific APIs
- **Architecture Understanding**: Explore class hierarchies and dependencies
- **Code Review**: Understand context around changes
- **Bug Investigation**: Search for related code patterns

### For AI Systems
- **Code Analysis**: Extract structured information about Chromium codebase
- **Documentation Generation**: Gather examples and usage patterns
- **Refactoring Assistance**: Find all usages of symbols before changes
- **Learning**: Understand large codebase patterns and conventions

### For Automation
- **CI/CD Integration**: Validate code patterns and standards
- **Monitoring**: Track usage of deprecated APIs
- **Documentation**: Generate up-to-date code examples
- **Security Audits**: Search for security-sensitive code patterns

## 🔍 Advanced Search Techniques

### Code Search Syntax
The tool supports Google CodeSearch syntax:

```bash
# Search specific function definitions
ch search "function:CreateWindow"

# Search class definitions
ch search "class:Browser"

# Search symbols (excludes comments/strings)
ch search "symbol:WebContents"

# Case-sensitive search
ch search "case:yes LOG"

# Language and file filters
ch search "lang:cpp file:*.h virtual"
```

### Complex Queries
```bash
# Find all virtual destructors in headers
ch search "virtual ~" --file-pattern "*.h" --language cpp

# Search for TODO comments in browser code
ch search "TODO" --type comment --file-pattern "chrome/browser/*"

# Find memory management patterns
ch search "std::unique_ptr" --language cpp --exclude-comments
```

## 🚀 Performance Tips

- Use `--limit` to control result count for faster responses
- Use `--file-pattern` to narrow search scope
- Use `--language` to filter by programming language
- Use `--format json` for faster parsing in scripts
- Cache results in shell scripts to avoid repeated API calls

## 🛠️ Development

```bash
# Clone and setup
git clone https://github.com/hjanuschka/ch-cli.git
cd ch-cli
npm install

# Development with watch mode
npm run dev

# Build
npm run build

# Test locally
node dist/index.js --help
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make your changes and add tests
4. Commit: `git commit -am 'Add new feature'`
5. Push: `git push origin feature/new-feature`
6. Create a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Related

- [Chromium Code Search](https://source.chromium.org) - Official web interface
- [Chromium Development](https://www.chromium.org/developers/) - Developer documentation
- [Gerrit Code Review](https://chromium-review.googlesource.com/) - Code review system

## 📞 Support

- [GitHub Issues](https://github.com/hjanuschka/ch-cli/issues) - Bug reports and feature requests
- [GitHub Discussions](https://github.com/hjanuschka/ch-cli/discussions) - Questions and community

---

## 🤖 CH Agent System (Experimental)

The `ch` CLI includes an experimental AI Agent system designed to assist with security analysis and codebase understanding for Chromium. This system is activated by running the `ch agent` command (or `npx chromium-helper agent`).

### Agent Configuration (`ch-agent-config.json`)

The agent system can be configured via a `ch-agent-config.json` file placed in the root directory where you run `chromium-helper-cli`. If this file is not found, default settings will be used.

**Example `ch-agent-config.json`:**
```json
{
  "llm": {
    "ollamaModel": "llama3",
    "ollamaBaseUrl": "http://localhost:11434",
    "cacheMaxSize": 100,
    "defaultTemperature": 0.7,
    "defaultMaxTokens": 1500
  },
  "proactiveBugFinder": {
    "filesPerCycle": 3,
    "heuristicKeywords": [
      "mojo",
      "IPC_MESSAGE_HANDLER",
      "RuntimeEnabledFeatures",
      "unsafe_raw_ptr",
      "reinterpret_cast"
    ],
    "sensitivePathPatterns": [
      "third_party/blink/renderer/core/",
      "content/browser/",
      "services/network/",
      "components/security_interstitials/",
      "net/"
    ],
    "prioritizationScore": {
      "pathMatch": 5,
      "keywordInFile": 3,
      "recentClMention": 2
    }
  },
  "bugPatternAnalysis": {
    "commitsPerCycle": 2
  },
  "codebaseUnderstanding": {
    "filesPerModuleCycle": 3,
    "maxModuleInsights": 20
  }
}
```

**Configuration Options:**

*   **`llm`**: Settings for Large Language Model communication.
    *   `ollamaModel`: (Default: "llama3") Specifies the Ollama model to use.
    *   `ollamaBaseUrl`: (Default: "http://localhost:11434") Base URL for the Ollama API.
    *   `cacheMaxSize`: (Default: 100) Maximum number of LLM responses to keep in the in-memory cache. Set to 0 to disable.
    *   `defaultTemperature`: (Default: 0.7) Default sampling temperature for LLM.
    *   `defaultMaxTokens`: (Default: 1500) Default maximum tokens for LLM responses.
*   **`proactiveBugFinder`**: Settings for the Proactive Bug Finder agent.
    *   `filesPerCycle`: (Default: 3) Number of files to analyze in each of its analysis cycles.
    *   `heuristicKeywords`: List of keywords used to initially find potentially interesting files.
    *   `sensitivePathPatterns`: List of file path patterns considered sensitive for prioritization.
    *   `prioritizationScore`: Weights for different heuristics when selecting files for analysis.
        *   `pathMatch`: Score for matching a sensitive path.
        *   `keywordInFile`: Score for file path containing a heuristic keyword.
        *   `recentClMention`: Score for file being mentioned in recent CL/issue activity.
        *   `sensitivePathRecentCommitScore`: Score for file found in a recent commit to a sensitive path.
    *   `maxProcessedFileHistory`: (Default: 100) Maximum number of file paths PBF remembers as processed to avoid re-analyzing in general sweeps.
*   **`bugPatternAnalysis`**: Settings for the Bug Pattern Analysis agent.
    *   `commitsPerCycle`: (Default: 2) Number of commits to analyze in each pattern extraction cycle.
    *   `targetIssueSeverities`: (Default: `["S0", "S1"]`) Array of issue severities (e.g., "S0", "S1") to target when searching for issues. If empty or omitted, may use broader keyword search.
    *   `maxProcessedHistorySize`: (Default: 200) Maximum number of commit IDs and issue IDs BPA remembers as processed.
*   **`codebaseUnderstanding`**: Settings for the Codebase Understanding agent.
    *   `filesPerModuleCycle`: (Default: 3) Number of files to analyze within a module during its analysis cycle.
    *   `maxModuleInsights`: (Default: 20) Maximum number of module insights to retain in the shared context.
    *   `maxProcessedModuleHistory`: (Default: 50) Maximum number of module paths CUA remembers as analyzed for its autonomous cycle.

### Agent Workflows

The agent system supports workflows that orchestrate multiple agents and LLM calls for complex tasks. You can list available workflows and run them:

*   `!workflows`: Lists all registered workflows.
*   `!workflow <workflow-id> [json-parameters]`: Runs a specific workflow.
    *   Example: `!workflow basic-cl-audit {"clNumber": "1234567"}`
    *   Example: `!workflow targeted-file-audit {"filePath": "path/to/your/file.cc"}`

Currently available example workflows:
*   **`basic-cl-audit`**: Performs a quick audit of a Chromium CL (status, diff summary, brief LLM review).
*   **`targeted-file-audit`**: Performs a more detailed security analysis of a specific file (context gathering, vulnerability scan, pattern matching, report synthesis).

---

**Made with ❤️ for the Chromium developer community**