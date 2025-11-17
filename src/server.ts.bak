/**
 * @file src/server.ts
 * @description Stateless Production MCP Server - Runtime Logic
 *
 * This file contains the complete runtime implementation of a stateless MCP server
 * designed for production use. It demonstrates the "fresh instance per request"
 * architecture pattern that enables infinite horizontal scaling.
 *
 * EDUCATIONAL MISSION:
 * This server exemplifies production-ready patterns for building MCP servers:
 * - True stateless design (no shared state between requests)
 * - Security-first architecture (rate limiting, DNS rebinding protection)
 * - Clean separation of concerns (data contracts in types.ts, logic here)
 * - Production observability (structured logging, metrics, health checks)
 * - Graceful error handling and resource cleanup
 *
 * ARCHITECTURE OVERVIEW:
 * Every HTTP request creates fresh McpServer and Transport instances,
 * processes the request through the SDK, then destroys the instances.
 * This pattern eliminates state-related bugs and enables serverless deployment.
 *
 * ERROR HANDLING PHILOSOPHY:
 * This server adheres to a strict "fail-fast" and "no-leaks" error policy.
 * 1. **SPECIFIC ERRORS:** All predictable operational errors (e.g., bad input)
 *    throw a protocol-compliant `McpError` with a specific `ErrorCode`. Generic
 *    `new Error()` is strictly avoided in tool logic.
 * 2. **INPUT VALIDATION:** Invalid parameters are caught early and result in an
 *    `McpError` with code `ErrorCode.InvalidParams`, providing actionable
 *    feedback to the client.
 * 3. **LEAK PREVENTION:** A top-level `try...catch` block in the main request
 *    handler (`handleMCPRequest`) catches all unexpected exceptions. It logs the
 *    full error internally for debugging but returns a generic, safe
 *    `ErrorCode.InternalError` to the client, preventing stack trace and
 *    implementation detail leaks.
 * 4. **PREDICTABILITY:** The client can reliably expect JSON-RPC 2.0-compliant
 *    error objects for any failed request, enabling robust client-side error handling.
 */

// Core Node.js and Express framework imports
import express, { type Request, type Response, type NextFunction } from 'express';
import type { URL } from 'url';
import { randomUUID } from 'crypto';

// Model Context Protocol SDK imports
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  type CallToolResult,
  type GetPromptResult,
  type ReadResourceResult,
  McpError,
  ErrorCode,
} from '@modelcontextprotocol/sdk/types.js';

// Third-party middleware for security and functionality
import cors from 'cors';
import rateLimit from 'express-rate-limit';

// Internal data contracts and type definitions
import { schemas, CONSTANTS, type Metrics, type ServerConfig, type SchemaInput } from './types.js';

/**
 * In-memory metrics collector.
 *
 * EDUCATIONAL NOTE: For this educational example, we use a simple global object.
 * In a high-concurrency production environment, you would use a dedicated,
 * more robust metrics library (like `prom-client`) to handle aggregation and
 * prevent potential race conditions.
 *
 * STATELESS CONSIDERATION: These metrics are process-global, not per-request.
 * Each request contributes to the global metrics, but no request depends on
 * metrics from previous requests. This maintains our stateless guarantee.
 *
 * PRODUCTION ALTERNATIVE: In a truly distributed system, metrics would be
 * sent to an external monitoring system (Prometheus, DataDog, etc.) rather
 * than accumulated in local memory.
 */
const metrics: Metrics = {
  requestDuration: [],
  toolExecutionTime: new Map(),
};

/**
 * Helper function to calculate percentiles efficiently.
 *
 * PERFORMANCE NOTE: This creates a sorted copy of the array for each calculation.
 * In a high-throughput production system, you would use a more efficient
 * percentile calculation algorithm (like t-digest) or a pre-sorted data structure.
 *
 * @param arr Array of numeric values to calculate percentile from
 * @param p Percentile value (0.0 to 1.0, where 0.5 = 50th percentile)
 * @returns The calculated percentile value
 */
function percentile(arr: number[], p: number): number {
  if (arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const index = Math.ceil((sorted.length - 1) * p);
  return sorted[index] ?? 0;
}

/**
 * Validates and returns a log level from an environment variable string.
 * @param level The raw string from `process.env`.
 * @returns A valid log level or 'info' as a default.
 */
function getLogLevel(level?: string): ServerConfig['logLevel'] {
  const validLevels: ServerConfig['logLevel'][] = ['debug', 'info', 'warn', 'error'];
  if (level && validLevels.includes(level as ServerConfig['logLevel'])) {
    return level as ServerConfig['logLevel'];
  }
  return 'info'; // Sensible default
}

/**
 * A simple structured logger class designed for stateless applications.
 *
 * DESIGN PHILOSOPHY: In a stateless architecture, each request is isolated.
 * This logger is designed to be instantiated with request-specific context
 * (like a request ID) for each request, ensuring that log entries can be
 * properly correlated across distributed systems.
 *
 * EDUCATIONAL FOCUS: This implementation prioritizes clarity and simplicity
 * over micro-optimizations. Modern JavaScript engines are highly optimized
 * for these patterns, making complex object pooling unnecessary.
 *
 * PRODUCTION CONSIDERATIONS:
 * - In high-throughput systems, consider using a dedicated logging library
 * - For distributed systems, integrate with centralized logging (ELK, Splunk)
 * - Add log level filtering based on environment configuration
 * - Consider async logging for better performance
 */
class Logger {
  /**
   * Contextual data attached to all log entries from this logger instance.
   * Common context includes: requestId, userId, operationId, etc.
   */
  context: Record<string, unknown> = {};

  /**
   * Creates a new logger instance with additional context.
   *
   * IMMUTABILITY PRINCIPLE: Instead of modifying the existing logger,
   * we create a new instance. This prevents accidental context pollution
   * between different parts of the application.
   *
   * @param ctx Additional context to merge with existing context
   * @returns A new Logger instance with merged context
   */
  withContext(ctx: Record<string, unknown>): Logger {
    const newLogger = new Logger();
    newLogger.context = { ...this.context, ...ctx };
    return newLogger;
  }

  /**
   * Core logging method that formats and outputs log entries.
   *
   * STRUCTURED LOGGING: All logs are JSON-formatted for easy parsing
   * by log aggregation systems. The consistent structure enables
   * powerful querying and analysis in production environments.
   *
   * @param level Log level (debug, info, warn, error)
   * @param message Human-readable log message
   * @param data Additional structured data to include
   */
  log(level: string, message: string, data?: Record<string, unknown>): void {
    const logEntry = {
      timestamp: new Date().toISOString(), // ISO 8601 for consistency
      level,
      message,
      context: this.context, // Request-specific context
      ...data, // Additional data merged at top level
    };
    // In production, you might send this to a logging service instead of console
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(logEntry));
  }

  /**
   * Convenience methods for different log levels.
   * These provide a clean, semantic API for different types of log entries.
   */
  debug(message: string, data?: Record<string, unknown>): void {
    this.log('debug', message, data);
  }

  info(message: string, data?: Record<string, unknown>): void {
    this.log('info', message, data);
  }

  warn(message: string, data?: Record<string, unknown>): void {
    this.log('warn', message, data);
  }

  error(message: string, data?: Record<string, unknown>): void {
    this.log('error', message, data);
  }
}

/**
 * Global logger instance for application-level logging.
 *
 * USAGE PATTERN: This global logger is used for application lifecycle events
 * (startup, shutdown, configuration). For request-specific logging, create
 * new logger instances with request context using logger.withContext().
 *
 * STATELESS PRINCIPLE: This global logger has no request-specific state,
 * making it safe to use across all requests without creating coupling.
 */
const logger = new Logger();

/**
 * @summary Creates a fresh, isolated McpServer instance for a single request.
 * @remarks
 * This factory function is the heart of the stateless architecture. It encapsulates
 * the creation and configuration of the server, including all tools and resources.
 * By creating a new instance per request, we ensure there is no state bleed, and
 * any errors are contained entirely within the request's lifecycle.
 *
 * DESIGN PATTERN: This factory function encapsulates the creation and configuration
 * of an MCP server instance. In our stateless architecture, this function is called
 * for *every* single HTTP request to create a fresh, isolated server instance.
 *
 * STATELESS GUARANTEE: Each server instance created by this factory:
 * - Has no knowledge of previous requests
 * - Shares no state with other instances
 * - Can be safely destroyed after request completion
 * - Enables infinite horizontal scaling
 *
 * ERROR HANDLING INTEGRATION: All tools registered by this factory implement
 * the server's error handling philosophy:
 * - Predictable errors throw McpError with specific ErrorCode values
 * - Input validation errors use ErrorCode.InvalidParams
 * - Unexpected errors are caught by the request handler's safety net
 *
 * EDUCATIONAL VALUE: This function demonstrates how to properly register:
 * - Tools (executable functions with parameter validation)
 * - Resources (data endpoints with URI patterns)
 * - Prompts (LLM conversation starters with context)
 *
 * @returns A new, fully configured `McpServer` instance.
 */
function createMCPServer(): McpServer {
  /**
   * Create the core MCP server instance with metadata and capabilities.
   *
   * SERVER IDENTITY: The name and version should be consistent across all
   * instances to maintain client compatibility. Clients may cache this
   * information for the duration of their connection.
   *
   * CAPABILITIES: We declare empty capability objects that will be populated
   * as we register tools, resources, and prompts below.
   */
  const server = new McpServer(
    {
      name: 'calculator-learning-demo-stateless',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {}, // Will be populated by server.tool() calls
        resources: {}, // Will be populated by server.resource() calls
        prompts: {}, // Will be populated by server.prompt() calls
        logging: {}, // Basic logging capability for debugging
      },
    },
  );

  /**
   * OPTIONAL SAMPLE TOOL (Educational)
   *
   * DYNAMIC REGISTRATION: This tool is only registered if the SAMPLE_TOOL_NAME
   * environment variable is set. This demonstrates how to conditionally add
   * tools based on configuration, which is useful for:
   * - A/B testing new features
   * - Environment-specific tools (dev vs prod)
   * - Feature flags and gradual rollouts
   *
   * EDUCATIONAL PURPOSE: This simple echo tool helps developers understand
   * the basic structure of MCP tool implementations without complex logic.
   */
  if (process.env['SAMPLE_TOOL_NAME']) {
    const sampleToolName = process.env['SAMPLE_TOOL_NAME'];
    server.tool(
      sampleToolName, // Tool name from environment variable
      'Educational echo tool for learning MCP concepts', // Human-readable description
      schemas.sampleTool.shape, // Zod schema for parameter validation
      async ({ value }): Promise<CallToolResult> => ({
        content: [
          {
            type: 'text',
            text: `test string print: ${value}`,
          },
        ],
      }),
    );
  }

  /**
   * CORE CALCULATOR TOOL
   *
   * This is the primary tool that demonstrates stateless operation patterns.
   * Every execution is completely independent and self-contained.
   */
  server.tool(
    'calculate', // Tool identifier (must be unique)
    'Performs arithmetic calculations in stateless mode', // Human-readable description
    schemas.calculate.shape, // Parameter schema for validation
    async ({ a, b, op, stream, precision = 2 }, { sendNotification }): Promise<CallToolResult> => {
      // STEP 1: INITIALIZE REQUEST CONTEXT
      // Start timing for performance metrics
      const toolStartTime = Date.now();

      // CRITICAL: Generate a unique ID for this specific tool execution
      // This enables correlation of logs, progress notifications, and metrics
      const requestId = randomUUID();

      // BEST PRACTICE: Create a request-scoped logger with context
      // This ensures all log entries from this execution can be correlated
      const requestLogger = logger.withContext({
        tool: 'calculate',
        requestId,
        operation: op,
      });

      requestLogger.info('Stateless calculation requested', { a, b, op });

      let result: number;
      const steps: string[] = []; // Track calculation steps for educational output

      try {
        // STEP 2: INPUT VALIDATION AND LOGGING
        steps.push(`Input: ${a} ${op} ${b}`);

        // STEP 3: OPTIONAL PROGRESS NOTIFICATIONS
        // Stream intermediate results if requested by the client
        // This demonstrates how to provide real-time feedback for long operations
        if (stream) {
          await sendNotification({
            method: 'notifications/progress',
            params: {
              progressToken: requestId, // Client can correlate this with their request
              progress: 0.1, // 10% complete
              total: 1.0, // Total progress range
            },
          });
        }

        // STEP 4: CORE BUSINESS LOGIC
        // Perform the requested arithmetic operation
        switch (op) {
          case 'add':
            result = a + b;
            steps.push(`Addition: ${a} + ${b} = ${result}`);
            break;
          case 'subtract':
            result = a - b;
            steps.push(`Subtraction: ${a} - ${b} = ${result}`);
            break;
          case 'multiply':
            result = a * b;
            steps.push(`Multiplication: ${a} × ${b} = ${result}`);
            break;
          case 'divide':
            // INPUT VALIDATION: This is a predictable, client-fixable error.
            if (b === 0) {
              requestLogger.error('Division by zero attempted, returning InvalidParams error', {
                a,
                b,
              });
              // CAVEAT: We throw a specific McpError here. This is crucial.
              // It sends a structured, protocol-compliant error to the client,
              // allowing it to programmatically understand that the input parameters
              // were invalid, rather than receiving a generic server failure.
              throw new McpError(ErrorCode.InvalidParams, 'Division by zero is not allowed.');
            }
            result = a / b;
            steps.push(`Division: ${a} ÷ ${b} = ${result}`);
            break;
        }

        // STEP 5: RESULT FORMATTING
        // Apply precision rounding and add to steps
        result = parseFloat(result.toFixed(precision));
        steps.push(`Final result (${precision} decimal places): ${result}`);

        // STEP 6: COMPLETION NOTIFICATION
        // Signal completion to streaming clients
        if (stream) {
          await sendNotification({
            method: 'notifications/progress',
            params: {
              progressToken: requestId,
              progress: 1.0, // 100% complete
              total: 1.0,
            },
          });
        }

        // STEP 7: METRICS COLLECTION
        // Record execution time for monitoring and performance analysis
        const toolDuration = Date.now() - toolStartTime;
        if (!metrics.toolExecutionTime.has('calculate')) {
          metrics.toolExecutionTime.set('calculate', []);
        }
        const toolMetrics = metrics.toolExecutionTime.get('calculate')!;
        toolMetrics.push(toolDuration);

        // MEMORY MANAGEMENT: Limit metrics array size to prevent memory leaks
        if (toolMetrics.length > 1000) {
          toolMetrics.shift(); // Remove oldest measurement
        }

        // STEP 8: STRUCTURED RESPONSE
        // Return the result in MCP-compliant format with educational details
        return {
          content: [
            {
              type: 'text',
              text: `${op.toUpperCase()}: ${a} ${op === 'add' ? '+' : op === 'subtract' ? '-' : op === 'multiply' ? '×' : '÷'} ${b} = ${result}\n\nSteps:\n${steps.join('\n')}\n\nRequest ID: ${requestId}`,
            },
          ],
        };
      } catch (error) {
        // STEP 9: ERROR HANDLING
        // Log the full error details for debugging
        requestLogger.error('Calculation failed', {
          operation: op,
          inputs: { a, b },
          error: error instanceof Error ? error.message : String(error),
        });

        // Re-throw to let the framework handle the response
        throw error;
      }
    },
  );

  /**
   * PROGRESS DEMONSTRATION TOOL
   *
   * EDUCATIONAL PURPOSE: This tool demonstrates how to implement progress
   * notifications in MCP. It's particularly useful for understanding:
   * - How to send incremental progress updates
   * - Proper use of progress tokens for correlation
   * - Timing considerations for user experience
   *
   * REAL-WORLD APPLICATION: Use this pattern for any long-running operations
   * like file processing, API calls, or complex calculations.
   */
  server.tool(
    'demo_progress',
    'Demonstrates progress notifications with 5 incremental steps',
    {}, // No input parameters required
    async (_, { sendNotification }): Promise<CallToolResult> => {
      // Generate unique progress identifier
      const progressId = randomUUID();
      const progressLogger = logger.withContext({ tool: 'demo_progress', progressId });

      progressLogger.info('Progress demonstration started');

      // PROGRESS LOOP: Send 5 incremental updates
      for (let i = 1; i <= 5; i++) {
        await sendNotification({
          method: 'notifications/progress',
          params: {
            progressToken: progressId, // Consistent token for correlation
            progress: i / 5, // Fractional progress (0.2, 0.4, 0.6, 0.8, 1.0)
            total: 1.0, // Always 1.0 for percentage-based progress
          },
        });

        // TIMING: Small delay to simulate processing work
        // In real applications, this would be actual work being performed
        await new Promise((resolve) => setTimeout(resolve, CONSTANTS.TIMING.PROGRESS_DELAY_MS));
      }

      progressLogger.info('Progress demonstration completed');

      return {
        content: [
          {
            type: 'text',
            text: 'Progress demonstration completed with 5 incremental steps',
          },
        ],
      };
    },
  );

  /**
   * MATHEMATICAL CONSTANTS RESOURCE
   *
   * RESOURCE PATTERN: Resources in MCP are data endpoints that provide
   * information to AI clients. They use URI schemes to organize related data.
   *
   * STATELESS DESIGN: This resource returns the same data for every request,
   * demonstrating how stateless resources work. No matter which server instance
   * handles the request, the response is identical.
   *
   * URI SCHEME: The 'calculator://' scheme groups all calculator-related
   * resources, making them easy to discover and organize.
   */
  server.resource(
    'math-constants', // Internal resource identifier
    'calculator://constants', // Public URI pattern
    {
      name: 'Mathematical Constants',
      description: 'Provides fundamental mathematical constants pi and e',
      mimeType: 'application/json', // Declares content type for clients
    },
    async (): Promise<ReadResourceResult> => {
      // STATIC DATA: These constants never change, making them perfect
      // for stateless architectures. No database or external service needed.
      return {
        contents: [
          {
            uri: 'calculator://constants',
            mimeType: 'application/json',
            text: JSON.stringify(
              {
                pi: 3.14159, // Mathematical constant π
                e: 2.71828, // Mathematical constant e (Euler's number)
              },
              null,
              2, // Pretty-printed JSON for readability
            ),
          },
        ],
      };
    },
  );

  /**
   * CALCULATOR HISTORY RESOURCE (Stateless Limitation Demonstration)
   *
   * EDUCATIONAL NOTE: This resource demonstrates how a stateless server handles
   * requests for stateful resources. It correctly informs the client that the
   * resource is unavailable in this architecture.
   *
   * ARCHITECTURAL CHOICE: In a stateless system, we cannot maintain history
   * across requests. This is a trade-off for scalability and simplicity.
   *
   * ALTERNATIVE APPROACHES:
   * - Store history in external database (adds complexity)
   * - Use client-side storage for history
   * - Provide export/import functionality instead
   */
  server.resource(
    'calculator-history',
    'calculator://history/{id}', // URI pattern with parameter
    {
      name: 'Calculator History',
      description: 'Calculator history (not available in stateless mode)',
      mimeType: 'application/json',
    },
    async (_uri: URL): Promise<ReadResourceResult> => {
      // ARCHITECTURAL ERROR: We throw a specific, protocol-compliant error.
      // This informs the client that the requested resource is fundamentally
      // incompatible with this server's stateless design, which is more
      // informative than a generic internal error.
      throw new McpError(
        ErrorCode.MethodNotFound, // Using MethodNotFound semantically.
        'Resource requires state, which is not supported by this server.',
      );
    },
  );

  /**
   * CALCULATOR STATISTICS RESOURCE
   *
   * PROCESS-LEVEL DATA: This resource provides server process statistics.
   * Note that these are process-global, not request-specific, maintaining
   * our stateless principle while providing useful operational data.
   *
   * MONITORING UTILITY: Clients can use this resource to monitor server
   * health and performance characteristics.
   */
  server.resource(
    'calculator-stats',
    'calculator://stats',
    {
      name: 'Calculator Statistics',
      description: 'Basic server process statistics',
      mimeType: 'application/json',
    },
    async (): Promise<ReadResourceResult> => {
      // RUNTIME DATA: Calculated fresh for each request
      return {
        contents: [
          {
            uri: 'calculator://stats',
            mimeType: 'application/json',
            text: JSON.stringify(
              {
                uptimeMs: process.uptime() * 1000, // Process uptime in milliseconds
                timestamp: new Date().toISOString(), // Current timestamp
                pattern: 'stateless', // Architecture pattern identifier
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  /**
   * MATHEMATICAL FORMULA LIBRARY RESOURCE
   *
   * EDUCATIONAL CONTENT: This resource provides a curated collection of
   * mathematical formulas organized by category. It demonstrates how to
   * structure educational content in MCP resources.
   *
   * DIFFERENT URI SCHEME: Uses 'formulas://' to show how multiple URI schemes
   * can coexist in a single server, organizing different types of content.
   *
   * STATIC REFERENCE DATA: Perfect for stateless architecture since the
   * formulas don't change between requests.
   */
  server.resource(
    'formula-library',
    'formulas://library',
    {
      name: 'Mathematical Formula Library',
      description: 'Curated collection of mathematical formulas organized by category',
      mimeType: 'application/json',
    },
    async (): Promise<ReadResourceResult> => {
      // EDUCATIONAL CONTENT: Comprehensive formula reference
      // Each formula includes name, mathematical notation, and category
      return {
        contents: [
          {
            uri: 'formulas://library',
            mimeType: 'application/json',
            text: JSON.stringify(
              [
                {
                  name: 'Quadratic Formula',
                  formula: 'x = (-b ± √(b² - 4ac)) / 2a',
                  category: 'algebra',
                  description: 'Solves quadratic equations of form ax² + bx + c = 0',
                },
                {
                  name: 'Pythagorean Theorem',
                  formula: 'a² + b² = c²',
                  category: 'geometry',
                  description: 'Relates sides of a right triangle',
                },
                {
                  name: 'Distance Formula',
                  formula: 'd = √((x₂-x₁)² + (y₂-y₁)²)',
                  category: 'geometry',
                  description: 'Calculates distance between two points in 2D space',
                },
                {
                  name: 'Compound Interest',
                  formula: 'A = P(1 + r/n)^(nt)',
                  category: 'finance',
                  description: 'Calculates compound interest over time',
                },
                {
                  name: 'Area of Circle',
                  formula: 'A = πr²',
                  category: 'geometry',
                  description: 'Calculates area of a circle given radius',
                },
                {
                  name: "Euler's Identity",
                  formula: 'e^(iπ) + 1 = 0',
                  category: 'complex',
                  description: 'Beautiful equation relating fundamental constants',
                },
                {
                  name: 'Law of Sines',
                  formula: 'a/sin(A) = b/sin(B) = c/sin(C)',
                  category: 'trigonometry',
                  description: 'Relates sides and angles in any triangle',
                },
                {
                  name: 'Law of Cosines',
                  formula: 'c² = a² + b² - 2ab·cos(C)',
                  category: 'trigonometry',
                  description: 'Generalizes Pythagorean theorem for any triangle',
                },
                {
                  name: 'Binomial Theorem',
                  formula: '(x+y)^n = Σ(n,k)·x^(n-k)·y^k',
                  category: 'algebra',
                  description: 'Expands binomial expressions to any power',
                },
                {
                  name: 'Derivative Power Rule',
                  formula: 'd/dx(x^n) = n·x^(n-1)',
                  category: 'calculus',
                  description: 'Basic differentiation rule for polynomial terms',
                },
              ],
              null,
              2, // Pretty-printed for readability
            ),
          },
        ],
      };
    },
  );

  /**
   * CURRENT REQUEST INFORMATION RESOURCE
   *
   * METADATA RESOURCE: This resource provides information about the current
   * request and server instance. Each call generates fresh metadata,
   * demonstrating true stateless behavior.
   *
   * DEBUGGING UTILITY: Useful for clients to understand the server state
   * and verify stateless operation (each request gets unique metadata).
   *
   * THIRD URI SCHEME: Uses 'request://' to demonstrate organizational patterns
   * for different types of server metadata.
   */
  server.resource(
    'request-info',
    'request://current',
    {
      name: 'Current Request Information',
      description: 'Metadata about the current stateless request and server instance',
      mimeType: 'application/json',
    },
    async (): Promise<ReadResourceResult> => {
      // FRESH METADATA: Generated uniquely for each request
      const requestId = randomUUID();
      const requestLogger = logger.withContext({ resource: 'request-info', requestId });

      requestLogger.debug('Request info resource accessed');

      return {
        contents: [
          {
            uri: 'request://current',
            mimeType: 'application/json',
            text: JSON.stringify(
              {
                requestId, // Unique identifier for this resource access
                timestamp: new Date().toISOString(), // Exact access time
                serverInfo: {
                  name: 'calculator-learning-demo-stateless',
                  version: '1.0.0',
                  pattern: 'stateless', // Architecture pattern identifier
                  instanceId: randomUUID(), // Unique to this server instance
                },
                processInfo: {
                  pid: process.pid, // Process identifier
                  platform: process.platform, // Operating system
                  nodeVersion: process.version, // Node.js version
                  uptime: process.uptime(), // Process uptime in seconds
                },
                memoryUsage: process.memoryUsage(), // Current memory statistics
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  /**
   * EXPLANATION PROMPT (Educational AI Interaction)
   *
   * PROMPT PATTERN: Prompts in MCP are pre-built conversation starters
   * that provide context and instructions to AI language models.
   * They ensure consistent, high-quality interactions.
   *
   * ADAPTIVE COMPLEXITY: This prompt adapts its instructions based on
   * the requested difficulty level, demonstrating personalized education.
   *
   * STATELESS DESIGN: Each prompt generates independent context without
   * relying on conversation history or user session state.
   */
  server.prompt(
    'explain-calculation',
    'Generates a prompt for AI to explain mathematical calculations step by step',
    schemas.explainCalculation.shape,
    async ({
      calculation,
      level = 'intermediate',
    }: SchemaInput<'explainCalculation'>): Promise<GetPromptResult> => {
      // ADAPTIVE INSTRUCTION: Tailor the prompt complexity to user level
      const levelInstructions = {
        basic: 'Use simple terms and break down each step clearly',
        intermediate: 'Include mathematical notation and explain properties',
        advanced: 'Discuss alternative methods, optimizations, and edge cases',
      };

      return {
        messages: [
          {
            role: 'user', // Standard chat role for AI interaction
            content: {
              type: 'text',
              text: `Please explain how to solve this calculation step by step: "${calculation}"
              
Target level: ${level}
- ${levelInstructions[level]}

Format your response with:
1. Clear numbered steps
2. Mathematical reasoning for each step
3. Final verification of the result

Make the explanation educational and easy to follow.`,
            },
          },
        ],
      };
    },
  );

  /**
   * PROBLEM GENERATION PROMPT (Educational Content Creation)
   *
   * CONTENT GENERATION: This prompt instructs AI to create practice problems
   * dynamically based on topic and difficulty parameters.
   *
   * PROGRESSIVE LEARNING: The prompt emphasizes building concepts progressively,
   * which is crucial for effective mathematics education.
   *
   * STRUCTURED OUTPUT: Requests specific formatting to ensure consistent,
   * usable educational content.
   */
  server.prompt(
    'generate-problems',
    'Creates a prompt for AI to generate practice math problems with progressive difficulty',
    schemas.generateProblems.shape,
    async ({
      topic,
      difficulty = 'medium',
      count = '5',
    }: SchemaInput<'generateProblems'>): Promise<GetPromptResult> => {
      // PARAMETER VALIDATION: Ensure reasonable problem count
      const problemCount = Math.min(parseInt(count) || 5, 10); // Max 10 problems

      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Generate ${problemCount} practice problems about "${topic}" at ${difficulty} difficulty level.

PEDAGOGICAL REQUIREMENTS:
- Problems should progressively build on concepts
- Include variety in problem types and approaches
- Ensure problems are solvable at the specified difficulty
- Make each problem educational and engaging

FORMATTING REQUIREMENTS:
- Number each problem clearly
- Provide complete problem statements
- Include an answer key with brief explanations
- Use proper mathematical notation

EXAMPLE FORMAT:
Problems:
1. [Problem statement with clear context]
2. [Problem statement building on previous concepts]
...

Answer Key:
1. [Answer with step-by-step explanation]
2. [Answer with reasoning and method]`,
            },
          },
        ],
      };
    },
  );

  /**
   * INTERACTIVE TUTORING PROMPT (Personalized Learning)
   *
   * PERSONALIZED EDUCATION: This prompt creates a personalized tutoring
   * experience that adapts to student level and specific topics.
   *
   * TOOL INTEGRATION: The prompt specifically mentions using the 'calculate'
   * tool, demonstrating how prompts can direct AI to use available tools.
   *
   * PEDAGOGICAL APPROACH: Emphasizes assessment, encouragement, and
   * practical application - key elements of effective tutoring.
   */
  server.prompt(
    'calculator-tutor',
    'Creates an interactive tutoring session prompt tailored to student level and topic',
    schemas.calculatorTutor.shape,
    async ({
      topic,
      studentLevel = 'intermediate',
    }: SchemaInput<'calculatorTutor'>): Promise<GetPromptResult> => {
      // CUSTOMIZATION: Build topic-specific context
      const topicContext = topic ? ` focusing on ${topic}` : '';

      // LEVEL-SPECIFIC GUIDANCE: Adapt tutoring approach to student level
      const levelGuidance = {
        beginner:
          'Use very simple language, concrete examples, and break down concepts into tiny steps',
        intermediate:
          'Use clear explanations with some mathematical terminology and visual examples',
        advanced:
          'Engage with complex concepts, encourage critical thinking, and explore connections',
      };

      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Act as a friendly and knowledgeable calculator tutor for a ${studentLevel}-level student${topicContext}.

TUTORING FRAMEWORK:
1. START: Begin with a warm, encouraging greeting
2. ASSESS: Ask a simple diagnostic question to gauge understanding
3. TEACH: Provide clear explanations adapted to their level
4. DEMONSTRATE: Use the 'calculate' tool to show examples
5. PRACTICE: Give them a problem to try
6. ENCOURAGE: Provide positive reinforcement throughout

LEVEL-SPECIFIC APPROACH:
- ${levelGuidance[studentLevel]}

TOOL USAGE:
- Use the 'calculate' tool to demonstrate calculations
- Show step-by-step problem solving
- Encourage the student to try calculations themselves

Be patient, encouraging, and make mathematics engaging and accessible!`,
            },
          },
        ],
      };
    },
  );

  /**
   * IMPORTANT: The server instance is now fully configured with:
   * - Tools: calculate, demo_progress, and optional sample tool
   * - Resources: constants, stats, history (404), formulas, request-info
   * - Prompts: explain-calculation, generate-problems, calculator-tutor
   *
   * ERROR HANDLING: The MCP SDK handles protocol-level errors automatically.
   * Tool-specific errors are handled within each tool implementation.
   *
   * STATELESS GUARANTEE: This server instance contains no request-specific
   * state and can be safely destroyed after handling one request.
   */
  return server;
}

/**
 * SERVER CONFIGURATION
 *
 * ENVIRONMENT-BASED CONFIG: All configuration comes from environment variables
 * with sensible defaults. This follows 12-factor app principles and makes
 * the server easy to deploy in containerized environments.
 *
 * SECURITY CONSIDERATIONS:
 * - CORS_ORIGIN should be restricted in production (not '*')
 * - Rate limiting prevents abuse and ensures fair resource usage
 * - Log level controls information disclosure
 *
 * STATELESS COMPATIBILITY: All configuration is read at startup and
 * doesn't change during request processing, maintaining stateless guarantees.
 */
const config: ServerConfig = {
  /** HTTP server port (default: 1071, not 3000, per MCP conventions) */
  port: parseInt(process.env['PORT'] ?? '1071'),

  /** CORS origin policy - MUST be restricted in production environments */
  corsOrigin: process.env['CORS_ORIGIN'] ?? '*',

  /** Whether to collect and expose performance metrics */
  enableMetrics: process.env['ENABLE_METRICS'] !== 'false',

  /** Logging verbosity level for controlling output detail */
  logLevel: getLogLevel(process.env['LOG_LEVEL']),

  /** Maximum requests per IP in the rate limiting window */
  rateLimitMax: parseInt(process.env['RATE_LIMIT_MAX'] ?? '1000'),

  /** Rate limiting time window in milliseconds (default: 15 minutes) */
  rateLimitWindow: parseInt(process.env['RATE_LIMIT_WINDOW'] ?? '900000'),
};

/**
 * EXPRESS APPLICATION FACTORY
 *
 * ARCHITECTURE OVERVIEW: This function creates and configures an Express
 * application with all necessary middleware for production use. The app
 * is stateless-ready with proper security, monitoring, and error handling.
 *
 * SECURITY LAYERS:
 * 1. CORS configuration for cross-origin requests
 * 2. Rate limiting to prevent abuse
 * 3. Request size validation to prevent memory attacks
 * 4. DNS rebinding protection (handled by MCP transport)
 *
 * MIDDLEWARE STACK:
 * 1. OPTIONS preflight handling (performance optimization)
 * 2. CORS middleware (security)
 * 3. Rate limiting (abuse prevention)
 * 4. Request size validation (security)
 * 5. JSON parsing (functionality)
 * 6. Request logging (observability)
 * 7. Route handlers (business logic)
 *
 * @returns Fully configured Express application ready for production
 */
async function createApp(): Promise<express.Application> {
  const app = express();

  /**
   * MIDDLEWARE LAYER 1: CORS PREFLIGHT OPTIMIZATION
   *
   * PERFORMANCE OPTIMIZATION: Handle OPTIONS requests immediately without
   * going through the full middleware stack. This reduces latency for
   * browser preflight requests in CORS scenarios.
   *
   * SECURITY HEADERS: Set all necessary CORS headers to enable controlled
   * cross-origin access while maintaining security boundaries.
   */
  app.options('*', (_req: Request, res: Response) => {
    // CORS headers for browser compatibility
    res.header('Access-Control-Allow-Origin', config.corsOrigin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.header(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, Accept, Mcp-Protocol-Version, Mcp-Session-Id',
    );
    res.header('Access-Control-Expose-Headers', 'Mcp-Protocol-Version');
    res.header('Access-Control-Allow-Credentials', 'true');
    // Cache preflight response for 24 hours to reduce overhead
    res.header('Access-Control-Max-Age', String(CONSTANTS.HTTP.PREFLIGHT_CACHE));
    res.sendStatus(CONSTANTS.STATUS.NO_CONTENT);
  });

  /**
   * MIDDLEWARE LAYER 2: CORS CONFIGURATION
   *
   * CROSS-ORIGIN SECURITY: Configure Cross-Origin Resource Sharing to
   * allow controlled access from web browsers while maintaining security.
   *
   * MCP-SPECIFIC HEADERS: Include MCP protocol headers in the CORS policy
   * to enable proper protocol negotiation between client and server.
   *
   * PRODUCTION WARNING: config.corsOrigin should be set to specific
   * domains in production, not '*' (wildcard).
   */
  app.use(
    cors({
      origin: config.corsOrigin, // Restrict origins in production
      methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], // Only necessary HTTP methods
      allowedHeaders: [
        'Content-Type', // For JSON payloads
        'Authorization', // For authentication (if implemented)
        'Accept', // For content negotiation
        'Mcp-Protocol-Version', // MCP protocol version negotiation
        'Mcp-Session-Id', // MCP session identification (not used in stateless mode)
      ],
      exposedHeaders: ['Mcp-Protocol-Version'], // Allow clients to read protocol version
      credentials: true, // Allow cookies/auth headers if needed
    }),
  );

  /**
   * MIDDLEWARE LAYER 3: RATE LIMITING (SECURITY)
   *
   * ABUSE PREVENTION: Limit the number of requests per IP address to prevent
   * denial-of-service attacks and ensure fair resource usage.
   *
   * MCP-COMPLIANT ERRORS: Return JSON-RPC 2.0 compliant error responses
   * when rate limits are exceeded, maintaining protocol consistency.
   *
   * TARGETED APPLICATION: Only apply rate limiting to the MCP endpoint,
   * allowing unrestricted access to health/metrics endpoints for monitoring.
   */
  const limiter = rateLimit({
    windowMs: config.rateLimitWindow, // Time window for rate limiting
    max: config.rateLimitMax, // Maximum requests per window per IP
    message: {
      jsonrpc: '2.0', // JSON-RPC 2.0 compliance
      error: {
        code: CONSTANTS.ERRORS.SERVER_ERROR, // Standard error code
        message: 'Too many requests. Please try again later.',
      },
      id: null, // No request ID available at this stage
    },
    standardHeaders: true, // Include standard rate limit headers
    legacyHeaders: false, // Don't include legacy X-RateLimit headers
  });

  // SECURITY: Apply rate limiting only to the MCP endpoint
  // Health and metrics endpoints remain unrestricted for monitoring
  app.use('/mcp', limiter);

  /**
   * MIDDLEWARE LAYER 4: REQUEST SIZE VALIDATION (SECURITY)
   *
   * MEMORY PROTECTION: Reject requests that exceed size limits before
   * parsing to prevent memory exhaustion attacks. This is a critical
   * security measure for public-facing servers.
   *
   * FAIL-FAST PRINCIPLE: Check request size immediately using the
   * Content-Length header rather than waiting for the full body to arrive.
   *
   * JSON-RPC COMPLIANCE: Return properly formatted error responses
   * that clients can parse and handle appropriately.
   */
  app.use((req: Request, res: Response, next: NextFunction) => {
    const contentLength = parseInt(req.headers['content-length'] ?? '0');

    // SECURITY CHECK: Reject oversized requests immediately
    if (contentLength > CONSTANTS.HTTP.MAX_REQUEST_SIZE) {
      res.status(CONSTANTS.STATUS.REQUEST_TOO_LARGE).json({
        jsonrpc: '2.0',
        error: {
          code: CONSTANTS.ERRORS.SERVER_ERROR,
          message: `Request too large. Maximum size: ${CONSTANTS.HTTP.MAX_REQUEST_SIZE} bytes`,
        },
        id: null, // Cannot determine request ID before parsing body
      });
      return; // Stop processing this request
    }

    // CONTINUE: Request size is acceptable, proceed to next middleware
    next();
  });

  /**
   * MIDDLEWARE LAYER 5: BODY PARSING (FUNCTIONALITY)
   *
   * JSON PARSING: Configure Express to parse JSON request bodies with
   * size limits that match our security validation above.
   *
   * URL ENCODING: Handle URL-encoded form data (though not typically
   * used in MCP, included for completeness).
   */
  app.use(express.json({ limit: CONSTANTS.HTTP.JSON_LIMIT }));
  app.use(express.urlencoded({ extended: true }));

  /**
   * MIDDLEWARE LAYER 6: REQUEST LOGGING (OBSERVABILITY)
   *
   * REQUEST CORRELATION: Generate a unique ID for each request to enable
   * log correlation across the entire request lifecycle.
   *
   * STRUCTURED LOGGING: Capture essential request metadata for debugging
   * and monitoring in production environments.
   *
   * REQUEST CONTEXT: Store the request ID in res.locals for access by
   * downstream handlers and middleware.
   */
  app.use((req: Request, res: Response, next: NextFunction) => {
    // CORRELATION: Generate unique identifier for request tracking
    const requestId = randomUUID();
    res.locals['requestId'] = requestId;

    // OBSERVABILITY: Log request details with correlation ID
    logger.withContext({ requestId }).debug('HTTP request received', {
      method: req.method,
      url: req.url,
      userAgent: req.headers['user-agent'],
      clientIp: req.ip,
      contentType: req.headers['content-type'],
    });

    // CONTINUE: Proceed to route handlers
    next();
  });

  // ==========================================
  // MCP ENDPOINTS (STATELESS PATTERN)
  // ==========================================

  /**
   * @summary The core request handler for the stateless MCP server.
   * @remarks
   * This function implements the "fresh instance per request" pattern. It is the
   * central orchestrator for every incoming MCP request. Its primary responsibilities are:
   * 1. Creating ephemeral server and transport instances.
   * 2. Delegating protocol handling to the MCP SDK.
   * 3. Ensuring resource cleanup via `res.on('close')`.
   * 4. Acting as the ultimate safety net, catching all unhandled exceptions
   *    and converting them into safe, protocol-compliant internal server errors.
   *
   * @param req The incoming Express request object.
   * @param res The outgoing Express response object.
   */
  // STATELESS ERROR FLOW (High-Level Sequence):
  // 1. HTTP Request -> Express Middleware (Rate Limit, CORS, Size Check)
  //    - On failure: Middleware sends HTTP 4xx/5xx error and stops.
  // 2. handleMCPRequest() -> Creates fresh McpServer & Transport.
  // 3. transport.handleRequest() -> SDK decodes JSON-RPC message.
  //    - On decode failure: SDK throws -> results in JSON-RPC ParseError.
  // 4. SDK routes to Tool/Resource handler (e.g., 'calculate').
  //    - On unknown method: Results in JSON-RPC MethodNotFound.
  // 5. Tool Handler Logic ('calculate') executes.
  //    - On invalid input: Throws McpError(ErrorCode.InvalidParams).
  //    - On unexpected failure: Throws generic Error.
  // 6. Final `catch` block in handleMCPRequest() catches any unhandled throws.
  //    - On failure: Wraps error into McpError(ErrorCode.InternalError) to prevent leaks.
  const handleMCPRequest = async (req: Request, res: Response) => {
    const startTime = Date.now();
    const requestId = res.locals['requestId'] as string;
    const requestLogger = logger.withContext({ requestId });

    // Connection pooling hints (Carmack optimization: reuse TCP connections)
    res.setHeader('Connection', 'keep-alive');
    res.setHeader(
      'Keep-Alive',
      `timeout=${CONSTANTS.HTTP.KEEP_ALIVE_TIMEOUT}, max=${CONSTANTS.HTTP.KEEP_ALIVE_MAX}`,
    );

    try {
      requestLogger.debug('Received MCP request', {
        method: req.method,
        headers: req.headers,
        contentType: req.headers['content-type'],
        body: req.method === 'POST' ? req.body : 'N/A (GET request)',
      });

      // Create fresh server instance for this request
      const server = createMCPServer();
      requestLogger.info('Created fresh MCP server instance');

      // Create stateless transport with security features
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined, // Stateless mode
        enableDnsRebindingProtection: true,
        allowedHosts: ['localhost:' + config.port, '127.0.0.1:' + config.port],
        ...(config.corsOrigin !== '*' && { allowedOrigins: [config.corsOrigin] }),
      });

      // Transport handles its own error logging

      await server.connect(transport);

      // Let the transport handle both POST commands and GET SSE streams
      await transport.handleRequest(req, res, req.method === 'POST' ? req.body : undefined);

      res.on('close', () => {
        requestLogger.debug('Request closed, cleaning up transport and server');

        // Collect request duration metric
        const duration = Date.now() - startTime;
        metrics.requestDuration.push(duration);
        // Keep only last 1000 measurements to avoid memory leak
        if (metrics.requestDuration.length > 1000) {
          metrics.requestDuration.shift();
        }

        void transport.close();
        void server.close();
      });
    } catch (error) {
      // SAFETY NET: This is the last line of defense. It catches any error
      // that was not handled within a tool or by the SDK itself.
      requestLogger.error('Unhandled error in MCP request handler', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });

      if (!res.headersSent) {
        // SECURITY CRITICAL: We return a generic, protocol-compliant error.
        // The detailed error is logged internally for debugging, but we NEVER
        // leak the original error message or stack trace to the client. This
        // prevents revealing internal implementation details.
        res.status(CONSTANTS.STATUS.INTERNAL_SERVER_ERROR).json({
          jsonrpc: '2.0',
          error: {
            code: ErrorCode.InternalError,
            message: 'An internal server error occurred.',
          },
          id: (req.body as { id?: unknown } | undefined)?.id ?? null,
        });
      }
    }

    /**
     * END OF STATELESS REQUEST LIFECYCLE
     *
     * At this point, the request has been fully processed using the
     * "fresh instance per request" pattern. The cleanup logic registered
     * above will be triggered when the response stream closes, ensuring
     * proper resource management and maintaining our stateless guarantee.
     */
  };

  /**
   * MCP ROUTE HANDLERS - STATELESS OPERATIONS
   *
   * These routes implement the MCP protocol endpoints using our stateless
   * request handler. Each request gets fresh server instances regardless
   * of the HTTP method used.
   */

  /**
   * POST /mcp - MCP COMMAND EXECUTION
   *
   * Handles MCP protocol commands like:
   * - tools/call: Execute registered tools
   * - resources/read: Fetch resource data
   * - prompts/get: Retrieve prompt templates
   * - resources/list: List available resources
   * - tools/list: List available tools
   * - prompts/list: List available prompts
   */
  app.post('/mcp', handleMCPRequest);

  /**
   * GET /mcp - SERVER-SENT EVENTS STREAM
   *
   * Establishes real-time communication channel for:
   * - Progress notifications during long-running operations
   * - Tool execution status updates
   * - Real-time data streaming
   *
   * STATELESS SSE: Even streaming connections use fresh instances
   * and maintain no server-side state between events.
   */
  app.get('/mcp', handleMCPRequest);

  /**
   * DELETE /mcp - UNSUPPORTED IN STATELESS MODE
   *
   * Educational endpoint that explains why DELETE operations don't make
   * sense in a stateless architecture. In stateful servers, DELETE might
   * close sessions, but we have no sessions to close.
   */
  app.delete('/mcp', (_req: Request, res: Response) => {
    res.writeHead(CONSTANTS.STATUS.METHOD_NOT_ALLOWED, { Allow: 'POST, GET' }).end(
      JSON.stringify({
        jsonrpc: '2.0',
        error: {
          code: CONSTANTS.ERRORS.SERVER_ERROR,
          message: 'Method not allowed. No sessions to delete in stateless mode.',
        },
        id: null,
      }),
    );
  });

  // ==========================================
  // OPERATIONAL MONITORING ENDPOINTS
  // ==========================================

  /**
   * These endpoints provide operational visibility into the server without
   * rate limiting or authentication. They are essential for:
   * - Load balancer health checks
   * - Container orchestration (Kubernetes, Docker Swarm)
   * - Application performance monitoring (APM)
   * - Infrastructure monitoring (Prometheus, DataDog)
   */

  /**
   * GET /health - BASIC HEALTH CHECK
   *
   * LOAD BALANCER INTEGRATION: Simple endpoint that returns 200 OK when
   * the server is running. Load balancers use this to determine if the
   * server instance should receive traffic.
   *
   * KUBERNETES READINESS: Can be used as a readiness probe to signal
   * when the container is ready to accept requests.
   *
   * MINIMAL OVERHEAD: Fast response with essential status information.
   */
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy', // Simple binary health indicator
      timestamp: new Date().toISOString(), // Current server time
      pattern: 'stateless', // Architecture pattern identifier
      uptime: process.uptime(), // Process uptime in seconds
      memory: process.memoryUsage(), // Current memory usage statistics
      version: '1.0.0', // Application version for deployment tracking
    });
  });

  /**
   * GET /health/detailed - COMPREHENSIVE HEALTH INFORMATION
   *
   * DEEP MONITORING: Provides detailed system and application metrics
   * for comprehensive health assessment and debugging.
   *
   * DEPLOYMENT VALIDATION: Helps verify that the server is configured
   * correctly after deployment with all expected characteristics.
   *
   * STATELESS VERIFICATION: The characteristics section explicitly
   * documents the stateless nature of this server instance.
   */
  app.get('/health/detailed', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      pattern: 'stateless',

      /**
       * SYSTEM METRICS: Low-level process and runtime information
       * useful for capacity planning and performance analysis.
       */
      system: {
        uptime: process.uptime(), // Process uptime in seconds
        memory: process.memoryUsage(), // Detailed memory usage breakdown
        cpu: process.cpuUsage(), // CPU usage statistics
        platform: process.platform, // Operating system platform
        nodeVersion: process.version, // Node.js version for compatibility tracking
      },

      /**
       * APPLICATION METRICS: High-level application configuration
       * and version information for deployment tracking.
       */
      application: {
        version: '1.0.0',
        config: {
          port: config.port, // Server port configuration
          rateLimitMax: config.rateLimitMax, // Rate limiting configuration
        },
      },

      /**
       * ARCHITECTURAL CHARACTERISTICS: Explicit documentation of
       * the server's operational model for client understanding.
       */
      characteristics: {
        persistent: false, // No data persists between requests
        sessionManagement: false, // No session state maintained
        resumability: false, // Operations cannot be resumed
        memoryModel: 'ephemeral', // All state is temporary
        sseSupport: true, // Server-Sent Events are supported
        scalingModel: 'horizontal', // Can scale infinitely across instances
        deploymentReady: 'serverless', // Compatible with serverless platforms
      },
    });
  });

  /**
   * GET /metrics - PROMETHEUS-COMPATIBLE METRICS
   *
   * OBSERVABILITY: Provides performance and operational metrics in
   * Prometheus exposition format for integration with monitoring systems.
   *
   * METRICS CATEGORIES:
   * 1. System Metrics: Memory usage, uptime
   * 2. Application Metrics: Request durations, tool performance
   * 3. Architectural Metrics: Server pattern identification
   *
   * PRODUCTION INTEGRATION: Can be scraped by Prometheus, DataDog,
   * or other monitoring systems for alerting and dashboards.
   */
  app.get('/metrics', (_req: Request, res: Response) => {
    /**
     * REQUEST PERFORMANCE ANALYSIS: Calculate percentiles from collected
     * request duration data to understand performance characteristics.
     */
    const reqP50 = percentile(metrics.requestDuration, 0.5); // Median response time
    const reqP95 = percentile(metrics.requestDuration, 0.95); // 95th percentile (outlier detection)
    const reqP99 = percentile(metrics.requestDuration, 0.99); // 99th percentile (tail latency)

    /**
     * TOOL PERFORMANCE ANALYSIS: Generate metrics for each tool that has
     * been executed, providing insights into individual tool performance.
     */
    let toolMetricsText = '';
    for (const [toolName, durations] of metrics.toolExecutionTime) {
      const p50 = percentile(durations, 0.5);
      const p95 = percentile(durations, 0.95);
      const p99 = percentile(durations, 0.99);

      // PROMETHEUS FORMAT: Standard exposition format with help and type declarations
      toolMetricsText += `
# HELP mcp_tool_duration_milliseconds Tool execution duration histogram
# TYPE mcp_tool_duration_milliseconds histogram
mcp_tool_duration_milliseconds{tool="${toolName}",quantile="0.5"} ${p50}
mcp_tool_duration_milliseconds{tool="${toolName}",quantile="0.95"} ${p95}
mcp_tool_duration_milliseconds{tool="${toolName}",quantile="0.99"} ${p99}
mcp_tool_duration_milliseconds_count{tool="${toolName}"} ${durations.length}
`;
    }

    /**
     * CONTENT TYPE: Set proper content type for Prometheus scraping.
     * The text/plain content type is required by the Prometheus specification.
     */
    res.set('Content-Type', 'text/plain');

    /**
     * METRICS EXPOSITION: Return all metrics in Prometheus format.
     * Each metric includes HELP text (description) and TYPE (metric type).
     */
    res.send(`# HELP nodejs_memory_usage_bytes Node.js memory usage by type
# TYPE nodejs_memory_usage_bytes gauge
nodejs_memory_usage_bytes{type="rss"} ${process.memoryUsage().rss}
nodejs_memory_usage_bytes{type="heapTotal"} ${process.memoryUsage().heapTotal}
nodejs_memory_usage_bytes{type="heapUsed"} ${process.memoryUsage().heapUsed}

# HELP nodejs_uptime_seconds Node.js process uptime in seconds
# TYPE nodejs_uptime_seconds counter
nodejs_uptime_seconds ${process.uptime()}

# HELP mcp_pattern MCP server architecture pattern identifier
# TYPE mcp_pattern gauge
mcp_pattern{type="stateless"} 1

# HELP mcp_request_duration_milliseconds HTTP request duration histogram
# TYPE mcp_request_duration_milliseconds histogram
mcp_request_duration_milliseconds{quantile="0.5"} ${reqP50}
mcp_request_duration_milliseconds{quantile="0.95"} ${reqP95}
mcp_request_duration_milliseconds{quantile="0.99"} ${reqP99}
mcp_request_duration_milliseconds_count ${metrics.requestDuration.length}
${toolMetricsText}`);
  });

  return app;
}

/**
 * SERVER INITIALIZATION & LIFECYCLE MANAGEMENT
 *
 * This function orchestrates the complete server startup process including:
 * - Express application creation and configuration
 * - HTTP server binding and startup
 * - Graceful shutdown handling for production deployments
 * - Error handling and process management
 *
 * PRODUCTION READINESS: Implements proper lifecycle management patterns
 * for containerized and cloud deployments.
 */
async function startServer(): Promise<void> {
  try {
    /**
     * APPLICATION CREATION: Build the complete Express application
     * with all middleware, routes, and security configurations.
     */
    const app = await createApp();

    /**
     * SERVER BINDING: Start the HTTP server and bind to the configured port.
     * The callback executes once the server is successfully listening.
     */
    const server = app.listen(config.port, () => {
      /**
       * STARTUP CONFIRMATION: Log successful startup with key configuration
       * details for operational visibility.
       */
      logger.info('Stateless MCP Server successfully started', {
        port: config.port,
        corsOrigin: config.corsOrigin,
        rateLimitMax: config.rateLimitMax,
        pattern: 'stateless',
        nodeVersion: process.version,
        platform: process.platform,
        pid: process.pid,
      });

      /**
       * ENDPOINT DOCUMENTATION: Log all available endpoints for easy
       * reference during development and operational troubleshooting.
       */
      logger.info('Available endpoints', {
        mcp: {
          postCommand: `POST http://localhost:${config.port}/mcp`,
          getSseStream: `GET http://localhost:${config.port}/mcp`,
          deleteNotSupported: `DELETE http://localhost:${config.port}/mcp (405 Method Not Allowed)`,
        },
        monitoring: {
          basicHealth: `GET http://localhost:${config.port}/health`,
          detailedHealth: `GET http://localhost:${config.port}/health/detailed`,
          prometheusMetrics: `GET http://localhost:${config.port}/metrics`,
        },
        characteristics: {
          sseSupport: true, // Real-time streaming supported
          sessionManagement: false, // No sessions in stateless mode
          pattern: 'stateless', // Architecture pattern
          scalingModel: 'horizontal', // Can scale infinitely
          deploymentModel: 'serverless-ready', // Works in serverless environments
        },
      });
    });

    /**
     * GRACEFUL SHUTDOWN IMPLEMENTATION
     *
     * PRODUCTION REQUIREMENT: Proper shutdown handling is essential for:
     * - Zero-downtime deployments
     * - Container orchestration (Kubernetes)
     * - Load balancer health checks
     * - In-flight request completion
     *
     * SIGNAL HANDLING: Responds to standard UNIX signals for shutdown.
     */
    const shutdown = async () => {
      logger.info('Graceful shutdown initiated', {
        reason: 'shutdown_signal_received',
        pattern: 'stateless',
      });

      /**
       * SERVER CLOSURE: Stop accepting new connections and close existing ones.
       * The callback executes once all connections are closed.
       */
      server.close(() => {
        logger.info('HTTP server closed successfully', {
          finalUptime: process.uptime(),
          pattern: 'stateless',
          cleanShutdown: true,
        });

        /**
         * PROCESS TERMINATION: Exit with success code after clean shutdown.
         * In containerized environments, this signals successful shutdown.
         */
        process.exit(0);
      });
    };

    /**
     * SIGNAL HANDLERS: Register shutdown handlers for common termination signals.
     *
     * SIGTERM: Standard termination signal from process managers
     * SIGINT: Interrupt signal (Ctrl+C) for development
     */
    process.on('SIGTERM', () => void shutdown()); // Kubernetes, Docker, systemd
    process.on('SIGINT', () => void shutdown()); // Ctrl+C in development
  } catch (error) {
    /**
     * STARTUP FAILURE HANDLING: Log detailed error information and exit
     * with non-zero code to signal failure to process managers.
     */
    logger.error('Server startup failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      pattern: 'stateless',
      startupFailed: true,
    });

    /**
     * FAILURE EXIT: Exit with error code 1 to signal startup failure
     * to container orchestrators and process managers.
     */
    process.exit(1);
  }
}

/**
 * AUTOMATIC STARTUP LOGIC
 *
 * CONDITIONAL EXECUTION: Only start the server automatically when:
 * - Not in test environment (prevents automatic startup during testing)
 * - Running directly (not being imported as a module)
 *
 * IMPORT VS EXECUTION: This pattern allows the module to be imported
 * for testing or embedding in other applications without automatically
 * starting the server.
 */
if (!process.env['NODE_ENV'] || process.env['NODE_ENV'] !== 'test') {
  startServer().catch((error) => {
    /**
     * CATASTROPHIC FAILURE: If startup fails and we can't even log properly,
     * fall back to console.error and exit immediately.
     */
    logger.error('Catastrophic server startup failure', {
      error: error instanceof Error ? error.message : String(error),
      pattern: 'stateless',
      catastrophicFailure: true,
    });
    process.exit(1);
  });
}

/**
 * MODULE EXPORTS
 *
 * FACTORY PATTERN: Export factory functions rather than instances to
 * maintain the stateless principle and enable testing/embedding.
 *
 * EXPORTED FUNCTIONS:
 * - createMCPServer: Creates fresh MCP server instances
 * - createApp: Creates configured Express applications
 * - startServer: Complete server startup orchestration
 *
 * USAGE PATTERNS:
 * - Testing: Import and call functions to create isolated instances
 * - Embedding: Import and integrate into larger applications
 * - Serverless: Export handlers that call these functions per request
 */
export {
  createMCPServer, // MCP server factory for stateless instances
  createApp, // Express app factory with all middleware
  startServer, // Complete startup orchestration
};
