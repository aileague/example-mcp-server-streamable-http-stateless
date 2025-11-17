/**
 * @file src/types.ts
 * @description Data contracts for the stateless MCP server.
 * This file contains all Zod schemas, constants, and TypeScript type definitions.
 * It is designed to be free of runtime logic, making it a stable dependency
 * for the rest of the application.
 *
 * EDUCATIONAL PURPOSE: Separating data contracts from business logic promotes
 * maintainability, testability, and reusability. This file serves as the
 * single source of truth for all data structures used throughout the application.
 */

import { z } from 'zod';

/**
 * Pre-compiled Zod schemas for all tool and prompt inputs.
 *
 * BEST PRACTICE: Defining schemas in a central location ensures consistency
 * and reusability. Compiling them once at module load (as happens here)
 * avoids the performance overhead of recreating them on every request.
 *
 * The `.describe()` method is crucial for self-documenting code and can be
 * used by AI clients to understand parameter purposes. Each description
 * becomes part of the tool's interface contract.
 *
 * STATELESS CONSIDERATION: These schemas define the input contracts for
 * stateless operations. They should not reference any persistent state
 * or session-specific data.
 */
export const schemas = {
  /**
   * Schema for the core calculator tool.
   * Demonstrates proper parameter validation with optional streaming support.
   */
  calculate: z.object({
    a: z.number().describe('First operand for the calculation'),
    b: z.number().describe('Second operand for the calculation'),
    op: z
      .enum(['add', 'subtract', 'multiply', 'divide'])
      .describe('Arithmetic operation to perform'),
    stream: z.boolean().optional().describe('Stream intermediate result chunks'),
    precision: z.number().default(2).describe('Number of decimal places for result (default: 2)'),
  }),

  /**
   * Schema for the optional sample tool (enabled via environment variable).
   * Demonstrates dynamic tool registration based on configuration.
   */
  sampleTool: z.object({
    value: z.string().describe('Value to be prefixed and returned'),
  }),

  /**
   * Schema for mathematical formula operations.
   * Used by multiple tools that deal with formula explanations and problem solving.
   */
  solveFormula: z.object({
    problem: z.string().describe('The mathematical problem to solve'),
    formula: z.string().describe('The formula to explain'),
    query: z.string().describe('The calculation query'),
  }),

  /**
   * Schema for calculation explanation prompts.
   * Demonstrates how prompts can accept different complexity levels.
   */
  explainCalculation: z.object({
    calculation: z.string().describe('The calculation to explain'),
    level: z.enum(['basic', 'intermediate', 'advanced']).optional(),
  }),

  /**
   * Schema for practice problem generation.
   * Shows how to handle optional parameters with sensible defaults.
   */
  generateProblems: z.object({
    topic: z.string().describe('The mathematical topic'),
    difficulty: z.enum(['easy', 'medium', 'hard']).optional(),
    count: z.string().optional().describe('Number of problems (1-10)'),
  }),

  /**
   * Schema for the interactive tutoring prompt.
   * Demonstrates adaptive learning interfaces in MCP tools.
   */
  calculatorTutor: z.object({
    topic: z.string().optional().describe('Specific topic to focus on'),
    studentLevel: z.enum(['beginner', 'intermediate', 'advanced']).optional(),
  }),
} as const; // 'as const' provides stricter TypeScript typing and prevents mutation

/**
 * Application-wide constants.
 *
 * BEST PRACTICE: Using a constants object avoids "magic strings/numbers"
 * in the codebase, making it easier to maintain and understand. All values
 * that are fixed and used in multiple places should be defined here.
 *
 * ARCHITECTURE NOTE: These constants are designed for a stateless server
 * where each request is independent. Values like timeouts and limits
 * are per-request, not per-session.
 */
export const CONSTANTS = {
  /**
   * HTTP-related constants for server configuration and response handling.
   * These values are tuned for production workloads with proper security.
   */
  HTTP: {
    /** Maximum request body size to prevent memory exhaustion attacks */
    MAX_REQUEST_SIZE: 1048576, // 1MB - reasonable for JSON-RPC payloads
    /** Express JSON parser limit (should match MAX_REQUEST_SIZE) */
    JSON_LIMIT: '1mb',
    /** HTTP Keep-Alive timeout for connection reuse optimization */
    KEEP_ALIVE_TIMEOUT: 5, // seconds
    /** Maximum requests per Keep-Alive connection */
    KEEP_ALIVE_MAX: 1000,
    /** CORS preflight cache duration for performance */
    PREFLIGHT_CACHE: 86400, // 24 hours in seconds
  },

  /**
   * Standard JSON-RPC 2.0 error codes for protocol compliance.
   * These ensure our server responds with spec-compliant error messages.
   */
  ERRORS: {
    /** Internal error (-32603): Server-side processing error */
    INTERNAL: -32603,
    /** Server error (-32000 to -32099): Implementation-defined server errors */
    SERVER_ERROR: -32000,
    /** Invalid params (-32602): Invalid method parameters */
    INVALID_PARAMS: -32602,
    /** Method not found (-32601): Custom extension for resource not found */
    NOT_FOUND: -32004,
  },

  /**
   * HTTP status codes used throughout the application.
   * Properly chosen status codes improve API usability and debugging.
   */
  STATUS: {
    /** 204: No Content - successful request with no response body */
    NO_CONTENT: 204,
    /** 405: Method Not Allowed - HTTP method not supported for endpoint */
    METHOD_NOT_ALLOWED: 405,
    /** 406: Not Acceptable - client Accept header cannot be satisfied */
    NOT_ACCEPTABLE: 406,
    /** 413: Payload Too Large - request body exceeds size limits */
    REQUEST_TOO_LARGE: 413,
    /** 415: Unsupported Media Type - Content-Type not supported */
    UNSUPPORTED_MEDIA_TYPE: 415,
    /** 500: Internal Server Error - unexpected server error */
    INTERNAL_SERVER_ERROR: 500,
  },

  /**
   * Timing-related constants for controlling operation flow.
   * These values balance user experience with server performance.
   */
  TIMING: {
    /** Delay between progress notification updates (milliseconds) */
    PROGRESS_DELAY_MS: 200, // 200ms provides smooth progress without overwhelming the client
  },
} as const; // Immutable constant object

/**
 * TypeScript interface for our simple, in-memory metrics collector.
 * Defines the shape of the data used for monitoring server performance.
 *
 * PRODUCTION NOTE: In a real production environment, you would typically
 * use a more sophisticated metrics library (like prom-client) with proper
 * aggregation, persistence, and thread safety. This simple implementation
 * is sufficient for educational purposes and basic monitoring.
 *
 * STATELESS CONSIDERATION: These metrics are process-global, not per-request.
 * In a truly stateless environment, metrics would be sent to an external
 * system (like Prometheus) rather than accumulated in memory.
 */
export type Metrics = {
  /** Array of request duration measurements in milliseconds */
  requestDuration: number[];
  /** Map of tool names to their execution time measurements */
  toolExecutionTime: Map<string, number[]>;
};

/**
 * Type utility for extracting the shape of our schemas.
 * This allows other parts of the application to reference the validated
 * input types without duplicating the schema definitions.
 *
 * USAGE EXAMPLE:
 * type CalculateInput = z.infer<typeof schemas.calculate>;
 */
export type SchemaInput<T extends keyof typeof schemas> = z.infer<(typeof schemas)[T]>;

/**
 * Configuration interface for the server.
 * Defines the shape of environment-based configuration options.
 *
 * BEST PRACTICE: Explicitly typing configuration prevents runtime errors
 * and makes the expected environment variables self-documenting.
 */
export type ServerConfig = {
  /** Port number for the HTTP server */
  port: number;
  /** CORS origin policy (use specific origins in production) */
  corsOrigin: string;
  /** Whether to collect and expose metrics */
  enableMetrics: boolean;
  /** Logging level for controlling output verbosity */
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  /** Maximum requests per IP address in the rate limit window */
  rateLimitMax: number;
  /** Rate limiting time window in milliseconds */
  rateLimitWindow: number;
  /** Allowed hosts for DNS rebinding protection */
  allowedHosts: string[];
  /** Whether to enable DNS rebinding protection */
  enableDnsRebindingProtection: boolean;
};

/**
 * Type definition for structured log entries.
 * Ensures consistent logging format across the application.
 *
 * OBSERVABILITY: Structured logging is essential for production systems.
 * This type ensures all log entries have the required fields for proper
 * aggregation and analysis in log management systems.
 */
export type LogEntry = {
  /** ISO 8601 timestamp of the log entry */
  timestamp: string;
  /** Log level (debug, info, warn, error) */
  level: string;
  /** Human-readable log message */
  message: string;
  /** Contextual data (request ID, user ID, etc.) */
  context: Record<string, unknown>;
  /** Additional structured data */
  [key: string]: unknown;
};
