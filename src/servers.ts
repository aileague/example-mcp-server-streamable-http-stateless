/**
 * @file src/server.ts
 * @description Stateless Production MCP Server - Runtime Logic
 */

// 首先加载环境变量 - 必须在其他导入之前
import dotenv from 'dotenv';
dotenv.config();

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
 */
const metrics: Metrics = {
  requestDuration: [],
  toolExecutionTime: new Map(),
};

/**
 * Helper function to calculate percentiles efficiently.
 */
function percentile(arr: number[], p: number): number {
  if (arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const index = Math.ceil((sorted.length - 1) * p);
  return sorted[index] ?? 0;
}

/**
 * Validates and returns a log level from an environment variable string.
 */
function getLogLevel(level?: string): ServerConfig['logLevel'] {
  const validLevels: ServerConfig['logLevel'][] = ['debug', 'info', 'warn', 'error'];
  if (level && validLevels.includes(level as ServerConfig['logLevel'])) {
    return level as ServerConfig['logLevel'];
  }
  return 'info';
}

/**
 * Parse allowed hosts from environment variable with proper error handling
 */
function getAllowedHosts(hostsString?: string, defaultPort: string = '1071'): string[] {
  console.log('ALLOWED_HOSTS environment variable:', hostsString);
  
  if (!hostsString || hostsString.trim() === '') {
    const defaultHosts = [
      `localhost:${defaultPort}`,
      `127.0.0.1:${defaultPort}`
    ];
    console.log('Using default allowed hosts:', defaultHosts);
    return defaultHosts;
  }
  
  try {
    const hosts = hostsString.split(',').map(host => {
      const trimmedHost = host.trim();
      // If host doesn't have a port, add the default port
      if (!trimmedHost.includes(':')) {
        return `${trimmedHost}:${defaultPort}`;
      }
      return trimmedHost;
    });
    
    console.log('Parsed allowed hosts:', hosts);
    return hosts;
  } catch (error) {
    console.error('Error parsing ALLOWED_HOSTS, using defaults:', error);
    return [
      `localhost:${defaultPort}`,
      `127.0.0.1:${defaultPort}`
    ];
  }
}

/**
 * A simple structured logger class designed for stateless applications.
 */
class Logger {
  context: Record<string, unknown> = {};

  withContext(ctx: Record<string, unknown>): Logger {
    const newLogger = new Logger();
    newLogger.context = { ...this.context, ...ctx };
    return newLogger;
  }

  log(level: string, message: string, data?: Record<string, unknown>): void {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      context: this.context,
      ...data,
    };
    console.log(JSON.stringify(logEntry));
  }

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
 */
const logger = new Logger();

/**
 * @summary Creates a fresh, isolated McpServer instance for a single request.
 */
function createMCPServer(): McpServer {
  const server = new McpServer(
    {
      name: 'calculator-learning-demo-stateless',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
        logging: {},
      },
    },
  );

  /**
   * OPTIONAL SAMPLE TOOL (Educational)
   */
  if (process.env['SAMPLE_TOOL_NAME']) {
    const sampleToolName = process.env['SAMPLE_TOOL_NAME'];
    server.tool(
      sampleToolName,
      'Educational echo tool for learning MCP concepts',
      schemas.sampleTool.shape,
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
   */
  server.tool(
    'calculate',
    'Performs arithmetic calculations in stateless mode',
    schemas.calculate.shape,
    async ({ a, b, op, stream, precision = 2 }, { sendNotification }): Promise<CallToolResult> => {
      const toolStartTime = Date.now();
      const requestId = randomUUID();
      const requestLogger = logger.withContext({
        tool: 'calculate',
        requestId,
        operation: op,
      });

      requestLogger.info('Stateless calculation requested', { a, b, op });

      let result: number;
      const steps: string[] = [];

      try {
        steps.push(`Input: ${a} ${op} ${b}`);

        if (stream) {
          await sendNotification({
            method: 'notifications/progress',
            params: {
              progressToken: requestId,
              progress: 0.1,
              total: 1.0,
            },
          });
        }

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
            if (b === 0) {
              requestLogger.error('Division by zero attempted, returning InvalidParams error', {
                a,
                b,
              });
              throw new McpError(ErrorCode.InvalidParams, 'Division by zero is not allowed.');
            }
            result = a / b;
            steps.push(`Division: ${a} ÷ ${b} = ${result}`);
            break;
          default:
            throw new McpError(ErrorCode.InvalidParams, `Unknown operation: ${op}`);
        }

        result = parseFloat(result.toFixed(precision));
        steps.push(`Final result (${precision} decimal places): ${result}`);

        if (stream) {
          await sendNotification({
            method: 'notifications/progress',
            params: {
              progressToken: requestId,
              progress: 1.0,
              total: 1.0,
            },
          });
        }

        const toolDuration = Date.now() - toolStartTime;
        if (!metrics.toolExecutionTime.has('calculate')) {
          metrics.toolExecutionTime.set('calculate', []);
        }
        const toolMetrics = metrics.toolExecutionTime.get('calculate')!;
        toolMetrics.push(toolDuration);

        if (toolMetrics.length > 1000) {
          toolMetrics.shift();
        }

        return {
          content: [
            {
              type: 'text',
              text: `${op.toUpperCase()}: ${a} ${op === 'add' ? '+' : op === 'subtract' ? '-' : op === 'multiply' ? '×' : '÷'} ${b} = ${result}\n\nSteps:\n${steps.join('\n')}\n\nRequest ID: ${requestId}`,
            },
          ],
        };
      } catch (error) {
        requestLogger.error('Calculation failed', {
          operation: op,
          inputs: { a, b },
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    },
  );

  /**
   * PROGRESS DEMONSTRATION TOOL
   */
  server.tool(
    'demo_progress',
    'Demonstrates progress notifications with 5 incremental steps',
    {},
    async (_, { sendNotification }): Promise<CallToolResult> => {
      const progressId = randomUUID();
      const progressLogger = logger.withContext({ tool: 'demo_progress', progressId });

      progressLogger.info('Progress demonstration started');

      for (let i = 1; i <= 5; i++) {
        await sendNotification({
          method: 'notifications/progress',
          params: {
            progressToken: progressId,
            progress: i / 5,
            total: 1.0,
          },
        });

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
   */
  server.resource(
    'math-constants',
    'calculator://constants',
    {
      name: 'Mathematical Constants',
      description: 'Provides fundamental mathematical constants pi and e',
      mimeType: 'application/json',
    },
    async (): Promise<ReadResourceResult> => {
      return {
        contents: [
          {
            uri: 'calculator://constants',
            mimeType: 'application/json',
            text: JSON.stringify(
              {
                pi: 3.14159,
                e: 2.71828,
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
   * CALCULATOR HISTORY RESOURCE (Stateless Limitation Demonstration)
   */
  server.resource(
    'calculator-history',
    'calculator://history/{id}',
    {
      name: 'Calculator History',
      description: 'Calculator history (not available in stateless mode)',
      mimeType: 'application/json',
    },
    async (_uri: URL): Promise<ReadResourceResult> => {
      throw new McpError(
        ErrorCode.MethodNotFound,
        'Resource requires state, which is not supported by this server.',
      );
    },
  );

  /**
   * CALCULATOR STATISTICS RESOURCE
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
      return {
        contents: [
          {
            uri: 'calculator://stats',
            mimeType: 'application/json',
            text: JSON.stringify(
              {
                uptimeMs: process.uptime() * 1000,
                timestamp: new Date().toISOString(),
                pattern: 'stateless',
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
              2,
            ),
          },
        ],
      };
    },
  );

  /**
   * CURRENT REQUEST INFORMATION RESOURCE
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
                requestId,
                timestamp: new Date().toISOString(),
                serverInfo: {
                  name: 'calculator-learning-demo-stateless',
                  version: '1.0.0',
                  pattern: 'stateless',
                  instanceId: randomUUID(),
                },
                processInfo: {
                  pid: process.pid,
                  platform: process.platform,
                  nodeVersion: process.version,
                  uptime: process.uptime(),
                },
                memoryUsage: process.memoryUsage(),
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
   */
  server.prompt(
    'explain-calculation',
    'Generates a prompt for AI to explain mathematical calculations step by step',
    schemas.explainCalculation.shape,
    async ({
      calculation,
      level = 'intermediate',
    }: SchemaInput<'explainCalculation'>): Promise<GetPromptResult> => {
      const levelInstructions = {
        basic: 'Use simple terms and break down each step clearly',
        intermediate: 'Include mathematical notation and explain properties',
        advanced: 'Discuss alternative methods, optimizations, and edge cases',
      };

      return {
        messages: [
          {
            role: 'user',
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
      const problemCount = Math.min(parseInt(count) || 5, 10);

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
   */
  server.prompt(
    'calculator-tutor',
    'Creates an interactive tutoring session prompt tailored to student level and topic',
    schemas.calculatorTutor.shape,
    async ({
      topic,
      studentLevel = 'intermediate',
    }: SchemaInput<'calculatorTutor'>): Promise<GetPromptResult> => {
      const topicContext = topic ? ` focusing on ${topic}` : '';

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

  return server;
}

/**
 * SERVER CONFIGURATION
 * 
 * 现在从环境变量中正确读取配置，包含详细的调试信息
 */
const config: ServerConfig = {
  port: parseInt(process.env['PORT'] ?? '1071'),
  corsOrigin: process.env['CORS_ORIGIN'] ?? '*',
  enableMetrics: process.env['ENABLE_METRICS'] !== 'false',
  logLevel: getLogLevel(process.env['LOG_LEVEL']),
  rateLimitMax: parseInt(process.env['RATE_LIMIT_MAX'] ?? '1000'),
  rateLimitWindow: parseInt(process.env['RATE_LIMIT_WINDOW'] ?? '900000'),
  allowedHosts: getAllowedHosts(process.env['ALLOWED_HOSTS'], process.env['PORT'] ?? '1071'),
  enableDnsRebindingProtection: process.env['ENABLE_DNS_REBINDING_PROTECTION'] !== 'false',
};

// 记录配置加载情况用于调试
console.log('Loaded configuration:', {
  port: config.port,
  corsOrigin: config.corsOrigin,
  allowedHosts: config.allowedHosts,
  enableDnsRebindingProtection: config.enableDnsRebindingProtection,
  rateLimitMax: config.rateLimitMax,
  logLevel: config.logLevel
});

/**
 * EXPRESS APPLICATION FACTORY
 */
async function createApp(): Promise<express.Application> {
  const app = express();

  /**
   * MIDDLEWARE LAYER 1: CORS PREFLIGHT OPTIMIZATION
   */
  app.options('*', (_req: Request, res: Response) => {
    res.header('Access-Control-Allow-Origin', config.corsOrigin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.header(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, Accept, Mcp-Protocol-Version, Mcp-Session-Id',
    );
    res.header('Access-Control-Expose-Headers', 'Mcp-Protocol-Version');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', String(CONSTANTS.HTTP.PREFLIGHT_CACHE));
    res.sendStatus(CONSTANTS.STATUS.NO_CONTENT);
  });

  /**
   * MIDDLEWARE LAYER 2: CORS CONFIGURATION
   */
  app.use(
    cors({
      origin: config.corsOrigin,
      methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'Accept',
        'Mcp-Protocol-Version',
        'Mcp-Session-Id',
      ],
      exposedHeaders: ['Mcp-Protocol-Version'],
      credentials: true,
    }),
  );

  /**
   * MIDDLEWARE LAYER 3: RATE LIMITING (SECURITY)
   */
  const limiter = rateLimit({
    windowMs: config.rateLimitWindow,
    max: config.rateLimitMax,
    message: {
      jsonrpc: '2.0',
      error: {
        code: CONSTANTS.ERRORS.SERVER_ERROR,
        message: 'Too many requests. Please try again later.',
      },
      id: null,
    },
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.use('/mcp', limiter);

  /**
   * MIDDLEWARE LAYER 4: REQUEST SIZE VALIDATION (SECURITY)
   */
  app.use((req: Request, res: Response, next: NextFunction) => {
    const contentLength = parseInt(req.headers['content-length'] ?? '0');

    if (contentLength > CONSTANTS.HTTP.MAX_REQUEST_SIZE) {
      res.status(CONSTANTS.STATUS.REQUEST_TOO_LARGE).json({
        jsonrpc: '2.0',
        error: {
          code: CONSTANTS.ERRORS.SERVER_ERROR,
          message: `Request too large. Maximum size: ${CONSTANTS.HTTP.MAX_REQUEST_SIZE} bytes`,
        },
        id: null,
      });
      return;
    }

    next();
  });

  /**
   * MIDDLEWARE LAYER 5: BODY PARSING (FUNCTIONALITY)
   */
  app.use(express.json({ limit: CONSTANTS.HTTP.JSON_LIMIT }));
  app.use(express.urlencoded({ extended: true }));

  /**
   * MIDDLEWARE LAYER 6: REQUEST LOGGING (OBSERVABILITY)
   */
  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId = randomUUID();
    res.locals['requestId'] = requestId;

    logger.withContext({ requestId }).debug('HTTP request received', {
      method: req.method,
      url: req.url,
      userAgent: req.headers['user-agent'],
      clientIp: req.ip,
      contentType: req.headers['content-type'],
    });

    next();
  });

  // ==========================================
  // MCP ENDPOINTS (STATELESS PATTERN)
  // ==========================================

  const handleMCPRequest = async (req: Request, res: Response) => {
    const startTime = Date.now();
    const requestId = res.locals['requestId'] as string;
    const requestLogger = logger.withContext({ requestId });

    // Connection pooling hints
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
        enableDnsRebindingProtection: config.enableDnsRebindingProtection,
        allowedHosts: config.allowedHosts,
        ...(config.corsOrigin !== '*' && { allowedOrigins: [config.corsOrigin] }),
      });

      await server.connect(transport);

      // Let the transport handle both POST commands and GET SSE streams
      await transport.handleRequest(req, res, req.method === 'POST' ? req.body : undefined);

      res.on('close', () => {
        requestLogger.debug('Request closed, cleaning up transport and server');

        // Collect request duration metric
        const duration = Date.now() - startTime;
        metrics.requestDuration.push(duration);
        if (metrics.requestDuration.length > 1000) {
          metrics.requestDuration.shift();
        }

        void transport.close();
        void server.close();
      });
    } catch (error) {
      requestLogger.error('Unhandled error in MCP request handler', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });

      if (!res.headersSent) {
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
  };

  /**
   * MCP ROUTE HANDLERS
   */
  app.post('/mcp', handleMCPRequest);
  app.get('/mcp', handleMCPRequest);

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
   * GET /health - BASIC HEALTH CHECK
   */
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      pattern: 'stateless',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: '1.0.0',
      config: {
        allowedHosts: config.allowedHosts,
        dnsRebindingProtection: config.enableDnsRebindingProtection,
      }
    });
  });

  /**
   * GET /health/detailed - COMPREHENSIVE HEALTH INFORMATION
   */
  app.get('/health/detailed', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      pattern: 'stateless',

      system: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        platform: process.platform,
        nodeVersion: process.version,
      },

      application: {
        version: '1.0.0',
        config: {
          port: config.port,
          rateLimitMax: config.rateLimitMax,
          allowedHosts: config.allowedHosts,
          enableDnsRebindingProtection: config.enableDnsRebindingProtection,
        },
      },

      characteristics: {
        persistent: false,
        sessionManagement: false,
        resumability: false,
        memoryModel: 'ephemeral',
        sseSupport: true,
        scalingModel: 'horizontal',
        deploymentReady: 'serverless',
      },
    });
  });

  /**
   * GET /metrics - PROMETHEUS-COMPATIBLE METRICS
   */
  app.get('/metrics', (_req: Request, res: Response) => {
    const reqP50 = percentile(metrics.requestDuration, 0.5);
    const reqP95 = percentile(metrics.requestDuration, 0.95);
    const reqP99 = percentile(metrics.requestDuration, 0.99);

    let toolMetricsText = '';
    for (const [toolName, durations] of metrics.toolExecutionTime) {
      const p50 = percentile(durations, 0.5);
      const p95 = percentile(durations, 0.95);
      const p99 = percentile(durations, 0.99);

      toolMetricsText += `
# HELP mcp_tool_duration_milliseconds Tool execution duration histogram
# TYPE mcp_tool_duration_milliseconds histogram
mcp_tool_duration_milliseconds{tool="${toolName}",quantile="0.5"} ${p50}
mcp_tool_duration_milliseconds{tool="${toolName}",quantile="0.95"} ${p95}
mcp_tool_duration_milliseconds{tool="${toolName}",quantile="0.99"} ${p99}
mcp_tool_duration_milliseconds_count{tool="${toolName}"} ${durations.length}
`;
    }

    res.set('Content-Type', 'text/plain');
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
 */
async function startServer(): Promise<void> {
  try {
    const app = await createApp();

    const server = app.listen(config.port, () => {
      logger.info('Stateless MCP Server successfully started', {
        port: config.port,
        corsOrigin: config.corsOrigin,
        rateLimitMax: config.rateLimitMax,
        allowedHosts: config.allowedHosts,
        enableDnsRebindingProtection: config.enableDnsRebindingProtection,
        pattern: 'stateless',
        nodeVersion: process.version,
        platform: process.platform,
        pid: process.pid,
      });

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
          sseSupport: true,
          sessionManagement: false,
          pattern: 'stateless',
          scalingModel: 'horizontal',
          deploymentModel: 'serverless-ready',
        },
      });
    });

    const shutdown = async () => {
      logger.info('Graceful shutdown initiated', {
        reason: 'shutdown_signal_received',
        pattern: 'stateless',
      });

      server.close(() => {
        logger.info('HTTP server closed successfully', {
          finalUptime: process.uptime(),
          pattern: 'stateless',
          cleanShutdown: true,
        });

        process.exit(0);
      });
    };

    process.on('SIGTERM', () => void shutdown());
    process.on('SIGINT', () => void shutdown());
  } catch (error) {
    logger.error('Server startup failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      pattern: 'stateless',
      startupFailed: true,
    });

    process.exit(1);
  }
}

/**
 * AUTOMATIC STARTUP LOGIC
 */
if (!process.env['NODE_ENV'] || process.env['NODE_ENV'] !== 'test') {
  startServer().catch((error) => {
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
 */
export {
  createMCPServer,
  createApp,
  startServer,
};
