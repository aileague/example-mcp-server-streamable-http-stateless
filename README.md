<div align="center">

**[STDIO](https://github.com/yigitkonur/example-mcp-server-stdio) | [Stateful HTTP](https://github.com/yigitkonur/example-mcp-server-streamable-http) | [Stateless HTTP](https://github.com/yigitkonur/example-mcp-server-streamable-http-stateless) | [SSE](https://github.com/yigitkonur/example-mcp-server-sse)**

</div>

---

# 🎓 MCP Stateless HTTP Streamable Server - Educational Reference

<div align="center">

**A Production-Ready Model Context Protocol Server Teaching Stateless Architecture and Scalability Best Practices**

[![MCP Version](https://img.shields.io/badge/MCP-1.0.0-blue)](https://spec.modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![SDK](https://img.shields.io/badge/SDK-Production%20Ready-green)](https://github.com/modelcontextprotocol/typescript-sdk)
[![Architecture](https://img.shields.io/badge/Architecture-True%20Stateless-gold)]()

_Learn by building a world-class MCP server designed for infinite scalability, security, and maintainability._

</div>

## 🎯 Project Goal & Core Concepts

This repository is a **deeply educational reference implementation** that demonstrates how to build a production-quality MCP server using a **truly stateless architecture**. This design is the gold standard for modern, cloud-native services.

Through a fully-functional calculator server, this project will teach you:

1.  **🏗️ Clean Architecture & Design**: Master the **"fresh instance per request"** pattern for infinite scaling and learn to structure your code with a clean separation of concerns (`types.ts` for data contracts, `server.ts` for logic).
2.  **⚙️ Protocol & Transport Mastery**: Correctly implement the `StreamableHTTPServerTransport` in its **stateless mode**, delegating all low-level protocol validation to the SDK.
3.  **🔒 Production-Grade Security**: Implement non-negotiable security layers, including **rate limiting**, request size validation, **DNS rebinding protection**, and strict CORS policies.
4.  **⚡ Resilient Error Handling**: Implement a "fail-fast" and "no-leaks" error policy using specific, protocol-compliant `McpError` types for predictable and secure failure modes.
5.  **📈 Production Observability**: Build a server that is transparent and monitorable from day one with structured logging, health check endpoints, and Prometheus-compatible metrics.

## 🤔 When to Use This Architecture

A stateless architecture is the optimal choice for environments where scalability, resilience, and operational simplicity are paramount.

- **Serverless Platforms:** Perfect for deployment to AWS Lambda, Vercel, Google Cloud Functions, or any "Function-as-a-Service" platform.
- **Auto-Scaling Environments:** Ideal for container orchestrators like Kubernetes, where a Horizontal Pod Autoscaler can add or remove server replicas based on traffic, with no need for session affinity ("sticky sessions").
- **High-Traffic APIs:** When you need to serve a large number of independent requests and cannot be constrained by the memory or state of a single server.
- **Simplified Operations:** Eliminates the need for a shared state store (like Redis), reducing infrastructure complexity and maintenance overhead.

## 🚀 Quick Start

### Prerequisites

- Node.js ≥ 20.0.0
- npm or yarn
- Docker (for containerized deployment)

### Installation & Running

```bash
# Clone the repository
git clone https://github.com/yigitkonur/example-mcp-server-streamable-http-stateless
cd example-mcp-server-streamable-http-stateless

# Install dependencies
npm install

# Build the project (compiles TypeScript to dist/)
npm run build

# Start the server in development mode (port 1071)
npm run dev
```

### Essential Commands

```bash
npm run dev        # Development mode with hot-reload (uses tsx)
npm run build      # Compile TypeScript to JavaScript in `dist/`
npm run start      # Run the production-ready compiled server
npm run lint       # Run code quality checks with ESLint
npm run lint:ci    # Run lint with zero warnings enforced
npm run typecheck  # TypeScript type checking
npm run format     # Format code with Prettier
npm run pipeline   # Full CI pipeline (clean + typecheck + lint + format + build)
npm run all        # Complete pipeline + smoke test
```

## 📐 Architecture Overview

### Key Principles

This server's architecture is defined by a commitment to modern best practices for building scalable and maintainable services.

1.  **Stateless by Design:** The server shares absolutely no state between requests. Every request is handled in complete isolation.
2.  **Ephemeral Instances & Explicit Cleanup:** The core of this pattern is creating a new `McpServer` and `Transport` for every request. These instances are explicitly destroyed when the request completes to prevent memory leaks.
3.  **Clean Code Architecture:** The codebase is intentionally split into `types.ts` (for data contracts, schemas, and constants) and `server.ts` (for runtime logic), promoting maintainability and a clear separation of concerns.
4.  **Resilient Error Handling:** The server uses a "fail-fast" and "no-leaks" error policy, throwing specific `McpError` types for predictable failures and wrapping all unexpected errors in a generic, safe response.
5.  **Production Observability:** The server exposes `/health` and `/metrics` endpoints from the start, making it transparent and easy to monitor in production environments.

### Architectural Diagrams

#### Logical Request Flow

This diagram shows how a single request is processed in our stateless model.

```
      Load Balancer (No Sticky Sessions Needed)
               |
    +----------+----------+----------+
    |          |          |          |
 Server 1   Server 2   Server 3   Server N  (Each server is identical)
    |
    | (Inside a single server handling one request)
    ▼
┌───────────────────────────┐
│  HTTP Request (POST/GET)  │
└────────────┬──────────────┘
             │
┌────────────▼──────────────┐
│  Express.js Middleware    │
│  (CORS, Rate Limit, Size) │
├───────────────────────────┤
│  handleMCPRequest Function│
│ ┌───────────────────────┐ │
│ │ Ephemeral McpServer   │ │ Create -> Connect -> Handle -> Destroy
│ │ Ephemeral Transport   │ │
│ └───────────────────────┘ │
└────────────┬──────────────┘
             │
┌────────────▼──────────────┐
│   HTTP Response / SSE     │
└───────────────────────────┘
```

#### Code Structure

This diagram shows how the source code is organized for maximum clarity and maintainability.

```
src/
├── types.ts      # Data Contracts (Schemas, Constants, Type Interfaces)
|                 #  - The "what" of our application.
|                 #  - Stable, logic-free, and reusable.
|
└── server.ts     # Runtime Logic (Server, Handlers, Tools, Middleware)
                  #  - The "how" of our application.
                  #  - Implements all behavior and depends on types.ts.
```

## 🔧 Core Implementation Patterns

This section highlights the most important, production-ready patterns demonstrated in this repository.

### Pattern 1: The "Per-Request Instance" Lifecycle

**The Principle:** To guarantee statelessness and prevent memory leaks, we follow a strict **create-use-destroy** lifecycle for server and transport objects within the scope of a single HTTP request handler.

**The Implementation:**

```typescript
// src/server.ts
const handleMCPRequest = async (req: Request, res: Response) => {
  try {
    // 1. CREATE: A fresh server and a stateless transport are created.
    const server = createMCPServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // CRITICAL: This enables stateless mode.
    });

    // 2. CONNECT & HANDLE: The ephemeral instances process the single request.
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);

    // 3. CLEANUP: Once the connection closes, we MUST destroy the instances.
    res.on('close', () => {
      transport.close();
      server.close(); // This prevents memory leaks.
    });
  } catch (error) {
    // ... global error handling ...
  }
};
```

### Pattern 2: Resilient & Secure Error Handling

**The Principle:** The server follows a "fail-fast" and "no-leaks" error policy. Predictable errors are reported with specific, protocol-compliant codes, while unexpected errors are caught and sanitized to prevent leaking internal details.

**The Implementation:**

1.  **Specific, Actionable Errors**: Predictable user errors, like division by zero, throw a specific `McpError`. This allows the client application to understand the failure and prompt the user for a correction.

    ```typescript
    // In the 'calculate' tool for the 'divide' operation:
    if (b === 0) {
      // Throw a structured error that the client can parse.
      throw new McpError(ErrorCode.InvalidParams, 'Division by zero is not allowed.');
    }
    ```

2.  **The "Safety Net" for Unexpected Errors**: The main `handleMCPRequest` function is wrapped in a `try...catch` block that acts as a safety net. It catches any unhandled exception, logs it internally, and returns a generic, safe error to the client.

    ```typescript
    // In src/server.ts -> handleMCPRequest
    } catch (error) {
      // 1. Log the full, detailed error for internal debugging.
      requestLogger.error('Unhandled error in MCP request handler', { error });

      // 2. Send a generic, protocol-compliant error to the client.
      //    This prevents leaking stack traces or implementation details.
      res.status(500).json({
        jsonrpc: '2.0',
        error: {
          code: ErrorCode.InternalError,
          message: 'An internal server error occurred.',
        },
        id: req.body?.id || null,
      });
    }
    ```

### Pattern 3: Strict Separation of Concerns (`types.ts` vs. `server.ts`)

**The Principle:** A clean architecture separates data contracts (the "what") from implementation logic (the "how"). This makes the code easier to maintain, test, and reason about.

**The Implementation:**

- **`src/types.ts`**: This file contains only data definitions. It has no runtime logic. It defines all Zod schemas for input validation, shared constants, and TypeScript interfaces. It is the stable foundation of the application.
- **`src/server.ts`**: This file contains all runtime logic. It imports the data contracts from `types.ts` and uses them to implement the server's behavior, including the Express app, middleware, tool handlers, and startup sequence.

### Pattern 4: Production-Ready Observability

**The Principle:** A production service must be transparent. This server includes built-in endpoints for health checks and metrics, allowing it to be easily integrated into modern monitoring and orchestration systems.

**The Implementation:**

- **`/health`:** A simple endpoint that returns a `200 OK` status with basic uptime and memory information. Perfect for load balancers and container readiness probes.
- **`/metrics`:** Exposes key performance indicators (KPIs) like request duration and tool execution times in a **Prometheus-compatible format**, ready to be scraped by monitoring systems like Prometheus or Grafana.

## 🧪 Testing & Validation

### Health & Metrics

Verify the server's operational status.

```bash
# Check basic health (responds with 200 OK if running)
curl http://localhost:1071/health

# Check Prometheus-style metrics for monitoring systems
curl http://localhost:1071/metrics
```

### Manual Request

Send a direct `curl` request to test a tool's functionality.

#### Testing a Success Case

```bash
# Test the 'calculate' tool
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"calculate","arguments":{"a":15,"b":7,"op":"add"}},"id":1}' \
  http://localhost:1071/mcp
```

#### Testing an Error Case

This command intentionally triggers the `InvalidParams` error to demonstrate the server's resilient error handling.

```bash
# Test division by zero
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"calculate","arguments":{"a":10,"b":0,"op":"divide"}},"id":2}' \
  http://localhost:1071/mcp

# Expected Error Response:
# {
#   "jsonrpc": "2.0",
#   "error": {
#     "code": -32602,
#     "message": "Division by zero is not allowed."
#   },
#   "id": 2
# }
```

### Interactive Testing with MCP Inspector

Use the official inspector for a rich, interactive testing experience.

```bash
# The inspector connects to the server's endpoint via HTTP.
npx @modelcontextprotocol/inspector --cli http://localhost:1071/mcp
```

## 🏭 Deployment & Configuration

### Configuration

The server is configured using environment variables, making it perfect for containerized deployments.

| Variable            | Description                                                                                                                                                                                                                                                                             | Default           |
| :------------------ | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------- |
| `PORT`              | The port for the HTTP server to listen on.                                                                                                                                                                                                                                              | `1071`            |
| `LOG_LEVEL`         | Logging verbosity (`debug`, `info`, `warn`, `error`).                                                                                                                                                                                                                                   | `info`            |
| `CORS_ORIGIN`       | Allowed origin for CORS. **Must be restricted in production.**                                                                                                                                                                                                                          | `*`               |
| `RATE_LIMIT_MAX`    | Max requests per window per IP.                                                                                                                                                                                                                                                         | `1000`            |
| `RATE_LIMIT_WINDOW` | Rate limit window in milliseconds.                                                                                                                                                                                                                                                      | `900000` (15 min) |
| `NODE_ENV`          | Sets the environment. Use `production` for Express optimizations.                                                                                                                                                                                                                       | `development`     |
| `SAMPLE_TOOL_NAME`  | **(Educational)** Demonstrates dynamic tool registration via environment variables. When set, adds a simple echo tool with the specified name that takes a `value` parameter and returns `test string print: {value}`. This pattern shows how MCP servers can be configured at runtime. | None              |

### Deployment

This server is designed from the ground up for modern, scalable deployment platforms. The included multi-stage `Dockerfile` and `docker-compose.yml` provide a secure and efficient container.

- **Serverless:** The `handleMCPRequest` function can be exported directly as a serverless function handler for platforms like Vercel or AWS Lambda.
- **Kubernetes:** The Docker image is ready to be deployed with a Horizontal Pod Autoscaler (HPA), allowing the cluster to automatically scale replicas up and down based on CPU or request load.

### 阿里百炼Http MCP
```json
{
  "mcpServers": {
    "cgz-ssh-stream": {
      "url": "https://172-30-6-23038000-9v54egeds2dcy8.ztna-dingtalk.com/mcp",
      "type": "streamableHttp"
    }
  }
}
```
