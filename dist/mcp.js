#!/usr/bin/env node
// stdio entrypoint for the ci-sentinel MCP server.
//
// This is the binary `npx -y ci-sentinel-mcp` runs. It is a THIN CLIENT: it
// carries no analysis engine — every audit (free and deep) is served by the
// hosted server (see mcpServer.ts). That keeps the workflow parser, taint engine,
// action-graph resolver and detector knowledge base behind the paywall (the moat).
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildMcpServer } from "./mcpServer.js";
async function main() {
    const server = buildMcpServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("ci-sentinel MCP server running on stdio.");
}
main().catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
});
