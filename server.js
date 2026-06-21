import express from "express";
import crypto from "crypto";
import { z } from "zod/v4";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.set("trust proxy", true);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

const ZENMONEY_TOKEN = process.env.ZENMONEY_TOKEN;
const MCP_SECRET = process.env.MCP_SECRET;

let cachedData = null;
let cachedAt = 0;
const CACHE_TTL_MS = 60 * 1000;

const oauthClients = new Map();
const oauthCodes = new Map();
const oauthTokens = new Set();

function baseUrl(req) {
  return `${req.protocol}://${req.get("host")}`;
}

function nowTs() {
  return Math.floor(Date.now() / 1000);
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function normalizeDate(value) {
  if (!value) return today();
  return String(value).slice(0, 10);
}

function positiveAmount(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error("Amount must be a positive number");
  }
  return n;
}

function jsonResult(data) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

function makeMap(items = []) {
  const map = {};
  for (const item of items) {
    if (item && item.id !== undefined) {
      map[item.id] = item;
    }
  }
  return map;
}

function normalizeTags(categoryIds) {
  if (!categoryIds) return [];
  if (Array.isArray(categoryIds)) return categoryIds.filter(Boolean);
  return [categoryIds].filter(Boolean);
}

async function zenmoneyDiff(extra = {}) {
  if (!ZENMONEY_TOKEN) {
    throw new Error("ZENMONEY_TOKEN is not configured");
  }

  const response = await fetch("https://api.zenmoney.ru/v8/diff/", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${ZENMONEY_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      currentClientTimestamp: nowTs(),
      serverTimestamp: 0,
      ...extra
    })
  });

  const text = await response.text();

  if (!response.ok) {
    throw new Error(`ZenMoney API error ${response.status}: ${text}`);
  }

  return JSON.parse(text);
}

async function getData(force = false) {
  const now = Date.now();

  if (!force && cachedData && now - cachedAt < CACHE_TTL_MS) {
    return cachedData;
  }

  const data = await zenmoneyDiff();
  cachedData = data;
  cachedAt = now;
  return data;
}

async function pushTransactions(transactions) {
  const result = await zenmoneyDiff({
    transaction: transactions
  });

  cachedData = null;
  cachedAt = 0;

  return result;
}

function getUserId(data) {
  const users = data.user || [];
  return users[0]?.id || null;
}

function findTransaction(data, id) {
  const transaction = (data.transaction || []).find(t => String(t.id) === String(id));

  if (!transaction) {
    throw new Error(`Transaction not found: ${id}`);
  }

  return transaction;
}

function enrichTransactions(data, transactions) {
  const accounts = makeMap(data.account || []);
  const categories = makeMap(data.tag || []);

  return transactions.map(t => ({
    id: t.id,
    date: normalizeDate(t.date),
    income: Number(t.income || 0),
    outcome: Number(t.outcome || 0),
    payee: t.payee || null,
    comment: t.comment || null,
    incomeAccount: t.incomeAccount || null,
    outcomeAccount: t.outcomeAccount || null,
    incomeAccountTitle: accounts[t.incomeAccount]?.title || null,
    outcomeAccountTitle: accounts[t.outcomeAccount]?.title || null,
    tags: Array.isArray(t.tag)
      ? t.tag.map(id => ({
          id,
          title: categories[id]?.title || null
        }))
      : [],
    deleted: Boolean(t.deleted)
  }));
}

/**
 * OAuth compatibility layer for Claude Desktop / mcp-remote.
 * Реальная защита остаётся через секретный путь:
 * /mcp/:secret
 */

function oauthMetadata(req, res) {
  const origin = baseUrl(req);

  res.json({
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    registration_endpoint: `${origin}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: [
      "none",
      "client_secret_post",
      "client_secret_basic"
    ],
    code_challenge_methods_supported: ["S256", "plain"],
    scopes_supported: ["mcp"]
  });
}

function protectedResourceMetadata(req, res) {
  const origin = baseUrl(req);

  res.json({
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"]
  });
}

app.get("/.well-known/oauth-authorization-server", oauthMetadata);
app.get("/.well-known/oauth-authorization-server/*", oauthMetadata);

app.get("/.well-known/oauth-protected-resource", protectedResourceMetadata);
app.get("/.well-known/oauth-protected-resource/*", protectedResourceMetadata);

app.post(["/register", "/oauth/register"], (req, res) => {
  const clientId = `client_${crypto.randomUUID()}`;
  const clientSecret = `secret_${crypto.randomUUID()}`;

  oauthClients.set(clientId, {
    clientId,
    clientSecret,
    redirectUris: req.body?.redirect_uris || [],
    createdAt: nowTs()
  });

  res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_id_issued_at: nowTs(),
    client_secret_expires_at: 0,
    redirect_uris: req.body?.redirect_uris || [],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "client_secret_post",
    scope: "mcp"
  });
});

app.get(["/authorize", "/oauth/authorize"], (req, res) => {
  const redirectUri = req.query.redirect_uri;
  const state = req.query.state;
  const clientId = req.query.client_id;

  if (!redirectUri) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "redirect_uri is required"
    });
  }

  const code = `code_${crypto.randomUUID()}`;

  oauthCodes.set(code, {
    clientId,
    redirectUri,
    createdAt: Date.now()
  });

  const redirect = new URL(String(redirectUri));
  redirect.searchParams.set("code", code);

  if (state) {
    redirect.searchParams.set("state", String(state));
  }

  res.redirect(302, redirect.toString());
});

app.post(["/token", "/oauth/token"], (req, res) => {
  const grantType = req.body?.grant_type;

  if (grantType === "authorization_code") {
    const code = req.body?.code;

    if (!code || !oauthCodes.has(code)) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Invalid authorization code"
      });
    }

    oauthCodes.delete(code);

    const accessToken = `token_${crypto.randomUUID()}`;
    const refreshToken = `refresh_${crypto.randomUUID()}`;

    oauthTokens.add(accessToken);

    return res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: "mcp"
    });
  }

  if (grantType === "refresh_token") {
    const accessToken = `token_${crypto.randomUUID()}`;
    oauthTokens.add(accessToken);

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: "mcp"
    });
  }

  return res.status(400).json({
    error: "unsupported_grant_type"
  });
});

function createMcpServer() {
  const server = new McpServer({
    name: "zenmoney-mcp",
    version: "1.1.0"
  });

  server.registerTool(
    "get_health",
    {
      description: "Check ZenMoney MCP server health.",
      inputSchema: {}
    },
    async () => {
      return jsonResult({
        ok: true,
        hasZenmoneyToken: Boolean(ZENMONEY_TOKEN),
        hasMcpSecret: Boolean(MCP_SECRET),
        oauthShim: true
      });
    }
  );

  server.registerTool(
    "get_accounts",
    {
      description: "Get all ZenMoney accounts with balances and currencies.",
      inputSchema: {}
    },
    async () => {
      const data = await getData();
      const instruments = makeMap(data.instrument || []);

      const accounts = (data.account || [])
        .filter(a => !a.deleted)
        .map(a => ({
          id: a.id,
          title: a.title,
          type: a.type,
          balance: a.balance,
          startBalance: a.startBalance,
          creditLimit: a.creditLimit,
          inBalance: a.inBalance,
          archive: a.archive,
          instrument: a.instrument,
          currency: instruments[a.instrument]?.shortTitle || null
        }));

      return jsonResult({ accounts });
    }
  );

  server.registerTool(
    "get_categories",
    {
      description: "Get ZenMoney categories/tags.",
      inputSchema: {}
    },
    async () => {
      const data = await getData();

      const categories = (data.tag || [])
        .filter(t => !t.deleted)
        .map(t => ({
          id: t.id,
          title: t.title,
          parent: t.parent || null,
          showIncome: t.showIncome,
          showOutcome: t.showOutcome,
          budgetIncome: t.budgetIncome,
          budgetOutcome: t.budgetOutcome
        }));

      return jsonResult({ categories });
    }
  );

  server.registerTool(
    "get_transactions",
    {
      description: "Get ZenMoney transactions with optional filters.",
      inputSchema: {
        from: z.string().optional(),
        to: z.string().optional(),
        limit: z.number().optional(),
        accountId: z.string().optional(),
        categoryId: z.string().optional(),
        search: z.string().optional()
      }
    },
    async ({ from, to, limit = 50, accountId, categoryId, search }) => {
      const data = await getData();

      const fromDate = from ? normalizeDate(from) : null;
      const toDate = to ? normalizeDate(to) : null;
      const max = Math.min(Number(limit || 50), 500);
      const q = search ? String(search).toLowerCase() : null;

      const transactions = (data.transaction || [])
        .filter(t => !t.deleted)
        .filter(t => !fromDate || normalizeDate(t.date) >= fromDate)
        .filter(t => !toDate || normalizeDate(t.date) <= toDate)
        .filter(t => !accountId || t.incomeAccount === accountId || t.outcomeAccount === accountId)
        .filter(t => !categoryId || (Array.isArray(t.tag) && t.tag.includes(categoryId)))
        .filter(t => {
          if (!q) return true;
          return [t.payee, t.comment, t.id]
            .filter(Boolean)
            .join(" ")
            .toLowerCase()
            .includes(q);
        })
        .sort((a, b) => String(b.date).localeCompare(String(a.date)))
        .slice(0, max);

      return jsonResult({
        transactions: enrichTransactions(data, transactions)
      });
    }
  );

  server.registerTool(
    "get_transaction_by_id",
    {
      description: "Get one ZenMoney transaction by id.",
      inputSchema: {
        id: z.string()
      }
    },
    async ({ id }) => {
      const data = await getData();
      const tx = findTransaction(data, id);

      return jsonResult({
        transaction: enrichTransactions(data, [tx])[0],
        raw: tx
      });
    }
  );

  server.registerTool(
    "get_summary",
    {
      description: "Get income/outcome summary by category for a period.",
      inputSchema: {
        from: z.string().optional(),
        to: z.string().optional()
      }
    },
    async ({ from, to }) => {
      const data = await getData();
      const categories = makeMap(data.tag || []);

      const fromDate = from ? normalizeDate(from) : null;
      const toDate = to ? normalizeDate(to) : null;

      const summary = {
        from: fromDate,
        to: toDate,
        totalIncome: 0,
        totalOutcome: 0,
        byCategory: {}
      };

      for (const t of data.transaction || []) {
        if (t.deleted) continue;

        const date = normalizeDate(t.date);
        if (fromDate && date < fromDate) continue;
        if (toDate && date > toDate) continue;

        const income = Number(t.income || 0);
        const outcome = Number(t.outcome || 0);

        summary.totalIncome += income;
        summary.totalOutcome += outcome;

        const tagIds = Array.isArray(t.tag) && t.tag.length
          ? t.tag
          : ["without_category"];

        for (const tagId of tagIds) {
          const title = tagId === "without_category"
            ? "Без категории"
            : categories[tagId]?.title || "Неизвестная категория";

          if (!summary.byCategory[tagId]) {
            summary.byCategory[tagId] = {
              id: tagId,
              title,
              income: 0,
              outcome: 0
            };
          }

          summary.byCategory[tagId].income += income;
          summary.byCategory[tagId].outcome += outcome;
        }
      }

      summary.byCategory = Object.values(summary.byCategory)
        .sort((a, b) => b.outcome - a.outcome);

      return jsonResult(summary);
    }
  );

  server.registerTool(
    "create_expense",
    {
      description: "Create an expense transaction in ZenMoney. Requires confirm=true.",
      inputSchema: {
        accountId: z.string(),
        amount: z.number(),
        date: z.string().optional(),
        categoryIds: z.array(z.string()).optional(),
        payee: z.string().optional(),
        comment: z.string().optional(),
        confirm: z.boolean()
      }
    },
    async ({ accountId, amount, date, categoryIds, payee, comment, confirm }) => {
      if (!confirm) {
        return jsonResult({
          ok: false,
          error: "confirm must be true to create expense"
        });
      }

      const data = await getData(true);
      const ts = nowTs();

      const transaction = {
        id: crypto.randomUUID(),
        user: getUserId(data),
        date: normalizeDate(date),
        changed: ts,
        created: ts,
        deleted: false,
        income: 0,
        outcome: positiveAmount(amount),
        outcomeAccount: accountId,
        tag: normalizeTags(categoryIds),
        payee: payee || null,
        comment: comment || null
      };

      const syncResult = await pushTransactions([transaction]);

      return jsonResult({
        ok: true,
        createdTransaction: transaction,
        syncResult
      });
    }
  );

  server.registerTool(
    "create_income",
    {
      description: "Create an income transaction in ZenMoney. Requires confirm=true.",
      inputSchema: {
        accountId: z.string(),
        amount: z.number(),
        date: z.string().optional(),
        categoryIds: z.array(z.string()).optional(),
        payee: z.string().optional(),
        comment: z.string().optional(),
        confirm: z.boolean()
      }
    },
    async ({ accountId, amount, date, categoryIds, payee, comment, confirm }) => {
      if (!confirm) {
        return jsonResult({
          ok: false,
          error: "confirm must be true to create income"
        });
      }

      const data = await getData(true);
      const ts = nowTs();

      const transaction = {
        id: crypto.randomUUID(),
        user: getUserId(data),
        date: normalizeDate(date),
        changed: ts,
        created: ts,
        deleted: false,
        income: positiveAmount(amount),
        outcome: 0,
        incomeAccount: accountId,
        tag: normalizeTags(categoryIds),
        payee: payee || null,
        comment: comment || null
      };

      const syncResult = await pushTransactions([transaction]);

      return jsonResult({
        ok: true,
        createdTransaction: transaction,
        syncResult
      });
    }
  );

  server.registerTool(
    "create_transfer",
    {
      description: "Create transfer between ZenMoney accounts. Requires confirm=true.",
      inputSchema: {
        fromAccountId: z.string(),
        toAccountId: z.string(),
        outcomeAmount: z.number(),
        incomeAmount: z.number().optional(),
        date: z.string().optional(),
        comment: z.string().optional(),
        confirm: z.boolean()
      }
    },
    async ({ fromAccountId, toAccountId, outcomeAmount, incomeAmount, date, comment, confirm }) => {
      if (!confirm) {
        return jsonResult({
          ok: false,
          error: "confirm must be true to create transfer"
        });
      }

      const data = await getData(true);
      const ts = nowTs();
      const out = positiveAmount(outcomeAmount);
      const inc = incomeAmount ? positiveAmount(incomeAmount) : out;

      const transaction = {
        id: crypto.randomUUID(),
        user: getUserId(data),
        date: normalizeDate(date),
        changed: ts,
        created: ts,
        deleted: false,
        income: inc,
        outcome: out,
        incomeAccount: toAccountId,
        outcomeAccount: fromAccountId,
        tag: [],
        payee: null,
        comment: comment || null
      };

      const syncResult = await pushTransactions([transaction]);

      return jsonResult({
        ok: true,
        createdTransaction: transaction,
        syncResult
      });
    }
  );

  server.registerTool(
    "update_transaction",
    {
      description: "Update a ZenMoney transaction. Requires confirm=true.",
      inputSchema: {
        id: z.string(),
        date: z.string().optional(),
        income: z.number().optional(),
        outcome: z.number().optional(),
        incomeAccount: z.string().optional(),
        outcomeAccount: z.string().optional(),
        categoryIds: z.array(z.string()).optional(),
        payee: z.string().optional(),
        comment: z.string().optional(),
        confirm: z.boolean()
      }
    },
    async ({ id, date, income, outcome, incomeAccount, outcomeAccount, categoryIds, payee, comment, confirm }) => {
      if (!confirm) {
        return jsonResult({
          ok: false,
          error: "confirm must be true to update transaction"
        });
      }

      const data = await getData(true);
      const current = findTransaction(data, id);

      const updated = {
        ...current,
        changed: nowTs(),
        deleted: false
      };

      if (date !== undefined) updated.date = normalizeDate(date);
      if (income !== undefined) updated.income = Number(income);
      if (outcome !== undefined) updated.outcome = Number(outcome);
      if (incomeAccount !== undefined) updated.incomeAccount = incomeAccount;
      if (outcomeAccount !== undefined) updated.outcomeAccount = outcomeAccount;
      if (categoryIds !== undefined) updated.tag = normalizeTags(categoryIds);
      if (payee !== undefined) updated.payee = payee || null;
      if (comment !== undefined) updated.comment = comment || null;

      const syncResult = await pushTransactions([updated]);

      return jsonResult({
        ok: true,
        updatedTransaction: updated,
        syncResult
      });
    }
  );

  server.registerTool(
    "set_transaction_category",
    {
      description: "Replace categories/tags for a transaction. Requires confirm=true.",
      inputSchema: {
        id: z.string(),
        categoryIds: z.array(z.string()),
        confirm: z.boolean()
      }
    },
    async ({ id, categoryIds, confirm }) => {
      if (!confirm) {
        return jsonResult({
          ok: false,
          error: "confirm must be true to set category"
        });
      }

      const data = await getData(true);
      const current = findTransaction(data, id);

      const updated = {
        ...current,
        changed: nowTs(),
        tag: normalizeTags(categoryIds)
      };

      const syncResult = await pushTransactions([updated]);

      return jsonResult({
        ok: true,
        updatedTransaction: updated,
        syncResult
      });
    }
  );

  server.registerTool(
    "delete_transaction",
    {
      description: "Delete a ZenMoney transaction. Requires confirm=true.",
      inputSchema: {
        id: z.string(),
        confirm: z.boolean()
      }
    },
    async ({ id, confirm }) => {
      if (!confirm) {
        return jsonResult({
          ok: false,
          error: "confirm must be true to delete transaction"
        });
      }

      const data = await getData(true);
      const current = findTransaction(data, id);

      const deletedTransaction = {
        ...current,
        changed: nowTs(),
        deleted: true
      };

      const syncResult = await pushTransactions([deletedTransaction]);

      return jsonResult({
        ok: true,
        deletedTransaction,
        syncResult
      });
    }
  );

  return server;
}

function checkSecret(req, res, next) {
  if (!MCP_SECRET) {
    return res.status(500).json({
      error: "MCP_SECRET is not configured"
    });
  }

  if (req.params.secret !== MCP_SECRET) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "zenmoney-mcp",
    oauthShim: true,
    mcpPath: "/mcp/YOUR_MCP_SECRET",
    tools: [
      "get_health",
      "get_accounts",
      "get_categories",
      "get_transactions",
      "get_transaction_by_id",
      "get_summary",
      "create_expense",
      "create_income",
      "create_transfer",
      "update_transaction",
      "set_transaction_category",
      "delete_transaction"
    ]
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    hasZenmoneyToken: Boolean(ZENMONEY_TOKEN),
    hasMcpSecret: Boolean(MCP_SECRET),
    oauthShim: true
  });
});

app.post("/mcp/:secret", checkSecret, async (req, res) => {
  const server = createMcpServer();

  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined
    });

    await server.connect(transport);

    res.on("close", () => {
      transport.close();
      server.close();
    });

    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP error:", error);

    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: error.message || "Internal server error"
        },
        id: req.body?.id ?? null
      });
    }
  }
});

app.get("/mcp/:secret", checkSecret, (req, res) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: {
      code: -32000,
      message: "Method not allowed. Use POST Streamable HTTP MCP."
    },
    id: null
  });
});

app.delete("/mcp/:secret", checkSecret, (req, res) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: {
      code: -32000,
      message: "Method not allowed."
    },
    id: null
  });
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`ZenMoney MCP server listening on port ${port}`);
});
