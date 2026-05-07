const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const zlib = require("zlib");

loadEnvFile();

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";
const PUBLIC_DIR = path.join(__dirname, "public");
const SYSTEM_PROMPT_FILE =
  process.env.LLM_SYSTEM_PROMPT_FILE || path.join(__dirname, "system-prompt.md");
const KNOWLEDGE_DIR = path.resolve(
  __dirname,
  process.env.KNOWLEDGE_DIR || "./knowledge"
);
const KNOWLEDGE_MAX_CHUNKS = Number(process.env.KNOWLEDGE_MAX_CHUNKS || 4);
const KNOWLEDGE_CHUNK_SIZE = Number(process.env.KNOWLEDGE_CHUNK_SIZE || 1800);
const KNOWLEDGE_CHUNK_OVERLAP = Number(process.env.KNOWLEDGE_CHUNK_OVERLAP || 250);
const LLM_SYSTEM_PROMPT = loadSystemPrompt();
const codexDefaults = loadCodexDefaults();
const DEFAULT_CHAT_CONFIG = buildDefaultChatConfig(codexDefaults);

let knowledgeCache = {
  signature: "",
  documents: [],
  loadedAt: "",
  warnings: []
};

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/api/config") {
      sendJson(res, 200, buildClientConfig(DEFAULT_CHAT_CONFIG, codexDefaults));
      return;
    }

    if (req.method === "POST" && req.url === "/api/chat") {
      await handleChat(req, res);
      return;
    }

    if (req.method !== "GET") {
      sendJson(res, 405, { error: "Method not allowed." });
      return;
    }

    const requestPath = req.url === "/" ? "/index.html" : req.url;
    const safePath = path.normalize(requestPath).replace(/^(\.\.[/\\])+/, "");
    const filePath = path.join(PUBLIC_DIR, safePath);

    if (!filePath.startsWith(PUBLIC_DIR)) {
      sendJson(res, 403, { error: "Forbidden." });
      return;
    }

    fs.readFile(filePath, (error, content) => {
      if (error) {
        if (error.code === "ENOENT") {
          sendJson(res, 404, { error: "Not found." });
          return;
        }

        sendJson(res, 500, { error: "Failed to read file." });
        return;
      }

      const extension = path.extname(filePath);
      const mimeType = MIME_TYPES[extension] || "application/octet-stream";
      res.writeHead(200, { "Content-Type": mimeType });
      res.end(content);
    });
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { error: "Internal server error." });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Chat app running at http://${HOST}:${PORT}`);
  ensureKnowledgeDir();
});

async function handleChat(req, res) {
  if (!DEFAULT_CHAT_CONFIG.apiKey || !DEFAULT_CHAT_CONFIG.baseUrl) {
    sendJson(res, 500, {
      error:
        "Missing LLM endpoint configuration. Add environment variables or a valid Codex config."
    });
    return;
  }

  const body = await readJsonBody(req);
  const incomingMessages = Array.isArray(body.messages) ? body.messages : [];
  const overrides = body.config && typeof body.config === "object" ? body.config : {};
  const requestConfig = {
    baseUrl:
      typeof overrides.baseUrl === "string" && overrides.baseUrl.trim()
        ? overrides.baseUrl.trim()
        : DEFAULT_CHAT_CONFIG.baseUrl,
    model:
      typeof overrides.model === "string" && overrides.model.trim()
        ? overrides.model.trim()
        : DEFAULT_CHAT_CONFIG.model,
    wireApi:
      typeof overrides.wireApi === "string" && overrides.wireApi.trim()
        ? overrides.wireApi.trim()
        : DEFAULT_CHAT_CONFIG.wireApi,
    apiKey: DEFAULT_CHAT_CONFIG.apiKey
  };

  if (incomingMessages.length === 0) {
    sendJson(res, 400, { error: "At least one message is required." });
    return;
  }

  const normalizedMessages = incomingMessages
    .filter((message) => message && typeof message.content === "string")
    .map((message) => ({
      role: message.role === "assistant" ? "assistant" : "user",
      content: message.content.trim()
    }))
    .filter((message) => message.content);

  const latestUserMessage = [...normalizedMessages]
    .reverse()
    .find((message) => message.role === "user");

  const knowledge = loadKnowledgeBase();
  const knowledgeContext = latestUserMessage
    ? buildKnowledgeContext(latestUserMessage.content, knowledge)
    : "";

  const messages = [
    { role: "system", content: LLM_SYSTEM_PROMPT },
    ...(knowledgeContext
      ? [
          {
            role: "system",
            content: knowledgeContext
          }
        ]
      : []),
    ...normalizedMessages
  ];

  const requestTarget = resolveEndpointUrl(
    requestConfig.baseUrl,
    requestConfig.wireApi
  );
  const requestBody =
    requestConfig.wireApi === "responses"
      ? {
          model: requestConfig.model,
          input: messages
        }
      : {
          model: requestConfig.model,
          messages
        };

  const upstreamResponse = await fetch(requestTarget, {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      Authorization: `Bearer ${requestConfig.apiKey}`
    },
    body: JSON.stringify(requestBody)
  });

  const responseText = await upstreamResponse.text();
  const responseJson = parseUpstreamPayload(responseText);

  if (!upstreamResponse.ok) {
    sendJson(res, upstreamResponse.status, {
      error:
        responseJson?.error?.message ||
        responseText ||
        "LLM endpoint request failed."
    });
    return;
  }

  const assistantMessage = extractAssistantText(responseJson);

  if (!assistantMessage) {
    sendJson(res, 502, {
      error: "The LLM endpoint returned a response, but no assistant text was found."
    });
    return;
  }

  sendJson(res, 200, { message: assistantMessage });
}

function buildClientConfig(chatConfig, codexConfig) {
  const knowledge = loadKnowledgeBase();

  return {
    defaults: {
      baseUrl: chatConfig.baseUrl || "",
      model: chatConfig.model || "",
      wireApi: chatConfig.wireApi || "chat_completions",
      providerName: chatConfig.providerName || "Custom"
    },
    source: {
      hasEnvOverride: Boolean(process.env.LLM_API_URL || process.env.LLM_MODEL),
      hasApiKey: Boolean(chatConfig.apiKey),
      codexConfigLoaded: Boolean(codexConfig.baseUrl || codexConfig.model)
    },
    knowledge: {
      directory: KNOWLEDGE_DIR,
      documentCount: knowledge.documents.length,
      loadedAt: knowledge.loadedAt,
      warnings: knowledge.warnings
    }
  };
}

function extractAssistantText(payload) {
  if (!payload || typeof payload !== "object") {
    return "";
  }

  if (payload.output_text && typeof payload.output_text === "string") {
    return payload.output_text;
  }

  const choiceText = payload.choices?.[0]?.message?.content;
  if (typeof choiceText === "string") {
    return choiceText;
  }

  const responseOutput = payload.output?.[0]?.content;
  if (Array.isArray(responseOutput)) {
    return responseOutput
      .map((item) => {
        if (typeof item?.text === "string") {
          return item.text;
        }

        if (typeof item?.content === "string") {
          return item.content;
        }

        return "";
      })
      .join("\n")
      .trim();
  }

  return "";
}

function parseUpstreamPayload(responseText) {
  if (!responseText) {
    return null;
  }

  try {
    return JSON.parse(responseText);
  } catch (error) {
    return parseSsePayload(responseText);
  }
}

function parseSsePayload(responseText) {
  const dataLines = responseText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trim())
    .filter((line) => line && line !== "[DONE]");

  for (let index = dataLines.length - 1; index >= 0; index -= 1) {
    try {
      return JSON.parse(dataLines[index]);
    } catch (error) {
      continue;
    }
  }

  return null;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";

    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) {
        reject(new Error("Request body too large."));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (!raw) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(new Error("Invalid JSON body."));
      }
    });

    req.on("error", reject);
  });
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

function loadEnvFile() {
  const envPath = path.join(__dirname, ".env");

  if (!fs.existsSync(envPath)) {
    return;
  }

  const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim();

    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

function loadSystemPrompt() {
  const envPrompt = process.env.LLM_SYSTEM_PROMPT;
  if (envPrompt && envPrompt.trim()) {
    return envPrompt.trim();
  }

  const filePrompt = readFileIfExists(SYSTEM_PROMPT_FILE);
  if (filePrompt && filePrompt.trim()) {
    return filePrompt.trim();
  }

  return "You are a helpful assistant.";
}

function buildDefaultChatConfig(codexConfig) {
  return {
    baseUrl:
      process.env.LLM_API_URL ||
      process.env.OPENAI_API_BASE ||
      process.env.OPENAI_BASE_URL ||
      codexConfig.baseUrl ||
      "",
    model:
      process.env.LLM_MODEL ||
      process.env.OPENAI_MODEL ||
      codexConfig.model ||
      "gpt-4.1-mini",
    wireApi:
      process.env.LLM_WIRE_API ||
      codexConfig.wireApi ||
      inferWireApi(process.env.LLM_API_URL),
    providerName: codexConfig.providerName || "Custom",
    apiKey:
      process.env.LLM_API_KEY ||
      process.env.OPENAI_API_KEY ||
      codexConfig.apiKey ||
      ""
  };
}

function loadCodexDefaults() {
  const codexHome = process.env.CODEX_HOME || path.join(os.homedir(), ".codex");
  const configPath = path.join(codexHome, "config.toml");
  const authPath = path.join(codexHome, "auth.json");
  const parsedConfig = parseCodexToml(readFileIfExists(configPath) || "");
  const authConfig = parseAuthJson(readFileIfExists(authPath) || "");

  const activeProfileName = parsedConfig.root.profile || "";
  const activeProfile = parsedConfig.profiles[activeProfileName] || {};
  const providerName =
    activeProfile.model_provider || parsedConfig.root.model_provider || "";
  const provider = parsedConfig.modelProviders[providerName] || {};
  const model = activeProfile.model || parsedConfig.root.model || provider.model || "";

  return {
    providerName: provider.name || providerName || "",
    baseUrl: provider.base_url || "",
    model,
    wireApi: provider.wire_api || inferWireApi(provider.base_url),
    apiKey: authConfig.OPENAI_API_KEY || ""
  };
}

function parseCodexToml(contents) {
  const root = {};
  const profiles = {};
  const modelProviders = {};
  let currentScope = root;
  let currentSection = "";

  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (!line || line.startsWith("#")) {
      continue;
    }

    const sectionMatch = line.match(/^\[(.+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1];

      if (currentSection.startsWith("profiles.")) {
        const profileName = currentSection.slice("profiles.".length);
        profiles[profileName] ||= {};
        currentScope = profiles[profileName];
      } else if (currentSection.startsWith("model_providers.")) {
        const providerName = currentSection.slice("model_providers.".length);
        modelProviders[providerName] ||= {};
        currentScope = modelProviders[providerName];
      } else {
        currentScope = {};
      }

      continue;
    }

    const assignmentMatch = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
    if (!assignmentMatch) {
      continue;
    }

    const [, key, rawValue] = assignmentMatch;
    currentScope[key] = parseTomlValue(rawValue);
  }

  return { root, profiles, modelProviders };
}

function parseTomlValue(rawValue) {
  const value = rawValue.trim();

  if (value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1);
  }

  if (value === "true") {
    return true;
  }

  if (value === "false") {
    return false;
  }

  if (/^-?\d+(\.\d+)?$/.test(value)) {
    return Number(value);
  }

  return value;
}

function parseAuthJson(contents) {
  if (!contents) {
    return {};
  }

  try {
    return JSON.parse(contents);
  } catch (error) {
    return {};
  }
}

function readFileIfExists(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (error) {
    return "";
  }
}

function inferWireApi(baseUrl) {
  if (typeof baseUrl === "string" && baseUrl.includes("/responses")) {
    return "responses";
  }

  return "chat_completions";
}

function resolveEndpointUrl(baseUrl, wireApi) {
  const trimmedBase = (baseUrl || "").trim().replace(/\/+$/, "");

  if (!trimmedBase) {
    return "";
  }

  if (/\/(chat\/completions|responses)$/.test(trimmedBase)) {
    return trimmedBase;
  }

  return wireApi === "responses"
    ? `${trimmedBase}/responses`
    : `${trimmedBase}/chat/completions`;
}

function ensureKnowledgeDir() {
  fs.mkdirSync(KNOWLEDGE_DIR, { recursive: true });
}

function loadKnowledgeBase() {
  ensureKnowledgeDir();

  const entries = fs
    .readdirSync(KNOWLEDGE_DIR, { withFileTypes: true })
    .filter((entry) => entry.isFile() && isKnowledgeFile(entry.name))
    .map((entry) => path.join(KNOWLEDGE_DIR, entry.name));

  const signature = entries
    .map((filePath) => {
      const stats = fs.statSync(filePath);
      return `${path.basename(filePath)}:${stats.size}:${stats.mtimeMs}`;
    })
    .join("|");

  if (signature === knowledgeCache.signature) {
    return knowledgeCache;
  }

  const documents = [];
  const warnings = [];

  for (const filePath of entries) {
    try {
      const document = loadKnowledgeDocument(filePath);
      if (document) {
        documents.push(document);
      }
    } catch (error) {
      warnings.push(`Failed to load ${path.basename(filePath)}: ${error.message}`);
    }
  }

  knowledgeCache = {
    signature,
    documents,
    warnings,
    loadedAt: new Date().toISOString()
  };

  return knowledgeCache;
}

function isKnowledgeFile(fileName) {
  const ext = path.extname(fileName).toLowerCase();
  return [".pdf", ".txt", ".md"].includes(ext);
}

function loadKnowledgeDocument(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const rawBuffer = fs.readFileSync(filePath);
  let text = "";

  if (ext === ".pdf") {
    text = extractTextFromPdf(rawBuffer);
  } else {
    text = rawBuffer.toString("utf8");
  }

  const normalizedText = normalizeKnowledgeText(text);
  if (!normalizedText) {
    throw new Error("No extractable text found.");
  }

  return {
    name: path.basename(filePath),
    path: filePath,
    chunks: chunkKnowledgeText(normalizedText, path.basename(filePath))
  };
}

function extractTextFromPdf(buffer) {
  const streamRegex = /stream\r?\n([\s\S]*?)endstream/g;
  const extractedParts = [];
  let match = null;

  while ((match = streamRegex.exec(buffer.toString("binary"))) !== null) {
    const rawStream = Buffer.from(match[1], "binary");
    const candidates = [rawStream, tryInflate(rawStream), tryInflateRaw(rawStream)];

    for (const candidate of candidates) {
      if (!candidate || !candidate.length) {
        continue;
      }

      const text = extractPdfStrings(candidate.toString("binary"));
      if (text) {
        extractedParts.push(text);
      }
    }
  }

  return extractedParts.join("\n");
}

function tryInflate(buffer) {
  try {
    return zlib.inflateSync(buffer);
  } catch (error) {
    return null;
  }
}

function tryInflateRaw(buffer) {
  try {
    return zlib.inflateRawSync(buffer);
  } catch (error) {
    return null;
  }
}

function extractPdfStrings(binaryText) {
  const parts = [];
  const literalRegex = /\((?:\\.|[^()\\])+\)/g;
  const hexRegex = /<([0-9A-Fa-f\s]{8,})>/g;
  let literalMatch = null;
  let hexMatch = null;

  while ((literalMatch = literalRegex.exec(binaryText)) !== null) {
    const decoded = decodePdfLiteral(literalMatch[0].slice(1, -1));
    if (looksLikeText(decoded)) {
      parts.push(decoded);
    }
  }

  while ((hexMatch = hexRegex.exec(binaryText)) !== null) {
    const decoded = decodePdfHex(hexMatch[1]);
    if (looksLikeText(decoded)) {
      parts.push(decoded);
    }
  }

  return parts.join(" ");
}

function decodePdfLiteral(value) {
  let decoded = "";

  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];

    if (char !== "\\") {
      decoded += char;
      continue;
    }

    const next = value[index + 1];
    if (!next) {
      continue;
    }

    if (/[0-7]/.test(next)) {
      const octal = value.slice(index + 1, index + 4).match(/^[0-7]{1,3}/)?.[0] || "";
      decoded += String.fromCharCode(parseInt(octal, 8));
      index += octal.length;
      continue;
    }

    const escapeMap = {
      n: "\n",
      r: "\r",
      t: "\t",
      b: "\b",
      f: "\f",
      "(": "(",
      ")": ")",
      "\\": "\\"
    };

    decoded += escapeMap[next] || next;
    index += 1;
  }

  return decoded;
}

function decodePdfHex(value) {
  const cleaned = value.replace(/\s+/g, "");
  const evenHex = cleaned.length % 2 === 0 ? cleaned : `${cleaned}0`;

  try {
    return Buffer.from(evenHex, "hex").toString("utf8");
  } catch (error) {
    return "";
  }
}

function looksLikeText(value) {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length < 4) {
    return false;
  }

  const printableChars = normalized.match(/[A-Za-z0-9]/g) || [];
  return printableChars.length >= Math.min(8, normalized.length);
}

function normalizeKnowledgeText(value) {
  return value
    .replace(/\u0000/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function chunkKnowledgeText(text, sourceName) {
  const chunks = [];
  let start = 0;

  while (start < text.length) {
    const end = Math.min(text.length, start + KNOWLEDGE_CHUNK_SIZE);
    const slice = text.slice(start, end).trim();

    if (slice) {
      chunks.push({
        sourceName,
        text: slice,
        searchText: normalizeForSearch(slice)
      });
    }

    if (end >= text.length) {
      break;
    }

    start = Math.max(end - KNOWLEDGE_CHUNK_OVERLAP, start + 1);
  }

  return chunks;
}

function buildKnowledgeContext(question, knowledge) {
  const query = normalizeForSearch(question);
  if (!query) {
    return "";
  }

  const queryTerms = uniqueTerms(query);
  const rankedChunks = knowledge.documents
    .flatMap((document) => document.chunks)
    .map((chunk) => ({
      ...chunk,
      score: scoreChunk(chunk.searchText, queryTerms)
    }))
    .filter((chunk) => chunk.score > 0)
    .sort((left, right) => right.score - left.score)
    .slice(0, KNOWLEDGE_MAX_CHUNKS);

  if (rankedChunks.length === 0) {
    return "";
  }

  const lines = [
    "Knowledge excerpts from local files. Use these as the primary source when they are relevant.",
    `Knowledge directory: ${KNOWLEDGE_DIR}`
  ];

  rankedChunks.forEach((chunk, index) => {
    lines.push(
      `[Knowledge ${index + 1}] Source: ${chunk.sourceName}\n${chunk.text}`
    );
  });

  if (knowledge.warnings.length > 0) {
    lines.push(`Knowledge warnings: ${knowledge.warnings.join(" | ")}`);
  }

  return lines.join("\n\n");
}

function normalizeForSearch(value) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function uniqueTerms(value) {
  return [...new Set(value.split(/\s+/).filter((term) => term.length > 2))];
}

function scoreChunk(text, queryTerms) {
  let score = 0;

  for (const term of queryTerms) {
    if (!text.includes(term)) {
      continue;
    }

    score += 2;

    const occurrences = text.split(term).length - 1;
    score += Math.min(occurrences, 4);
  }

  return score;
}
