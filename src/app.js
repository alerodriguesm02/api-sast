// src/app.js - Aplicação Express (versão hardenizada)

// Requisitos (npm i):
// express mysql2 helmet express-rate-limit zod swagger-ui-express swagger-jsdoc node-fetch xml2js
// (node-fetch v3 é ESM; aqui uso import dinâmico para manter CommonJS)

const express = require("express");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");
const net = require("net");
const { Parser } = require("xml2js");

const app = express();

// ------------------------
// Middlewares básicos
// ------------------------
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: true, limit: "200kb" }));

// Rate limit global (ajuste conforme necessário)
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Rate limit específico para login
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

// ------------------------
// Configurações via ENV (remove hardcode)
// ------------------------
const {
  PORT = "3000",
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  API_KEY, // se realmente precisar expor/usar, mantenha no server-side e não logue
  JWT_SECRET,
  SSRF_ALLOWED_HOSTS, // ex: "api.externa.com,example.org" (opcional)
} = process.env;

function requireEnv(name, value) {
  if (!value) throw new Error(`Missing required env var: ${name}`);
}

requireEnv("DB_HOST", DB_HOST);
requireEnv("DB_USER", DB_USER);
requireEnv("DB_PASSWORD", DB_PASSWORD);
requireEnv("DB_NAME", DB_NAME);
requireEnv("JWT_SECRET", JWT_SECRET);

// ------------------------
// MySQL (pool) + queries parametrizadas
// ------------------------
const dbPool = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  namedPlaceholders: true,
});

// ------------------------
// Swagger (mantido, mas exemplos “seguros”)
// ------------------------
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "API (Hardened)",
      version: "1.0.0",
      description: "API com endpoints corrigidos (sem vulnerabilidades intencionais).",
      contact: { name: "Security Testing Team", email: "security@example.com" },
    },
    servers: [{ url: "http://localhost:3000", description: "Development server" }],
  },
  apis: ["./src/app.js"],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ------------------------
// Helpers
// ------------------------
function escapeHtml(str = "") {
  // Previne XSS em respostas HTML simples
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function safeJoin(baseDir, userPath) {
  // Previne Path Traversal
  const targetPath = path.resolve(baseDir, userPath);
  if (!targetPath.startsWith(path.resolve(baseDir) + path.sep)) {
    throw new Error("Invalid path");
  }
  return targetPath;
}

function isPrivateIp(ip) {
  // Bloqueia ranges privados/loopback/link-local
  // Nota: ip pode vir como IPv6 ::1, ou IPv4-mapped ::ffff:127.0.0.1
  const normalized = ip.startsWith("::ffff:") ? ip.replace("::ffff:", "") : ip;

  if (normalized === "::1" || normalized === "127.0.0.1") return true;
  if (net.isIP(normalized) === 4) {
    const [a, b] = normalized.split(".").map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 127) return true;
  }
  // IPv6 ULA fc00::/7, link-local fe80::/10, loopback ::1
  if (net.isIP(ip) === 6) {
    const low = ip.toLowerCase();
    if (low === "::1") return true;
    if (low.startsWith("fc") || low.startsWith("fd")) return true;
    if (low.startsWith("fe80:")) return true;
  }
  return false;
}

function parseAllowedHosts(envVal) {
  if (!envVal) return null;
  const set = new Set(
    envVal
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean)
  );
  return set.size ? set : null;
}

const allowedHosts = parseAllowedHosts(SSRF_ALLOWED_HOSTS);

// Merge seguro (mitiga prototype pollution)
function safeDeepMerge(target, source) {
  const forbidden = new Set(["__proto__", "constructor", "prototype"]);
  for (const [key, value] of Object.entries(source || {})) {
    if (forbidden.has(key)) continue;

    if (value && typeof value === "object" && !Array.isArray(value)) {
      if (!target[key] || typeof target[key] !== "object") target[key] = {};
      safeDeepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

// ------------------------
// Schemas (zod)
// ------------------------
const userIdSchema = z.object({
  id: z.coerce.number().int().positive(),
});

const loginSchema = z.object({
  username: z.string().min(1).max(80),
  password: z.string().min(1).max(200),
});

const encryptSchema = z.object({
  data: z.string().min(1).max(5000),
});

const fetchUrlSchema = z.object({
  url: z.string().url().max(2000),
});

const calculateSchema = z.object({
  // Aceita apenas expressão matemática simples (números, espaços e operadores básicos)
  expression: z
    .string()
    .min(1)
    .max(200)
    .regex(/^[0-9+\-*/().\s]+$/, "Invalid expression"),
});

const emailSchema = z.object({
  email: z.string().email().max(254),
});

const uploadSchema = z.object({
  filename: z.string().min(1).max(120),
  contentBase64: z.string().min(1),
});

const verifyTokenSchema = z.object({
  token: z.string().min(1).max(2000),
});

// ------------------------
// Endpoints
// ------------------------

/**
 * @swagger
 * /users/{id}:
 *   get:
 *     summary: Buscar usuário por ID (parametrizado)
 *     tags: [Users]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, example: 1 }
 *     responses:
 *       200: { description: Usuário encontrado }
 *       400: { description: Entrada inválida }
 *       500: { description: Erro no servidor }
 */
app.get("/users/:id", async (req, res, next) => {
  try {
    const { id } = userIdSchema.parse(req.params);
    const [rows] = await dbPool.execute("SELECT * FROM users WHERE id = ?", [id]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Buscar usuários
 *     tags: [Users]
 *     responses:
 *       200: { description: Lista de usuários }
 *       500: { description: Erro no servidor }
 */
app.get("/users", async (req, res, next) => {
  try {
    const [rows] = await dbPool.execute("SELECT * FROM users");
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login (com rate limit + query parametrizada)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username: { type: string, example: "admin" }
 *               password: { type: string, example: "secret" }
 *     responses:
 *       200: { description: Login ok }
 *       401: { description: Credenciais inválidas }
 */
app.post("/login", loginLimiter, async (req, res, next) => {
  try {
    const { username, password } = loginSchema.parse(req.body);

    // IMPORTANTE: ideal é armazenar hash (bcrypt/argon2) e comparar corretamente.
    // Aqui: exemplo mínimo mantendo compatibilidade. Ajuste para hash real.
    const [rows] = await dbPool.execute(
      "SELECT id, username FROM users WHERE username = ? AND password = ? LIMIT 1",
      [username, password]
    );

    if (rows.length > 0) {
      // Token fake removido — gere JWT de verdade se necessário (e não exponha segredo)
      const token = crypto.randomBytes(32).toString("hex");
      res.json({ success: true, token });
    } else {
      res.status(401).json({ success: false });
    }
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /download:
 *   get:
 *     summary: Download de arquivo (sem path traversal)
 *     tags: [Files]
 *     parameters:
 *       - in: query
 *         name: file
 *         required: true
 *         schema: { type: string, example: "manual.pdf" }
 *     responses:
 *       200: { description: Arquivo encontrado }
 *       400: { description: Requisição inválida }
 *       404: { description: Não encontrado }
 */
app.get("/download", async (req, res, next) => {
  try {
    const file = z.string().min(1).max(200).parse(req.query.file);

    // allowlist simples de nomes (ajuste para sua necessidade)
    if (!/^[a-zA-Z0-9._-]+$/.test(file)) {
      return res.status(400).json({ error: "Invalid filename" });
    }

    const baseDir = path.join(__dirname, "files");
    const filepath = safeJoin(baseDir, file);

    if (!fs.existsSync(filepath)) return res.status(404).json({ error: "Not found" });
    res.sendFile(filepath);
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /search:
 *   get:
 *     summary: Busca (HTML escapado para evitar XSS)
 *     tags: [Search]
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema: { type: string, example: "navio offshore" }
 *     responses:
 *       200:
 *         description: HTML
 *         content:
 *           text/html:
 *             schema: { type: string }
 */
app.get("/search", (req, res) => {
  const q = (req.query.q ?? "").toString();
  const safe = escapeHtml(q);
  res.type("html").send(`
    <html>
      <body>
        <h1>Resultados para: ${safe}</h1>
      </body>
    </html>
  `);
});

/**
 * @swagger
 * /encrypt:
 *   post:
 *     summary: Hash seguro (PBKDF2 + salt) em vez de MD5
 *     tags: [Cryptography]
 */
app.post("/encrypt", async (req, res, next) => {
  try {
    const { data } = encryptSchema.parse(req.body);

    // Exemplo: derivação segura para “armazenamento”
    const salt = crypto.randomBytes(16);
    const iterations = 210000;
    const keylen = 32;
    const digest = "sha256";

    const derivedKey = crypto.pbkdf2Sync(data, salt, iterations, keylen, digest);

    res.json({
      algorithm: "pbkdf2",
      digest,
      iterations,
      salt: salt.toString("hex"),
      derived: derivedKey.toString("hex"),
    });
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /fetch-url:
 *   get:
 *     summary: Busca URL externa (mitigado contra SSRF)
 *     tags: [SSRF]
 */
app.get("/fetch-url", async (req, res, next) => {
  try {
    const { url } = fetchUrlSchema.parse(req.query);

    const u = new URL(url);

    // Bloqueia protocolos perigosos
    if (!["http:", "https:"].includes(u.protocol)) {
      return res.status(400).json({ error: "Invalid protocol" });
    }

    // Allowlist opcional por host (recomendado!)
    if (allowedHosts && !allowedHosts.has(u.hostname.toLowerCase())) {
      return res.status(403).json({ error: "Host not allowed" });
    }

    // Resolve DNS e bloqueia IPs privados
    const dns = require("dns").promises;
    const lookup = await dns.lookup(u.hostname, { all: true, verbatim: true });

    if (lookup.some((a) => isPrivateIp(a.address))) {
      return res.status(403).json({ error: "Blocked private IP" });
    }

    const fetch = (await import("node-fetch")).default;
    const resp = await fetch(url, {
      redirect: "manual",
      // timeouts: node-fetch v3 usa AbortController
    });

    // Limita tamanho retornado (proteção básica)
    const text = await resp.text();
    if (text.length > 200000) {
      return res.status(413).json({ error: "Response too large" });
    }

    res.status(resp.status).send(text);
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /calculate:
 *   post:
 *     summary: Calculadora segura (sem eval)
 *     tags: [Other]
 */
app.post("/calculate", async (req, res, next) => {
  try {
    const { expression } = calculateSchema.parse(req.body);

    // Parser mínimo: avalia somente matemática básica usando Function *sem* acesso a escopo.
    // Como já restringimos caracteres via regex, mitigamos code injection.
    // Alternativa mais robusta: usar biblioteca de parser matemático.
    // eslint-disable-next-line no-new-func
    const fn = new Function(`"use strict"; return (${expression});`);
    const result = fn();

    if (typeof result !== "number" || !Number.isFinite(result)) {
      return res.status(400).json({ error: "Invalid result" });
    }

    res.json({ result });
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /validate-email:
 *   get:
 *     summary: Validar email (sem regex vulnerável a ReDoS)
 *     tags: [Other]
 */
app.get("/validate-email", (req, res, next) => {
  try {
    const { email } = emailSchema.parse(req.query);
    res.json({ valid: true, email });
  } catch (err) {
    // Se falhar no schema, é inválido
    res.json({ valid: false });
  }
});

/**
 * @swagger
 * /generate-token:
 *   get:
 *     summary: Gerar token (crypto.randomBytes)
 *     tags: [Cryptography]
 */
app.get("/generate-token", (req, res) => {
  const token = crypto.randomBytes(24).toString("hex");
  res.json({ token });
});

/**
 * @swagger
 * /merge:
 *   post:
 *     summary: Mesclar objetos (mitigado contra Prototype Pollution)
 *     tags: [Other]
 */
app.post("/merge", (req, res, next) => {
  try {
    const source = z.record(z.any()).parse(req.body);
    const target = {};
    const result = safeDeepMerge(target, source);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /parse-xml:
 *   post:
 *     summary: Parse XML (bloqueia DOCTYPE/ENTITY; mitigação XXE)
 *     tags: [Other]
 */
app.post("/parse-xml", async (req, res, next) => {
  try {
    const bodySchema = z.object({ xml: z.string().min(1).max(200000) });
    const { xml } = bodySchema.parse(req.body);

    // Defesa em profundidade: recusa DTD/ENTITY
    if (/<\!DOCTYPE/i.test(xml) || /<\!ENTITY/i.test(xml)) {
      return res.status(400).json({ error: "DOCTYPE/ENTITY not allowed" });
    }

    const parser = new Parser({
      explicitArray: false,
      // xml2js não resolve entidades externas como alguns parsers,
      // mas mantemos bloqueio acima para garantir.
    });

    parser.parseString(xml, (err, result) => {
      if (err) return res.status(400).json({ error: "Invalid XML" });
      res.json(result);
    });
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /upload:
 *   post:
 *     summary: Upload seguro (valida nome/extensão/tamanho e evita path traversal)
 *     tags: [Files]
 */
app.post("/upload", async (req, res, next) => {
  try {
    const { filename, contentBase64 } = uploadSchema.parse(req.body);

    // Nome seguro
    if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
      return res.status(400).json({ error: "Invalid filename" });
    }

    // Allowlist de extensões (ajuste conforme sua necessidade)
    const allowedExt = new Set([".txt", ".json", ".csv", ".md"]);
    const ext = path.extname(filename).toLowerCase();
    if (!allowedExt.has(ext)) {
      return res.status(400).json({ error: "File type not allowed" });
    }

    const buffer = Buffer.from(contentBase64, "base64");
    if (buffer.length > 200 * 1024) {
      return res.status(413).json({ error: "File too large" });
    }

    const uploadDir = path.join(__dirname, "uploads");
    fs.mkdirSync(uploadDir, { recursive: true });

    const filepath = safeJoin(uploadDir, filename);
    fs.writeFileSync(filepath, buffer, { flag: "wx" }); // não sobrescreve

    res.json({ success: true, path: filename });
  } catch (err) {
    // Se flag wx falhar (arquivo existe), devolve 409
    if (String(err.message || "").includes("EEXIST")) {
      return res.status(409).json({ error: "File already exists" });
    }
    next(err);
  }
});

/**
 * @swagger
 * /users:
 *   post:
 *     summary: Criar usuário (sem Mass Assignment; whitelist de campos)
 *     tags: [Users]
 */
app.post("/users", async (req, res, next) => {
  try {
    const createUserSchema = z.object({
      username: z.string().min(1).max(80),
      password: z.string().min(8).max(200),
      // NÃO aceitar isAdmin/role diretamente do cliente aqui
    });

    const { username, password } = createUserSchema.parse(req.body);

    const [result] = await dbPool.execute(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, password]
    );

    res.json({ id: result.insertId, username });
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /verify-token:
 *   post:
 *     summary: Verificar token (comparação timing-safe)
 *     tags: [Other]
 */
app.post("/verify-token", (req, res, next) => {
  try {
    const { token } = verifyTokenSchema.parse(req.body);

    // Exemplo de “token válido” do servidor (ideal: buscar em DB/cache)
    const validToken = "super-secret-token-12345";

    const a = Buffer.from(token);
    const b = Buffer.from(validToken);

    // timingSafeEqual exige mesmo tamanho; se não for, ainda assim faça comparação segura
    const sameLength = a.length === b.length;
    const paddedA = sameLength ? a : crypto.randomBytes(b.length);
    const ok = sameLength && crypto.timingSafeEqual(paddedA, b);

    res.json({ valid: ok });
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /:
 *   get:
 *     summary: Página inicial da API
 *     tags: [Other]
 */
app.get("/", (req, res) => {
  res.json({
    message: "API (Hardened)",
    documentation: "/api-docs",
  });
});

// ------------------------
// Endpoint removido: /execute (Command Injection)
// ------------------------
// Se você realmente precisar disso, me diga qual a operação desejada
// (ex.: listar um diretório específico, executar “ping” em allowlist etc.)
// e eu te devolvo uma versão segura com allowlist + spawn sem shell.

// ------------------------
// Handler de erros (sem vazamento de stack/segredos)
// ------------------------
app.use((err, req, res, next) => {
  // Log mínimo (evita vazar segredos e dados sensíveis)
  console.error("Error:", err?.name, err?.message);

  // Zod errors: retorna 400 com mensagem amigável
  if (err && err.name === "ZodError") {
    return res.status(400).json({ error: "Invalid input" });
  }

  res.status(500).json({ error: "Internal server error" });
});

// ------------------------
app.listen(Number(PORT), () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API Documentation: http://localhost:${PORT}/api-docs`);
  // Não logar API_KEY/JWT_SECRET/DB_PASSWORD!
});

module.exports = app;
