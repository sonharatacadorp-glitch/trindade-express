import express from "express";
import dotenv from "dotenv";
import pg from "pg";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

dotenv.config();
const { Pool } = pg;

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
});
db.query("SELECT NOW()")
  .then(() => console.log("PostgreSQL conectado com sucesso"))
  .catch((erro) => console.error("Erro ao conectar PostgreSQL:", erro.message));
  db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    nome TEXT NOT NULL,
    cpf_cnpj TEXT,
    whatsapp TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    criado_em TIMESTAMPTZ DEFAULT NOW()
  );

  ALTER TABLE users ADD COLUMN IF NOT EXISTS cpf_cnpj TEXT;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp TEXT;
  ALTER TABLE users ALTER COLUMN id DROP DEFAULT;
ALTER TABLE users ALTER COLUMN id TYPE TEXT USING id::text;
ALTER TABLE users DROP COLUMN IF EXISTS password_salt;
ALTER TABLE users DROP COLUMN IF EXISTS telefone;
`)
  .then(() => console.log("Tabela users pronta"))
  .catch((erro) => console.error("Erro ao criar/ajustar tabela users:", erro.message));
  db.query(`
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    criado_em TIMESTAMPTZ DEFAULT NOW()
  )
`)
  .then(() => console.log("Tabela sessions pronta"))
  .catch((erro) => console.error("Erro ao criar tabela sessions:", erro.message));
  db.query(`
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    numero TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,
    cliente JSONB NOT NULL,
    origem JSONB NOT NULL,
    destino JSONB NOT NULL,
    distancia_trecho_km NUMERIC,
    distancia_cobrada_km NUMERIC,
    tempo_estimado_min INTEGER,
    peso_kg NUMERIC,
    dimensoes_cm JSONB,
    servico JSONB,
    valor_base NUMERIC,
    adicional_urgente NUMERIC,
    total NUMERIC NOT NULL,
    status TEXT NOT NULL DEFAULT 'Aguardando pagamento',
    mercado_pago_order_id TEXT,
    pagamento_status TEXT,
    criado_em TIMESTAMPTZ DEFAULT NOW(),
    atualizado_em TIMESTAMPTZ DEFAULT NOW()
  )
`)
  .then(() => console.log("Tabela orders pronta"))
  .catch((erro) => console.error("Erro ao criar tabela orders:", erro.message));
const app = express();
app.use(express.json());
app.use(express.static("public"));

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, "data");
const usersFile = path.join(dataDir, "users.json");
const sessionsFile = path.join(dataDir, "sessions.json");

const ordersFile = path.join(dataDir, "orders.json");
const adminSessionsFile = path.join(dataDir, "admin_sessions.json");
fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, "[]");
if (!fs.existsSync(sessionsFile)) fs.writeFileSync(sessionsFile, "{}");
if (!fs.existsSync(ordersFile)) fs.writeFileSync(ordersFile, "[]");
if (!fs.existsSync(adminSessionsFile)) fs.writeFileSync(adminSessionsFile, "{}");

const PORT = process.env.PORT || 3000;
const PRICE_PER_KM = Number(process.env.PRICE_PER_KM || 1.5);
const MIN_PRICE = Number(process.env.MIN_PRICE || 15);
const URGENT_PERCENT = Number(process.env.URGENT_PERCENT || 0.30);
const WEIGHT_INCLUDED_KG = Number(process.env.WEIGHT_INCLUDED_KG || 20);
const EXTRA_KG_PRICE = Number(process.env.EXTRA_KG_PRICE || 0);

function readJson(file) { return JSON.parse(fs.readFileSync(file, "utf8")); }
function writeJson(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2)); }
function cleanCep(v) { return String(v || "").replace(/\D/g, ""); }
function cleanEmail(v) { return String(v || "").trim().toLowerCase(); }
function money(v) { return Math.round(v * 100) / 100; }
function token() { return crypto.randomBytes(32).toString("hex"); }
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, key] = String(stored).split(":");
  if (!salt || !key) return false;
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(key, "hex"));
}
function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k) out[k] = decodeURIComponent(v.join("="));
  }
  return out;
}
async function setSession(res, userId) {
  const t = token();

  await db.query(
    "INSERT INTO sessions (token, user_id) VALUES ($1, $2)",
    [t, userId]
  );

  res.setHeader(
    "Set-Cookie",
    `trindade_session=${encodeURIComponent(t)}; HttpOnly; SameSite=Lax; Path=/`
  );
}
async function currentUser(req) {
  const cookies = parseCookies(req);
  const t = cookies.trindade_session;

  if (!t) return null;

  const result = await db.query(`
    SELECT
      u.id,
      u.nome,
      u.cpf_cnpj AS "cpfCnpj",
      u.whatsapp,
      u.email
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = $1
    LIMIT 1
  `, [t]);

  return result.rows[0] || null;
}

async function requireAuth(req, res, next) {
  try {
    const user = await currentUser(req);

    if (!user) {
      return res.status(401).json({ error: "Faça login para continuar." });
    }

    req.user = user;
    next();
  } catch (erro) {
    console.error("Erro ao validar sessão:", erro);
    res.status(500).json({ error: "Erro ao validar sessão." });
  }
}

function adminCredentials() {
  return {
    email: cleanEmail(process.env.ADMIN_EMAIL || ""),
    password: String(process.env.ADMIN_PASSWORD || "")
  };
}
function setAdminSession(res) {
  const t = token();
  const sessions = readJson(adminSessionsFile);
  sessions[t] = { createdAt: new Date().toISOString() };
  writeJson(adminSessionsFile, sessions);
  res.setHeader("Set-Cookie", `trindade_admin_session=${encodeURIComponent(t)}; HttpOnly; SameSite=Lax; Path=/admin`);
}
function isAdmin(req) {
  const cookies = parseCookies(req);
  const t = cookies.trindade_admin_session;
  if (!t) return false;
  const sessions = readJson(adminSessionsFile);
  return Boolean(sessions[t]);
}
function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(401).json({ error: "Acesso administrativo não autorizado." });
  next();
}

app.post("/api/admin/login", (req, res) => {
  const { email, senha } = req.body || {};
  const cfg = adminCredentials();
  if (!cfg.email || !cfg.password) return res.status(503).json({ error: "Administrador ainda não configurado. Crie o arquivo .env com ADMIN_EMAIL e ADMIN_PASSWORD." });
  if (cleanEmail(email) !== cfg.email || String(senha || "") !== cfg.password) {
    return res.status(401).json({ error: "E-mail ou senha administrativa incorretos." });
  }
  setAdminSession(res);
  res.json({ ok: true });
});

app.post("/api/admin/logout", (req, res) => {
  const cookies = parseCookies(req);
  const t = cookies.trindade_admin_session;
  if (t) { const sessions = readJson(adminSessionsFile); delete sessions[t]; writeJson(adminSessionsFile, sessions); }
  res.setHeader("Set-Cookie", "trindade_admin_session=; HttpOnly; SameSite=Lax; Path=/admin; Max-Age=0");
  res.json({ ok: true });
});

app.get("/api/admin/me", (req, res) => {
  res.json({ authenticated: isAdmin(req) });
});

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const orders = readJson(ordersFile).slice().sort((a,b) => new Date(b.criadoEm) - new Date(a.criadoEm));
  res.json({ orders });
});

const ORDER_STATUSES = ["Aguardando pagamento", "Pagamento aprovado", "Coleta agendada", "Coletado", "Em trânsito", "Entregue", "Cancelado"];
app.patch("/api/admin/orders/:id/status", requireAdmin, (req, res) => {
  const status = String(req.body?.status || "");
  if (!ORDER_STATUSES.includes(status)) return res.status(400).json({ error: "Status inválido." });
  const orders = readJson(ordersFile);
  const order = orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: "Pedido não encontrado." });
  order.status = status;
  order.atualizadoEm = new Date().toISOString();
  writeJson(ordersFile, orders);
  res.json({ order });
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const orders = readJson(ordersFile);
  const total = orders.reduce((sum, o) => sum + Number(o.total || 0), 0);
  const entregues = orders.filter(o => o.status === "Entregue").length;
  const pendentes = orders.filter(o => !["Entregue", "Cancelado"].includes(o.status)).length;
  res.json({ totalPedidos: orders.length, valorTotal: money(total), entregues, pendentes });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { nome, cpfCnpj, whatsapp, email, senha } = req.body;

    const name = String(nome || "").trim();
    const mail = cleanEmail(email);
    const whats = String(whatsapp || "").trim();

    if (name.length < 3) {
      return res.status(400).json({ error: "Informe seu nome completo." });
    }

    if (!mail.includes("@") || mail.length < 6) {
      return res.status(400).json({ error: "Informe um e-mail válido." });
    }

    if (String(senha || "").length < 6) {
      return res.status(400).json({ error: "A senha deve ter pelo menos 6 caracteres." });
    }

    if (!whats) {
      return res.status(400).json({ error: "Informe seu WhatsApp." });
    }

    const existente = await db.query(
      "SELECT id FROM users WHERE email = $1 LIMIT 1",
      [mail]
    );

    if (existente.rows.length) {
      return res.status(409).json({ error: "Este e-mail já está cadastrado." });
    }

    const user = {
      id: crypto.randomUUID(),
      nome: name,
      cpfCnpj: String(cpfCnpj || "").trim(),
      whatsapp: whats,
      email: mail,
      passwordHash: hashPassword(String(senha))
    };

    await db.query(
      `INSERT INTO users
       (id, nome, cpf_cnpj, whatsapp, email, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        user.id,
        user.nome,
        user.cpfCnpj,
        user.whatsapp,
        user.email,
        user.passwordHash
      ]
    );

    await setSession(res, user.id);

    res.status(201).json({
      user: {
        id: user.id,
        nome: user.nome,
        email: user.email,
        whatsapp: user.whatsapp
      }
    });
  } catch (erro) {
    console.error("Erro ao criar conta:", erro);
    res.status(500).json({ error: "Não foi possível criar sua conta." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;
    const mail = cleanEmail(email);

    const result = await db.query(
      `SELECT
        id,
        nome,
        cpf_cnpj AS "cpfCnpj",
        whatsapp,
        email,
        password_hash AS "passwordHash"
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [mail]
    );

    const user = result.rows[0];

    if (!user || !verifyPassword(String(senha || ""), user.passwordHash)) {
      return res.status(401).json({ error: "E-mail ou senha incorretos." });
    }

    await setSession(res, user.id);

    res.json({
      user: {
        id: user.id,
        nome: user.nome,
        email: user.email,
        whatsapp: user.whatsapp
      }
    });
  } catch (erro) {
    console.error("Erro ao fazer login:", erro);
    res.status(500).json({ error: "Não foi possível fazer login." });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const t = cookies.trindade_session;

    if (t) {
      await db.query(
        "DELETE FROM sessions WHERE token = $1",
        [t]
      );
    }

    res.setHeader(
      "Set-Cookie",
      "trindade_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
    );

    res.json({ ok: true });
  } catch (erro) {
    console.error("Erro ao sair da conta:", erro);
    res.status(500).json({ error: "Não foi possível sair da conta." });
  }
});

app.get("/api/auth/me", async (req, res) => {
  try {
    const user = await currentUser(req);

    if (!user) {
      return res.status(401).json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      user: {
        id: user.id,
        nome: user.nome,
        email: user.email,
        whatsapp: user.whatsapp
      }
    });
  } catch (erro) {
    console.error("Erro ao consultar usuário:", erro);
    res.status(500).json({ error: "Não foi possível consultar o usuário." });
  }
});

async function viaCep(cep) {
  try {
    console.log("Consultando ViaCEP:", cep);

    const r = await fetch(`https://brasilapi.com.br/api/cep/v1/${cep}`);

    console.log("ViaCEP respondeu com HTTP:", r.status);

    if (!r.ok) {
      throw new Error(`ViaCEP respondeu HTTP ${r.status}`);
    }

    const data = await r.json();
data.localidade = data.city;
data.uf = data.state;
data.logradouro = data.street || "";
data.bairro = data.neighborhood || "";
    if (data.erro) {
      throw new Error(`CEP não encontrado: ${cep}`);
    }

    return data;

  } catch (e) {
    console.error("ERRO VIACEP:", e);
    console.error("CAUSA VIACEP:", e.cause);
    throw new Error(`Falha ViaCEP: ${e.message}`);
  }
}
async function geocode(address) {
  const q = encodeURIComponent(
    `${address.logradouro}, ${address.localidade}, ${address.uf}, Brasil`
  );

  const url = `https://nominatim.openstreetmap.org/search?format=jsonv2&limit=1&countrycodes=br&q=${q}`;

  const r = await fetch(url, {
    headers: {
      "User-Agent": "TrindadeExpress/2.0 (cotacao)"
    }
  });

  if (!r.ok) {
    throw new Error("Não foi possível localizar o endereço no mapa.");
  }

  const data = await r.json();

  if (!data.length) {
    throw new Error("Endereço não localizado no mapa.");
  }

  return {
    lat: Number(data[0].lat),
    lon: Number(data[0].lon)
  };
}

async function route(a, b) {
  const url = `https://router.project-osrm.org/route/v1/driving/${a.lon},${a.lat};${b.lon},${b.lat}?overview=false`;

  const r = await fetch(url);

  if (!r.ok) {
    throw new Error("Falha ao calcular a rota.");
  }

  const data = await r.json();

  if (data.code !== "Ok" || !data.routes?.length) {
    throw new Error("Rota não encontrada.");
  }

  return {
    km: data.routes[0].distance / 1000,
    minutes: Math.round(data.routes[0].duration / 60)
  };
}
app.post("/api/quote", requireAuth, async (req, res) => {
  try {
    const { origemCep, destinoCep, peso, comprimento, largura, altura, servico, idaRetorno = true } = req.body;
    const oCep = cleanCep(origemCep), dCep = cleanCep(destinoCep), kg = Number(peso);
    if (oCep.length !== 8 || dCep.length !== 8 || !kg || kg <= 0) return res.status(400).json({ error: "Informe CEPs válidos e um peso maior que zero." });
    console.log("TESTE: iniciando consulta ViaCEP");
    const [origem, destino] = await Promise.all([viaCep(oCep), viaCep(dCep)]);
    console.log("TESTE: ViaCEP funcionou. Iniciando geocode");
    const [oGeo, dGeo] = await Promise.all([geocode(origem), geocode(destino)]);
    console.log("TESTE: geocode funcionou. Iniciando cálculo da rota");
    const r = await route(oGeo, dGeo);
    const kmTrecho = r.km, kmCobrado = idaRetorno ? kmTrecho * 2 : kmTrecho;
    let base = Math.max(MIN_PRICE, kmCobrado * PRICE_PER_KM);
    const extraKg = Math.max(0, kg - WEIGHT_INCLUDED_KG); base += extraKg * EXTRA_KG_PRICE;
    const urgente = servico === "urgente", adicionalUrgente = urgente ? base * URGENT_PERCENT : 0;
    const total = money(base + adicionalUrgente);
    res.json({
      cliente: { id: req.user.id, nome: req.user.nome },
      origem: { cep: oCep, cidade: origem.localidade, uf: origem.uf },
      destino: { cep: dCep, cidade: destino.localidade, uf: destino.uf },
      distanciaTrechoKm: money(kmTrecho), distanciaCobradaKm: money(kmCobrado),
      tempoEstimadoMin: r.minutes * (idaRetorno ? 2 : 1), pesoKg: kg,
      dimensoesCm: { comprimento: Number(comprimento)||0, largura: Number(largura)||0, altura: Number(altura)||0 },
      servico: urgente ? "Urgente" : "Programada", valorBase: money(base), adicionalUrgente: money(adicionalUrgente), total, moeda: "BRL"
    });
} catch (e) {
  console.error("ERRO NA COTACAO:", e);
  res.status(500).json({ error: e.message || "Erro ao calcular cotação." });
}
});

app.post("/api/orders", requireAuth, (req, res) => {
  try {
    const q = req.body?.quote;
    if (!q || !q.total || !q.origem?.cep || !q.destino?.cep) {
      return res.status(400).json({ error: "Cotação inválida para criar o pedido." });
    }
    const total = Number(q.total);
    if (!Number.isFinite(total) || total <= 0) return res.status(400).json({ error: "Valor da cotação inválido." });
    const orders = readJson(ordersFile);
    const order = {
      id: crypto.randomUUID(),
      numero: `TE-${String(orders.length + 1).padStart(6, "0")}`,
      userId: req.user.id,
      cliente: { nome: req.user.nome, email: req.user.email, whatsapp: req.user.whatsapp },
      origem: q.origem,
      destino: q.destino,
      distanciaTrechoKm: q.distanciaTrechoKm,
      distanciaCobradaKm: q.distanciaCobradaKm,
      tempoEstimadoMin: q.tempoEstimadoMin,
      pesoKg: q.pesoKg,
      dimensoesCm: q.dimensoesCm,
      servico: q.servico,
      valorBase: q.valorBase,
      adicionalUrgente: q.adicionalUrgente,
      total,
      status: "Aguardando pagamento",
      criadoEm: new Date().toISOString(),
      atualizadoEm: new Date().toISOString()
    };
    orders.push(order);
    writeJson(ordersFile, orders);
    res.status(201).json({ order });
  } catch (e) {
    res.status(500).json({ error: "Não foi possível criar o pedido." });
  }
});

app.get("/api/orders", requireAuth, (req, res) => {
  const orders = readJson(ordersFile).filter(o => o.userId === req.user.id);
  res.json({ orders });
});

app.post("/api/payment/pix", requireAuth, async (req, res) => {
  const tokenMP = process.env.MERCADOPAGO_ACCESS_TOKEN;

  if (!tokenMP) {
    return res.status(503).json({
      error: "Mercado Pago ainda não configurado."
    });
  }

  try {
    const { amount, email, reference } = req.body;
    const value = Number(amount);

    if (!value || value <= 0 || !email) {
      return res.status(400).json({
        error: "Valor e e-mail são obrigatórios."
      });
    }

    const idempotencyKey = crypto.randomUUID();

    const mp = await fetch("https://api.mercadopago.com/v1/orders", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${tokenMP}`,
        "X-Idempotency-Key": idempotencyKey
      },
      body: JSON.stringify({
        type: "online",
        processing_mode: "automatic",
        total_amount: value.toFixed(2),
        external_reference: reference || `TRINDADE-${Date.now()}`,
        payer: {
          email: email,
          first_name: "APRO"
        },
        transactions: {
          payments: [
            {
              amount: value.toFixed(2),
              payment_method: {
                id: "pix",
                type: "bank_transfer"
              }
            }
          ]
        }
      })
    });

    const data = await mp.json();

    if (!mp.ok) {
      return res.status(mp.status).json({
        error: "Mercado Pago recusou a criação da order.",
        details: data
      });
    }

    const payment = data.transactions?.payments?.[0] || {};
    const method = payment.payment_method || {};
const orders = readJson(ordersFile);
const pedido = orders.find(o => o.numero === reference);

if (pedido) {
  pedido.mercadoPagoOrderId = data.id;
  pedido.pagamentoStatus = payment.status || data.status;
  pedido.atualizadoEm = new Date().toISOString();
  writeJson(ordersFile, orders);
}
    res.json({
      orderId: data.id,
      status: payment.status || data.status,
      statusDetail: payment.status_detail || data.status_detail,
      qrCode: method.qr_code || null,
      qrCodeBase64: method.qr_code_base64 || null,
      ticketUrl: method.ticket_url || null
    });

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao criar order PIX."
    });
  }
});

// CONSULTAR STATUS DO PAGAMENTO NO MERCADO PAGO
app.get("/api/payment/status/:numero", requireAuth, async (req, res) => {
  const tokenMP = process.env.MERCADOPAGO_ACCESS_TOKEN;

  if (!tokenMP) {
    return res.status(503).json({
      error: "Mercado Pago ainda não configurado."
    });
  }

  try {
    const orders = readJson(ordersFile);
    const pedido = orders.find(
      o => o.numero === req.params.numero && o.userId === req.user.id
    );

    if (!pedido) {
      return res.status(404).json({
        error: "Pedido não encontrado."
      });
    }

    if (!pedido.mercadoPagoOrderId) {
      return res.status(400).json({
        error: "Este pedido ainda não possui pagamento PIX."
      });
    }

    const mp = await fetch(
      `https://api.mercadopago.com/v1/orders/${pedido.mercadoPagoOrderId}`,
      {
        headers: {
          "Authorization": `Bearer ${tokenMP}`
        }
      }
    );

    const data = await mp.json();

    if (!mp.ok) {
      return res.status(mp.status).json({
        error: "Não foi possível consultar o Mercado Pago.",
        details: data
      });
    }

    const payment = data.transactions?.payments?.[0] || {};
    const pagamentoStatus = payment.status || data.status;

    pedido.pagamentoStatus = pagamentoStatus;
    pedido.atualizadoEm = new Date().toISOString();

    if (
      pagamentoStatus === "approved" ||
      data.status === "processed"
    ) {
      pedido.status = "Pagamento aprovado";
    }

    writeJson(ordersFile, orders);

    res.json({
      pedido: pedido.numero,
      status: pedido.status,
      pagamentoStatus: pedido.pagamentoStatus,
      mercadoPagoStatus: data.status,
      mercadoPagoStatusDetail:
        payment.status_detail || data.status_detail || null
    });

  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Erro ao consultar status do pagamento."
    });
  }
});

// WEBHOOK MERCADO PAGO
app.post("/api/webhook/mercadopago", async (req, res) => {
  try {
const secret = process.env.MERCADOPAGO_WEBHOOK_SECRET;
const xSignature = req.headers["x-signature"];
const xRequestId = req.headers["x-request-id"];
const dataId = String(req.query?.["data.id"] || req.body?.data?.id || "");

if (!secret || !xSignature || !xRequestId || !dataId) {
  console.error("Webhook sem dados necessários para validar assinatura.");
  return res.sendStatus(401);
}

let ts = "";
let v1 = "";

for (const parte of xSignature.split(",")) {
  const [chave, valor] = parte.split("=");
  if (chave?.trim() === "ts") ts = valor?.trim() || "";
  if (chave?.trim() === "v1") v1 = valor?.trim() || "";
}

const manifest = `id:${dataId};request-id:${xRequestId};ts:${ts};`;

const assinaturaCalculada = crypto
  .createHmac("sha256", secret)
  .update(manifest)
  .digest("hex");

const assinaturaValida =
  v1.length === assinaturaCalculada.length &&
  crypto.timingSafeEqual(
    Buffer.from(v1),
    Buffer.from(assinaturaCalculada)
  );

if (!assinaturaValida) {
  console.error("Webhook Mercado Pago com assinatura inválida.");
  return res.sendStatus(401);
}

res.sendStatus(200);

    const orderId =
      req.body?.data?.id ||
      req.query?.["data.id"];

    if (!orderId) {
      console.log("Webhook recebido sem Order ID.");
      return;
    }

    console.log("Webhook Mercado Pago - Order:", orderId);

    const tokenMP = process.env.MERCADOPAGO_ACCESS_TOKEN;

    if (!tokenMP) {
      console.log("Token do Mercado Pago não configurado.");
      return;
    }

    const mp = await fetch(
      `https://api.mercadopago.com/v1/orders/${orderId}`,
      {
        headers: {
          "Authorization": `Bearer ${tokenMP}`
        }
      }
    );

    const data = await mp.json();

    if (!mp.ok) {
      console.error("Erro ao consultar Order:", data);
      return;
    }

    const payment = data.transactions?.payments?.[0] || {};
    const pagamentoStatus = payment.status || data.status;

    const orders = readJson(ordersFile);

    const pedido = orders.find(
      o => o.mercadoPagoOrderId === orderId
    );

    if (!pedido) {
      console.log("Pedido local não encontrado para Order:", orderId);
      return;
    }

    pedido.pagamentoStatus = pagamentoStatus;
    pedido.atualizadoEm = new Date().toISOString();

    if (
      pagamentoStatus === "approved" ||
      data.status === "processed"
    ) {
      pedido.status = "Pagamento aprovado";
    }

    writeJson(ordersFile, orders);

    console.log(
      `Pedido ${pedido.numero} atualizado: ${pedido.status}`
    );

  } catch (e) {
    console.error("Erro no webhook Mercado Pago:", e);
  }
});
app.get("/api/health", async (req, res) => {
  const resultados = {};

  for (const [nome, url] of [
    ["google", "https://www.google.com"],
    ["brasilapi", "https://brasilapi.com.br/api/cep/v1/14020000"]
  ]) {
    try {
      const r = await fetch(url);
      resultados[nome] = {
        ok: r.ok,
        status: r.status
      };
    } catch (e) {
      resultados[nome] = {
        ok: false,
        erro: e.message,
        causa: e.cause?.code || null
      };
    }
  }

  res.json(resultados);
});
app.listen(PORT, () => console.log(`Trindade Express em http://localhost:${PORT}`));
