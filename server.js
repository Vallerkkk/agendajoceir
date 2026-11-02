/* Backend da Agenda do Joceir — Render (Node.js + Express)
   - Serve o site estático (index.html)
   - API /api/eventos conversa com o Supabase usando a SECRET key
     (variável de ambiente — a chave nunca aparece no navegador)
*/
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const webpush = require("web-push");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

const VAPID_PUBLICA = process.env.VAPID_PUBLIC_KEY || null;
const VAPID_PRIVADA = process.env.VAPID_PRIVATE_KEY || null;
const VAPID_CONTATO = process.env.VAPID_SUBJECT || "mailto:agenda@joceir.local";
const CRON_TOKEN = process.env.CRON_TOKEN || null;

const EMAIL_PARA = process.env.EMAIL_PARA || null;   /* ex.: joceircipriano@gmail.com */
const SMTP_HOST = process.env.SMTP_HOST || null;     /* ex.: smtp.gmail.com */
const SMTP_PORT = process.env.SMTP_PORT || "465";
const SMTP_USUARIO = process.env.SMTP_USUARIO || null;
const SMTP_SENHA = process.env.SMTP_SENHA || null;   /* senha de app (Gmail) ou chave SMTP (Brevo) */
const SITE_URL = process.env.SITE_URL || "https://agendajoceir.onrender.com";

if (VAPID_PUBLICA && VAPID_PRIVADA) {
  webpush.setVapidDetails(VAPID_CONTATO, VAPID_PUBLICA, VAPID_PRIVADA);
}

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.warn("AVISO: defina as variáveis SUPABASE_URL e SUPABASE_SECRET_KEY.");
}

app.use(express.json({ limit: "2mb" }));

/* ---------- helpers do Supabase (REST/PostgREST) ---------- */
function sbHeaders() {
  return {
    apikey: SUPABASE_SECRET_KEY,
    Authorization: "Bearer " + SUPABASE_SECRET_KEY,
    "Content-Type": "application/json",
  };
}

async function sbFetch(caminho, opts = {}) {
  const resp = await fetch(SUPABASE_URL + "/rest/v1/" + caminho, {
    ...opts,
    headers: { ...sbHeaders(), ...(opts.headers || {}) },
  });
  if (!resp.ok) {
    const corpo = await resp.text().catch(() => "");
    throw new Error("Supabase " + resp.status + ": " + corpo);
  }
  const texto = await resp.text();
  return texto ? JSON.parse(texto) : null;
}

async function listarEventos() {
  const rows = await sbFetch("agenda_eventos?select=id,dados,atualizado_em&order=atualizado_em.asc");
  return rows || [];
}

async function salvarEventos(eventos) {
  const agora = new Date().toISOString();
  const atuais = new Set(eventos.map(e => e.id));

  if (eventos.length) {
    const linhas = eventos.map(e => ({ id: e.id, dados: e, atualizado_em: agora }));
    await sbFetch("agenda_eventos?on_conflict=id", {
      method: "POST",
      headers: { ...sbHeaders(), Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify(linhas),
    });
  }

  const existentes = await listarEventos();
  const sobrando = existentes.map(r => r.id).filter(id => !atuais.has(id));
  if (sobrando.length) {
    await sbFetch(
      "agenda_eventos?id=in.(" + sobrando.map(encodeURIComponent).join(",") + ")",
      { method: "DELETE", headers: sbHeaders() }
    );
  }
  return listarEventos();
}

/* ---------- acesso (login) ---------- */
/* O navegador deriva hash = PBKDF2(senha, salt); a senha nunca chega ao servidor.
   A tabela agenda_acesso guarda uma única linha (id=1). */
async function lerAcesso() {
  const rows = await sbFetch("agenda_acesso?select=usuario,salt,hash&id=eq.1&limit=1");
  return (rows && rows[0]) || null;
}

const sessoesRevogadas = new Set(); /* saídas feitas enquanto o processo estava ativo */
const DIA_MS = 24 * 3600 * 1000;
const VALIDADE_SESSAO = 30 * DIA_MS;
/* Segredo que assina o token: uma variável própria ou, na falta, a chave do banco.
   Como o token é auto-validável, a sessão sobrevive a reinícios do servidor. */
const SEGREDOS_SESSAO = process.env.SESSION_SECRET || SUPABASE_SECRET_KEY || "agenda-joceir";

function assinar(texto) {
  return crypto.createHmac("sha256", SEGREDOS_SESSAO).update(texto).digest("hex");
}
function novoToken() {
  const corpo = crypto.randomBytes(16).toString("hex") + "." + (Date.now() + VALIDADE_SESSAO);
  return corpo + "." + assinar(corpo);
}
function tokenDaSessao(req) {
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)agenda_sessao=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}
function sessaoValida(req) {
  const t = tokenDaSessao(req);
  if (!t || sessoesRevogadas.has(t)) return false;
  const partes = t.split(".");
  if (partes.length !== 3) return false;
  const [nonce, expStr, sig] = partes;
  const esperado = assinar(nonce + "." + expStr);
  let ok = false;
  try {
    ok = sig.length === esperado.length &&
      crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(esperado, "hex"));
  } catch { return false; }
  return ok && Number(expStr) > Date.now();
}
function exigirSessao(req, res, next) {
  if (sessaoValida(req)) return next();
  res.status(401).json({ erro: "não autenticado" });
}
function definirCookie(res, token) {
  res.setHeader("Set-Cookie",
    "agenda_sessao=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000; Secure");
}

/* ---------- API ---------- */
app.get("/api/acesso", async (req, res) => {
  try {
    if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) throw new Error("banco não configurado");
    const a = await lerAcesso();
    res.json({ cadastrado: !!a, usuario: a ? a.usuario : null, salt: a ? a.salt : null });
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha ao ler o cadastro de acesso" });
  }
});

app.post("/api/acesso", async (req, res) => {
  try {
    const { usuario, salt, hash } = req.body || {};
    if (!usuario || String(usuario).trim().length < 2 || String(usuario).length > 80)
      return res.status(400).json({ erro: "usuário inválido" });
    if (!/^[a-f0-9]{32}$/.test(salt || "")) return res.status(400).json({ erro: "salt inválido" });
    if (!/^[a-f0-9]{64}$/.test(hash || "")) return res.status(400).json({ erro: "hash inválido" });
    if (await lerAcesso()) return res.status(409).json({ erro: "já existe um acesso cadastrado" });
    await sbFetch("agenda_acesso", {
      method: "POST",
      headers: { ...sbHeaders(), Prefer: "return=minimal" },
      body: JSON.stringify({ id: 1, usuario: String(usuario).trim(), salt, hash }),
    });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha ao criar o acesso" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { usuario, hash } = req.body || {};
    const a = await lerAcesso();
    if (!a) return res.status(400).json({ erro: "nenhum acesso cadastrado" });
    const esperado = Buffer.from(a.hash, "hex");
    const recebido = Buffer.from(/^[a-f0-9]{64}$/.test(hash || "") ? hash : "0".repeat(64), "hex");
    if (usuario !== a.usuario || !crypto.timingSafeEqual(esperado, recebido))
      return res.status(401).json({ erro: "usuário ou senha incorretos" });
    const token = novoToken();
    definirCookie(res, token);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha ao entrar" });
  }
});

app.post("/api/sair", (req, res) => {
  const t = tokenDaSessao(req);
  if (t) sessoesRevogadas.add(t);
  res.setHeader("Set-Cookie", "agenda_sessao=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Secure");
  res.json({ ok: true });
});

app.get("/api/eventos", exigirSessao, async (req, res) => {
  try {
    if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) throw new Error("banco não configurado");
    res.json(await listarEventos());
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha ao ler o banco de dados" });
  }
});

app.put("/api/eventos", exigirSessao, async (req, res) => {
  try {
    if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) throw new Error("banco não configurado");
    const eventos = req.body && Array.isArray(req.body.eventos) ? req.body.eventos : null;
    if (!eventos) return res.status(400).json({ erro: "envie { eventos: [...] }" });
    res.json(await salvarEventos(eventos));
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha ao gravar no banco de dados" });
  }
});

app.get("/api/saude", (req, res) => res.json({ ok: true }));

/* ---------- notificações push (lembrete diário às 09:00) ---------- */
/* A tabela agenda_push guarda uma linha por dispositivo: endpoint + subscription. */

app.get("/api/push-chave", (req, res) => {
  res.json({ publicKey: VAPID_PUBLICA, pronta: !!(VAPID_PUBLICA && VAPID_PRIVADA) });
});

/* Inscrição é pública: o lembrete das 09:00 não contém dados da agenda,
   então qualquer aparelho pode se cadastrar mesmo sem ter entrado. */
app.post("/api/inscricoes", async (req, res) => {
  try {
    const s = req.body || {};
    if (typeof s.endpoint !== "string" || s.endpoint.length > 2000)
      return res.status(400).json({ erro: "inscrição inválida" });
    if (!/^https:\/\//.test(s.endpoint) || !s.keys || !s.keys.p256dh || !s.keys.auth)
      return res.status(400).json({ erro: "inscrição inválida" });
    await sbFetch("agenda_push?on_conflict=endpoint", {
      method: "POST",
      headers: { ...sbHeaders(), Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify({ endpoint: s.endpoint, dados: s }),
    });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha ao guardar a inscrição" });
  }
});

app.delete("/api/inscricoes", exigirSessao, async (req, res) => {
  try {
    const endpoint = (req.body || {}).endpoint || "";
    if (!endpoint) return res.status(400).json({ erro: "envie { endpoint }" });
    await sbFetch("agenda_push?endpoint=eq." + encodeURIComponent(endpoint),
      { method: "DELETE", headers: sbHeaders() });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha ao remover a inscrição" });
  }
});

/* Chamado uma vez por dia pelo agendador externo (cron) às 09:00 de Brasília. */

function hojeSaoPaulo() {
  return new Intl.DateTimeFormat("sv-SE", { timeZone: "America/Sao_Paulo" }).format(new Date());
}

const NOMES_CAT = {
  boletorecorrente: "Boleto recorrente", boletoesp: "Boleto esporádico", visita: "Visita a cliente",
  compromisso: "Compromisso", retorno: "Retorno a cliente", consulta: "Consulta médica",
};

function resumoDoDia(rows, hoje) {
  const dia = Number(hoje.slice(8, 10));
  const doDia = (rows || []).map(r => r.dados).filter(e =>
    e.tipo === "boletorecorrente" ? Number(e.diaMes) === dia : e.data === hoje
  );
  if (!doDia.length) return "Nenhum evento para hoje.";
  return doDia.map(e => {
    const extra = [e.valor ? "R$ " + e.valor : "", e.pessoa || ""].filter(Boolean).join(" · ");
    return "- " + (NOMES_CAT[e.tipo] || e.tipo) + ": " + e.titulo + (extra ? " (" + extra + ")" : "");
  }).join("\n");
}

async function enviarEmail(resumo, hoje) {
  const transportador = nodemailer.createTransport({
    host: SMTP_HOST, port: Number(SMTP_PORT), secure: String(SMTP_PORT) === "465",
    auth: { user: SMTP_USUARIO, pass: SMTP_SENHA },
  });
  const dataBR = hoje.split("-").reverse().join("/");
  await transportador.sendMail({
    from: '"Agenda J&S" <' + SMTP_USUARIO + ">",
    to: EMAIL_PARA,
    subject: "Checar agenda! (" + dataBR + ")",
    text: "Checar agenda!\n\nBom dia! Sua agenda de " + dataBR + ":\n"
      + resumo + "\n\nAbrir agenda: " + SITE_URL + "\n",
  });
}

app.post("/api/despacho", async (req, res) => {
  try {
    if (!CRON_TOKEN) return res.status(503).json({ erro: "CRON_TOKEN não configurado" });
    if (req.headers["x-agenda-token"] !== CRON_TOKEN)
      return res.status(401).json({ erro: "token inválido" });
    if (!VAPID_PUBLICA || !VAPID_PRIVADA)
      return res.status(503).json({ erro: "chaves VAPID não configuradas" });

    const linhas = await sbFetch("agenda_push?select=endpoint,dados");
    const corpo = JSON.stringify({
      title: "Agenda J&S",
      body: "Bom dia! Hora de checar a agenda de hoje.",
      tag: "agenda-diaria",
      data: { url: "/" },
    });

    let enviados = 0, mortas = 0, falhas = 0;
    for (const linha of linhas || []) {
      try {
        await webpush.sendNotification(linha.dados, corpo);
        enviados++;
      } catch (e) {
        if (e && (e.statusCode === 404 || e.statusCode === 410)) {
          await sbFetch("agenda_push?endpoint=eq." + encodeURIComponent(linha.endpoint),
            { method: "DELETE", headers: sbHeaders() }).catch(() => {});
          mortas++;
        } else {
          console.error("push falhou", linha.endpoint.slice(0, 60), e && e.statusCode);
          falhas++;
        }
      }
    }
    let email = "nao configurado";
    if (EMAIL_PARA && SMTP_HOST && SMTP_USUARIO && SMTP_SENHA) {
      try {
        const eventos = await listarEventos();
        await enviarEmail(resumoDoDia(eventos, hojeSaoPaulo()), hojeSaoPaulo());
        email = "enviado";
      } catch (e) {
        console.error("email falhou:", e.message);
        email = "erro";
      }
    }

    res.json({ total: (linhas || []).length, enviados, mortas, falhas, email });
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha no disparo" });
  }
});

/* ---------- site estático ---------- */
app.use(express.static(path.join(__dirname)));

app.listen(PORT, () => console.log("Agenda do Joceir rodando na porta " + PORT));
