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

const EMAIL_PARA = (process.env.EMAIL_PARA || "").split(/[,;]/).map(s => s.trim()).filter(Boolean);
const EMAIL_DESDE = process.env.EMAIL_DESDE || "joceiragenda@gmail.com";
const BREVO_API_KEY = process.env.BREVO_API_KEY || null; /* envia por HTTPS — funciona no Render grátis */
/* aceita "27 999795399", "27999795399" ou "+5527999795399" */
const SMS_PARA = (process.env.SMS_PARA || "")
  .split(/[,;]/)
  .map(s => s.replace(/\D/g, ""))
  .filter(Boolean)
  .map(d => (d.startsWith("55") || d.length <= 9 ? d : "55" + d));
const SMS_REMETENTE = process.env.SMS_REMETENTE || "AgendaJS"; /* nome aprovado na Brevo para SMS */
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

/* Chamado pelo agendador externo (cron) às 09:00 e às 15:00 de Brasília. */

function hojeSaoPaulo() {
  return new Intl.DateTimeFormat("sv-SE", { timeZone: "America/Sao_Paulo" }).format(new Date());
}

const NOMES_CAT = {
  boletorecorrente: "Boleto recorrente", boletoesp: "Boleto esporádico", visita: "Visita a cliente",
  compromisso: "Compromisso", compromissorecorrente: "Compromisso recorrente",
  retorno: "Retorno a cliente", consulta: "Consulta médica",
};

function resumoDoDia(rows, hoje) {
  const dia = Number(hoje.slice(8, 10));
  /* recorrente é o que tem diaMes: repete todo mês, sem data fixa */
  const doDia = (rows || []).map(r => r.dados).filter(e =>
    e.diaMes ? Number(e.diaMes) === dia : e.data === hoje
  );
  if (!doDia.length) return "Nenhum evento para hoje.";
  return doDia.map(e => {
    const extra = [
      e.valor ? "R$ " + e.valor : "",
      e.pessoa || "",
      e.telefone ? "tel. " + e.telefone : "",
    ].filter(Boolean).join(" · ");
    let linha = "- " + (NOMES_CAT[e.tipo] || e.tipo) + ": " + e.titulo + (extra ? " (" + extra + ")" : "");
    if (e.endereco) linha += "\n   endereço: " + e.endereco;
    return linha;
  }).join("\n");
}

const MSG = {
  manha: { saudacao: "Bom dia", tag: "agenda-manha" },
  tarde: { saudacao: "Boa tarde", tag: "agenda-tarde" },
};
const frase = m => m.saudacao + " Joceir, cheque a agenda.";

/* ---------- boletos em atraso (mesma regra do index.html) ---------- */
const CAT_COM_VALOR = new Set(["boletorecorrente", "boletoesp"]);
const valorNum = v => parseFloat(String(v || "0").replace(/\./g, "").replace(",", ".")) || 0;
const reais = v => "R$ " + v.toLocaleString("pt-BR", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const pagoEm = (e, data) => !!(e && Array.isArray(e.pagos) && e.pagos.includes(data));

/* Data em que o evento vence num mês (recorrente: diaMes, recuado para o último
   dia quando o mês é mais curto; pontual: a própria data, só naquele mês) */
function ocorrenciaNoMes(e, ano, mes) {
  if (e.diaMes) {
    const ultimo = new Date(ano, mes, 0).getDate();
    const dia = Math.min(Number(e.diaMes) || 1, ultimo);
    return `${ano}-${String(mes).padStart(2, "0")}-${String(dia).padStart(2, "0")}`;
  }
  if (!e.data) return null;
  const [a, m] = e.data.split("-").map(Number);
  return (a === ano && m === mes) ? e.data : null;
}

/* Vencimento já passado (hoje ou antes) mais recente do evento.
   Pontual vence uma única vez e continua em atraso até ser pago;
   recorrente retrocede mês a mês até achar a ocorrência vencida mais recente. */
function ultimoVencimento(e, hoje) {
  if (!e.diaMes) return e.data && e.data <= hoje ? e.data : null;
  const [ano, mes] = hoje.split("-").map(Number);
  for (let k = 0; k < 12; k++) {
    const d = new Date(ano, mes - k, 0);
    const oc = ocorrenciaNoMes(e, d.getFullYear(), d.getMonth() + 1);
    if (oc && oc <= hoje) return oc;
  }
  return null;
}

function diasCorridos(de, ate) {
  return Math.round((new Date(ate + "T12:00:00Z") - new Date(de + "T12:00:00Z")) / 86400000);
}

function atrasosDoDia(rows, hoje) {
  return (rows || []).map(r => r.dados)
    .filter(e => e && CAT_COM_VALOR.has(e.tipo) && valorNum(e.valor))
    .map(e => {
      const venc = ultimoVencimento(e, hoje);
      if (!venc || pagoEm(e, venc)) return null;
      const dias = diasCorridos(venc, hoje);
      return dias > 0 ? { titulo: e.titulo, valor: valorNum(e.valor), venc, dias } : null;
    })
    .filter(Boolean)
    .sort((a, b) => b.dias - a.dias);
}

function textoAtrasos(atrasos) {
  if (!atrasos.length) return "";
  const total = atrasos.reduce((s, a) => s + a.valor, 0);
  const linhas = atrasos.map(a =>
    "- " + a.titulo + ": " + a.dias + " dia" + (a.dias > 1 ? "s" : "") + " de atraso (" +
    reais(a.valor) + ", venceu em " + a.venc.split("-").reverse().join("/") + ")"
  ).join("\n");
  return "\n\nBoletos em atraso (" + atrasos.length + "):\n" + linhas +
    "\nTotal em atraso: " + reais(total) + "\n";
}

async function enviarEmail(resumo, hoje, m, atrasosTxt) {
  const dataBR = hoje.split("-").reverse().join("/");
  const assunto = frase(m) + (atrasosTxt ? " — ⚠️ boletos em atraso" : "") + " (" + dataBR + ")";
  const texto = frase(m) + "\n\nSua agenda de " + dataBR + ":\n"
    + resumo + (atrasosTxt || "") + "\n\nAbrir agenda: " + SITE_URL + "\n";

  if (BREVO_API_KEY) {
    /* API por HTTPS: funciona no plano gratuito do Render, que bloqueia SMTP */
    const resp = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": BREVO_API_KEY, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        sender: { name: "Agenda J&S", email: EMAIL_DESDE },
        to: EMAIL_PARA.map(e => ({ email: e })),
        subject: assunto,
        textContent: texto,
      }),
    });
    if (!resp.ok) throw new Error("Brevo " + resp.status + ": " + await resp.text().catch(() => ""));
    return;
  }

  const transportador = nodemailer.createTransport({
    host: SMTP_HOST, port: Number(SMTP_PORT), secure: String(SMTP_PORT) === "465",
    auth: { user: SMTP_USUARIO, pass: SMTP_SENHA },
    /* o plano gratuito do Render bloqueia SMTP: sem estes limites a requisição
       fica ~2 min presa esperando uma conexão que nunca acontece */
    connectionTimeout: 8000, greetingTimeout: 8000, socketTimeout: 10000,
  });
  await transportador.sendMail({
    from: '"Agenda J&S" <' + SMTP_USUARIO + ">",
    to: EMAIL_PARA.join(","),
    subject: assunto,
    text: texto,
  });
}

/* Frase curta para push/SMS: só o essencial do atraso (limite de caracteres) */
function avisoAtraso(atrasos) {
  if (!atrasos.length) return "";
  const total = atrasos.reduce((s, a) => s + a.valor, 0);
  return " ⚠️ " + atrasos.length + " boleto(s) em atraso (" + reais(total) +
    "), o mais antigo há " + atrasos[0].dias + (atrasos[0].dias > 1 ? " dias" : " dia") + ".";
}

async function enviarSMS(m, aviso) {
  /* a API da Brevo aceita um destino por chamada (campo "recipient", não array) */
  const base = { sender: SMS_REMETENTE, content: (frase(m) + aviso + " " + SITE_URL).trim(), type: "transactional" };
  const erros = [];
  for (const numero of SMS_PARA) {
    const resp = await fetch("https://api.brevo.com/v3/transactionalSMS/sms", {
      method: "POST",
      headers: { "api-key": BREVO_API_KEY, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ ...base, recipient: numero }),
    });
    if (!resp.ok) {
      const texto = await resp.text().catch(() => "");
      let msg = texto;
      try { msg = JSON.parse(texto).message; } catch {}
      erros.push(numero + ": " + msg);
    }
  }
  if (erros.length) throw new Error(erros.join(" | "));
}

app.post("/api/despacho", async (req, res) => {
  try {
    if (!CRON_TOKEN) return res.status(503).json({ erro: "CRON_TOKEN não configurado" });
    if (req.headers["x-agenda-token"] !== CRON_TOKEN)
      return res.status(401).json({ erro: "token inválido" });
    if (!VAPID_PUBLICA || !VAPID_PRIVADA)
      return res.status(503).json({ erro: "chaves VAPID não configuradas" });

    const m = MSG[(req.body && req.body.periodo) || req.query.periodo || "manha"] || MSG.manha;
    const hoje = hojeSaoPaulo();
    const eventos = await listarEventos().catch(e => { console.error("leitura de eventos falhou:", e.message); return []; });
    const atrasos = atrasosDoDia(eventos, hoje);
    const aviso = avisoAtraso(atrasos);
    const linhas = await sbFetch("agenda_push?select=endpoint,dados");
    const corpo = JSON.stringify({
      title: "Agenda J&S",
      body: frase(m) + aviso,
      tag: m.tag,
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
    if (EMAIL_PARA.length && (BREVO_API_KEY || (SMTP_HOST && SMTP_USUARIO && SMTP_SENHA))) {
      try {
        await enviarEmail(resumoDoDia(eventos, hoje), hoje, m, textoAtrasos(atrasos));
        email = "enviado";
      } catch (e) {
        console.error("email falhou:", e.message);
        email = "erro: " + e.message;
      }
    }
    let sms = "nao configurado";
    if (BREVO_API_KEY && SMS_PARA.length) {
      try {
        await enviarSMS(m, aviso);
        sms = "enviado";
      } catch (e) {
        console.error("sms falhou:", e.message);
        sms = "erro: " + e.message;
      }
    }

    res.json({ total: (linhas || []).length, enviados, mortas, falhas, email, sms });
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha no disparo" });
  }
});

/* ---------- site estático ---------- */
app.use(express.static(path.join(__dirname)));

/* funções puras de atraso, exportadas para teste local (node -e "require('./server.js')") */
module.exports = { atrasosDoDia, textoAtrasos, avisoAtraso, ultimoVencimento, resumoDoDia };

app.listen(PORT, () => console.log("Agenda do Joceir rodando na porta " + PORT));
