/* Backend da Agenda do Joceir — Render (Node.js + Express)
   - Serve o site estático (index.html)
   - API /api/eventos conversa com o Supabase usando a SECRET key
     (variável de ambiente — a chave nunca aparece no navegador)
*/
const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

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
  const resp = await fetch(SUPABASE_URL + "/rest/v1/" + caminho, opts);
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

/* ---------- API ---------- */
app.get("/api/eventos", async (req, res) => {
  try {
    if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) throw new Error("banco não configurado");
    res.json(await listarEventos());
  } catch (e) {
    console.error(e);
    res.status(502).json({ erro: "Falha ao ler o banco de dados" });
  }
});

app.put("/api/eventos", async (req, res) => {
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

/* ---------- site estático ---------- */
app.use(express.static(path.join(__dirname)));

app.listen(PORT, () => console.log("Agenda do Joceir rodando na porta " + PORT));
