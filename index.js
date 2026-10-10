// bienvisto-api: redirector público (ir.bienvisto.com.mx) + API del panel (admini.bienvisto.com.mx/api/*)
// Versión 2: valida el JWT de Cloudflare Access en la API.

const ADMIN_HOST = "admini.bienvisto.com.mx";

// Cloudflare Access: equipo y audiencia de la aplicación "Panel Administrador".
const ACCESS_ISS = "https://late-tooth-db48.cloudflareaccess.com";
const ACCESS_AUD = "a5f1705fbfaa8e73babb09229132db7fe09a0dd8807a2581380daecbee4f00fd";
const LLAVES_TTL_MS = 60 * 60 * 1000;
let llavesCache = null;
let llavesCacheAt = 0;

// Catálogo único de estados (en español). Debe coincidir con el panel y con la base.
const ESTADOS = ["libre", "activo", "pausa", "retirado", "adeudo", "prueba"];

const ETIQUETAS_ESTADO = {
  libre: "libre",
  activo: "activo",
  pausa: "en pausa",
  retirado: "retirado",
  adeudo: "con adeudo",
  prueba: "en prueba",
};

// Alfabeto de folios: LDLD, letras sin I ni O, dígitos sin 0 ni 1.
const LETRAS = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITOS = "23456789";
const FOLIO_RE = /^[ABCDEFGHJKLMNPQRSTUVWXYZ][2-9][ABCDEFGHJKLMNPQRSTUVWXYZ][2-9]$/;

const MAX_LOTE = 100;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env, url);
    }
    return handleRedirect(request, env, url);
  },
};

// ==========================================
// 1. API DEL PANEL (solo admini, solo con identidad de Access)
// ==========================================
async function handleApi(request, env, url) {
  // La API solo existe en el host de administración. En cualquier otro host, 404.
  if (url.hostname !== ADMIN_HOST) {
    return json({ error: "No encontrado" }, 404);
  }

  // Identidad verificada por firma del JWT de Access. Sin JWT válido, no hay acceso.
  const usuario = await verificarAccess(request);
  if (!usuario) {
    return json({ error: "No autorizado" }, 401);
  }

  try {
    const method = request.method;
    const path = url.pathname;

    if (path === "/api/displays" && method === "GET") {
      return listarFolios(env);
    }

    if (path === "/api/lotes" && method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT id, tipo, costo, destino, nota, cantidad, created_at FROM lotes ORDER BY created_at DESC"
      ).all();
      return json(results);
    }

    if (path.startsWith("/api/lotes/") && method === "PATCH") {
      return actualizarLote(request, env, url);
    }

    if (path.startsWith("/api/lotes/") && method === "DELETE") {
      return borrarLote(env, url);
    }

    if (path === "/api/displays/batch" && method === "POST") {
      return generarLote(request, env, usuario);
    }

    if (path.startsWith("/api/displays/") && method === "PATCH") {
      return actualizarFolio(request, env, url, usuario);
    }

    return json({ error: "Endpoint no encontrado" }, 404);
  } catch (err) {
    console.error("api error", err);
    return json({ error: "Error interno" }, 500);
  }
}

async function listarFolios(env) {
  const { results } = await env.DB.prepare(
    "SELECT folio, estado, negocio_asignado, url_destino, lote_id, created_at, updated_at FROM folios ORDER BY created_at DESC"
  ).all();
  return json(results);
}

async function generarLote(request, env, usuario) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  let cantidad = Number.isInteger(body.cantidad) ? body.cantidad : 10;
  if (cantidad < 1 || cantidad > MAX_LOTE) {
    return json({ error: `cantidad debe estar entre 1 y ${MAX_LOTE}` }, 400);
  }

  const tipo = typeof body.tipo === "string" && body.tipo.trim() ? body.tipo.trim().slice(0, 100) : "Reseñas de Google";
  const costo = body.costo === undefined ? 0 : Number(body.costo);
  if (!Number.isFinite(costo) || costo < 0 || costo > 100000) {
    return json({ error: "costo no válido" }, 400);
  }
  const destino = typeof body.destino === "string" && body.destino.trim() ? body.destino.trim().slice(0, 200) : null;
  const nota = typeof body.nota === "string" && body.nota.trim() ? body.nota.trim().slice(0, 300) : null;

  const loteId = "LOTE-" + Date.now();
  const generados = [];
  const yaUsados = new Set();
  let intentos = 0;

  while (generados.length < cantidad && intentos < cantidad * 20) {
    intentos++;
    const folio = folioAleatorio();
    if (yaUsados.has(folio)) continue;
    yaUsados.add(folio);

    const existe = await env.DB.prepare("SELECT folio FROM folios WHERE folio = ?").bind(folio).first();
    if (!existe) generados.push(folio);
  }

  if (generados.length < cantidad) {
    return json({ error: "No se pudieron generar todos los folios únicos. Nada se guardó." }, 409);
  }

  // Todo el lote en una sola transacción: o entran todos o ninguno.
  const stmts = [];
  stmts.push(
    env.DB.prepare(
      "INSERT INTO lotes (id, tipo, costo, destino, nota, cantidad, created_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)"
    ).bind(loteId, tipo, costo, destino, nota, generados.length)
  );
  for (const folio of generados) {
    stmts.push(
      env.DB.prepare(
        "INSERT INTO folios (folio, estado, lote_id, created_at, updated_at) VALUES (?, 'libre', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
      ).bind(folio, loteId)
    );
    stmts.push(
      env.DB.prepare(
        "INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, NULL, 'libre', ?)"
      ).bind(folio, usuario)
    );
  }
  await env.DB.batch(stmts);

  return json({ success: true, lote_id: loteId, total: generados.length, folios: generados }, 201);
}

async function actualizarLote(request, env, url) {
  const id = decodeURIComponent(url.pathname.slice("/api/lotes/".length));
  if (!/^LOTE-\d+$/.test(id)) {
    return json({ error: "Lote inválido" }, 400);
  }

  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const existe = await env.DB.prepare("SELECT id FROM lotes WHERE id = ?").bind(id).first();
  if (!existe) return json({ error: "Lote no encontrado" }, 404);

  const tipo = typeof body.tipo === "string" && body.tipo.trim() ? body.tipo.trim().slice(0, 100) : "Reseñas de Google";
  const costo = body.costo === undefined ? 0 : Number(body.costo);
  if (!Number.isFinite(costo) || costo < 0 || costo > 100000) {
    return json({ error: "costo no válido" }, 400);
  }
  const destino = typeof body.destino === "string" && body.destino.trim() ? body.destino.trim().slice(0, 200) : null;
  const nota = typeof body.nota === "string" && body.nota.trim() ? body.nota.trim().slice(0, 300) : null;

  await env.DB.prepare("UPDATE lotes SET tipo = ?, costo = ?, destino = ?, nota = ? WHERE id = ?")
    .bind(tipo, costo, destino, nota, id)
    .run();

  return json({ success: true, id });
}

// Borra un lote y sus folios solo si ninguno está en uso (todos libres, sin negocio,
// sin cambios registrados). Todo en una sola transacción.
async function borrarLote(env, url) {
  const id = decodeURIComponent(url.pathname.slice("/api/lotes/".length));
  if (!/^LOTE-\d+$/.test(id)) {
    return json({ error: "Lote inválido" }, 400);
  }

  const enUso = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM folios WHERE lote_id = ? AND (estado != 'libre' OR negocio_asignado IS NOT NULL OR url_destino IS NOT NULL)"
  ).bind(id).first();
  if (enUso && enUso.n > 0) {
    return json({ error: "El lote tiene displays en uso. No se puede borrar." }, 409);
  }

  const movimientos = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM auditoria_estados WHERE estado_anterior IS NOT NULL AND folio IN (SELECT folio FROM folios WHERE lote_id = ?)"
  ).bind(id).first();
  if (movimientos && movimientos.n > 0) {
    return json({ error: "El lote tiene cambios registrados. No se puede borrar." }, 409);
  }

  const folios = await env.DB.prepare("SELECT COUNT(*) AS n FROM folios WHERE lote_id = ?").bind(id).first();
  const existeLote = await env.DB.prepare("SELECT id FROM lotes WHERE id = ?").bind(id).first();
  if ((!folios || folios.n === 0) && !existeLote) {
    return json({ error: "Lote no encontrado" }, 404);
  }

  await env.DB.batch([
    env.DB.prepare("DELETE FROM auditoria_estados WHERE folio IN (SELECT folio FROM folios WHERE lote_id = ?)").bind(id),
    env.DB.prepare("DELETE FROM folios WHERE lote_id = ?").bind(id),
    env.DB.prepare("DELETE FROM lotes WHERE id = ?").bind(id),
  ]);

  return json({ success: true, id, folios_borrados: folios ? folios.n : 0 });
}

async function actualizarFolio(request, env, url, usuario) {
  const folio = decodeURIComponent(url.pathname.slice("/api/displays/".length)).toUpperCase();
  if (!FOLIO_RE.test(folio)) {
    return json({ error: "Folio inválido" }, 400);
  }

  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  if (body.estado !== undefined && !ESTADOS.includes(body.estado)) {
    return json({ error: "Estado no válido" }, 400);
  }
  if (body.url_destino !== undefined && body.url_destino !== null && !esUrlResena(body.url_destino)) {
    return json({ error: "url_destino debe ser una URL https de Google" }, 400);
  }
  if (body.negocio_asignado !== undefined && body.negocio_asignado !== null) {
    if (typeof body.negocio_asignado !== "string" || body.negocio_asignado.length > 200) {
      return json({ error: "negocio_asignado no válido" }, 400);
    }
  }

  const actual = await env.DB.prepare("SELECT estado FROM folios WHERE folio = ?").bind(folio).first();
  if (!actual) {
    return json({ error: "Folio no encontrado" }, 404);
  }

  const nuevoEstado = body.estado !== undefined ? body.estado : actual.estado;

  const sets = ["estado = ?", "updated_at = CURRENT_TIMESTAMP"];
  const params = [nuevoEstado];
  if ("negocio_asignado" in body) {
    sets.push("negocio_asignado = ?");
    params.push(body.negocio_asignado);
  }
  if ("url_destino" in body) {
    sets.push("url_destino = ?");
    params.push(body.url_destino);
  }

  const stmts = [
    env.DB.prepare(`UPDATE folios SET ${sets.join(", ")} WHERE folio = ?`).bind(...params, folio),
  ];
  if (actual.estado !== nuevoEstado) {
    stmts.push(
      env.DB.prepare(
        "INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, ?, ?, ?)"
      ).bind(folio, actual.estado, nuevoEstado, usuario)
    );
  }
  await env.DB.batch(stmts);

  return json({ success: true, folio, estado: nuevoEstado });
}

// ==========================================
// 2. REDIRECTOR PÚBLICO (ir.bienvisto.com.mx)
// Solo GET/HEAD. No lee query strings para decidir nada.
// ==========================================
async function handleRedirect(request, env, url) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Método no permitido", { status: 405, headers: { Allow: "GET, HEAD" } });
  }

  const folio = url.pathname.slice(1).toUpperCase();
  if (!folio) {
    return new Response("Folio no especificado", { status: 400 });
  }
  if (!FOLIO_RE.test(folio)) {
    return new Response("Error: El folio no existe.", { status: 404 });
  }

  const display = await env.DB.prepare("SELECT estado, url_destino FROM folios WHERE folio = ?")
    .bind(folio)
    .first();

  if (!display) {
    return new Response("Error: El folio no existe.", { status: 404 });
  }

  // Solo 'activo' con una URL de reseña válida redirige.
  if (display.estado === "activo" && esUrlResena(display.url_destino)) {
    return Response.redirect(display.url_destino, 302);
  }

  const etiqueta = ETIQUETAS_ESTADO[display.estado] || "no disponible";
  const html = `<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="robots" content="noindex"><title>Display No Disponible</title><style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#f5f5f5;margin:0;}div{background:#fff;padding:40px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.1);text-align:center;}</style></head>
<body><div><h2>Display No Disponible</h2><p>Este folio (${esc(folio)}) se encuentra actualmente <b>${esc(etiqueta)}</b>.</p><p>Si crees que esto es un error, contacta a soporte.</p></div></body>
</html>`;

  return new Response(request.method === "HEAD" ? null : html, {
    status: 403,
    headers: { "Content-Type": "text/html;charset=UTF-8", "X-Robots-Tag": "noindex" },
  });
}

// ==========================================
// Utilidades
// ==========================================
// Verifica la firma RS256 del JWT de Access y devuelve el correo, o null.
async function verificarAccess(request) {
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return null;

  const partes = token.split(".");
  if (partes.length !== 3) return null;

  let header;
  let payload;
  try {
    header = JSON.parse(new TextDecoder().decode(b64uDecode(partes[0])));
    payload = JSON.parse(new TextDecoder().decode(b64uDecode(partes[1])));
  } catch {
    return null;
  }

  if (header.alg !== "RS256") return null;
  if (payload.iss !== ACCESS_ISS) return null;

  const audiencias = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiencias.includes(ACCESS_AUD)) return null;

  const ahora = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= ahora) return null;

  const llave = await obtenerLlave(header.kid);
  if (!llave) return null;

  const firmaValida = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    llave,
    b64uDecode(partes[2]),
    new TextEncoder().encode(partes[0] + "." + partes[1])
  );
  if (!firmaValida) return null;

  return typeof payload.email === "string" && payload.email ? payload.email : null;
}

async function obtenerLlave(kid) {
  if (!kid) return null;

  if (!llavesCache || Date.now() - llavesCacheAt > LLAVES_TTL_MS) {
    const res = await fetch(`${ACCESS_ISS}/cdn-cgi/access/certs`);
    if (!res.ok) return null;
    llavesCache = await res.json();
    llavesCacheAt = Date.now();
  }

  const jwk = (llavesCache.keys || []).find((k) => k.kid === kid);
  if (!jwk) return null;

  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

function b64uDecode(texto) {
  const b64 = texto.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(texto.length / 4) * 4, "=");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function folioAleatorio() {
  return (
    randomDe(LETRAS) +
    randomDe(DIGITOS) +
    randomDe(LETRAS) +
    randomDe(DIGITOS)
  );
}

function randomDe(conjunto) {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return conjunto[buf[0] % conjunto.length];
}

// Google: g.page o cualquier subdominio de google.com, siempre https.
function esUrlResena(valor) {
  if (typeof valor !== "string") return false;
  try {
    const u = new URL(valor);
    if (u.protocol !== "https:") return false;
    return u.hostname === "g.page" || u.hostname === "google.com" || u.hostname.endsWith(".google.com");
  } catch {
    return false;
  }
}

async function leerJson(request) {
  try {
    const data = await request.json();
    return data && typeof data === "object" ? data : null;
  } catch {
    return null;
  }
}

function json(data, status = 200) {
  return Response.json(data, { status });
}

function esc(texto) {
  return String(texto).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
