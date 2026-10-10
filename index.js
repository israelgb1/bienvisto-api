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

// Pasa a libre los displays en prueba vencidos. Se llama antes de leer,
// así el estado siempre sale correcto sin tarea programada.
async function aplicarVencimientos(env, usuario, folio, minutos) {
  const filtro = folio
    ? "estado = 'prueba' AND prueba_inicio IS NOT NULL AND folio = ? AND prueba_inicio <= datetime('now', ?)"
    : "estado = 'prueba' AND prueba_inicio IS NOT NULL AND prueba_inicio <= datetime('now', ?)";
  const corte = `-${minutos} minutes`;
  const q = folio
    ? env.DB.prepare(`SELECT folio, estado FROM folios WHERE ${filtro}`).bind(folio, corte)
    : env.DB.prepare(`SELECT folio, estado FROM folios WHERE ${filtro}`).bind(corte);
  const { results } = await q.all();
  if (!results.length) return;

  const stmts = [];
  for (const r of results) {
    stmts.push(
      env.DB.prepare("UPDATE folios SET estado = 'libre', prueba_inicio = NULL, negocio_asignado = NULL, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'prueba'").bind(r.folio)
    );
    stmts.push(
      env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'prueba', 'libre', ?)").bind(r.folio, usuario || "sistema")
    );
  }
  await env.DB.batch(stmts);
}

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

    if (path === "/api/vendedores" && method === "GET") {
      return listarVendedores(env);
    }

    if (path === "/api/vendedores" && method === "POST") {
      return crearVendedor(request, env, usuario);
    }

    if (path.startsWith("/api/vendedores/") && method === "PATCH") {
      return actualizarVendedor(request, env, url, usuario);
    }

    if (path === "/api/displays/asignar" && method === "POST") {
      return asignarDisplays(request, env, usuario);
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

    if (path === "/api/auditoria" && method === "GET") {
      return listarAuditoria(env);
    }
    if (path === "/api/precios" && method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT fecha, precio, comision, promo_n, promo_precio, usuario, nota FROM precios_historial ORDER BY id DESC LIMIT 200"
      ).all();
      return json(results);
    }
    if (path === "/api/config" && method === "GET") {
      return json(await leerConfig(env));
    }
    if (path === "/api/config" && method === "PATCH") {
      return actualizarConfig(request, env, usuario);
    }

    if (path === "/api/ventas" && method === "GET") {
      return listarVentas(env);
    }
    if (path === "/api/ventas" && method === "POST") {
      return crearVenta(request, env, usuario);
    }
    if (path.startsWith("/api/ventas/") && method === "PATCH") {
      return actualizarVenta(request, env, url, usuario);
    }
    if (path === "/api/cortes" && method === "GET") {
      return listarCortes(env);
    }
    if (path === "/api/cortes" && method === "POST") {
      return crearCorte(request, env, usuario);
    }
    if (/^\/api\/ventas\/[^/]+\/comprobante$/.test(path) && method === "POST") {
      return guardarComprobante(request, env, url, usuario);
    }
    if (/^\/api\/ventas\/[^/]+\/comprobante$/.test(path) && method === "GET") {
      return leerComprobante(env, url);
    }
    if (path === "/api/solicitudes" && method === "GET") {
      return listarSolicitudes(env);
    }
    if (path === "/api/solicitudes" && method === "POST") {
      return crearSolicitud(request, env, usuario);
    }
    if (path.startsWith("/api/solicitudes/") && method === "PATCH") {
      return actualizarSolicitud(request, env, url, usuario);
    }

    return json({ error: "Endpoint no encontrado" }, 404);
  } catch (err) {
    console.error("api error", err);
    return json({ error: "Error interno" }, 500);
  }
}

async function listarFolios(env) {
  await aplicarVencimientos(env, "sistema", null, (await leerConfig(env)).prueba_minutos);
  const { results } = await env.DB.prepare(
    "SELECT folio, estado, negocio_asignado, url_destino, lote_id, vendedor_id, prueba_inicio, created_at, updated_at FROM folios ORDER BY created_at DESC"
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

// ---------- Vendedores ----------
const MAX_ASIGNAR = 50;
const NIVELES = ["nuevo", "confianza"];

async function listarVendedores(env) {
  const { results } = await env.DB.prepare(
    "SELECT id, nombre, whatsapp, correo, nivel, estado, fecha_registro FROM vendedores ORDER BY fecha_registro DESC"
  ).all();
  return json(results);
}

function limpiarWhatsapp(valor) {
  if (typeof valor !== "string" || !valor.trim()) return null;
  return valor.replace(/[^\d+]/g, "").slice(0, 20) || null;
}

function limpiarCorreo(valor) {
  if (typeof valor !== "string") return null;
  const c = valor.trim().toLowerCase().slice(0, 254);
  if (!c) return null;
  return /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(c) ? c : undefined; // undefined = inválido
}

async function crearVendedor(request, env, usuario) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const nombre = typeof body.nombre === "string" ? body.nombre.trim().slice(0, 120) : "";
  if (!nombre) return json({ error: "nombre es obligatorio" }, 400);
  const whatsapp = limpiarWhatsapp(body.whatsapp);
  const correo = limpiarCorreo(body.correo);
  if (correo === undefined) return json({ error: "correo no válido" }, 400);
  const nivel = body.nivel === undefined ? "nuevo" : body.nivel;
  if (!NIVELES.includes(nivel)) return json({ error: "nivel no válido" }, 400);

  const id = "V-" + crypto.randomUUID().slice(0, 8);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO vendedores (id, nombre, whatsapp, correo, nivel, estado) VALUES (?, ?, ?, ?, ?, 'activo')").bind(id, nombre, whatsapp, correo, nivel),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Alta de vendedor ${id} (${nombre})`),
  ]);
  return json({ success: true, id }, 201);
}

async function actualizarVendedor(request, env, url, usuario) {
  const id = decodeURIComponent(url.pathname.slice("/api/vendedores/".length));
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const actual = await env.DB.prepare("SELECT id, nombre, whatsapp, correo, nivel, estado FROM vendedores WHERE id = ?").bind(id).first();
  if (!actual) return json({ error: "Vendedor no encontrado" }, 404);

  const nombre = body.nombre !== undefined ? (typeof body.nombre === "string" ? body.nombre.trim().slice(0, 120) : "") : actual.nombre;
  if (!nombre) return json({ error: "nombre no válido" }, 400);
  const whatsapp = body.whatsapp !== undefined ? limpiarWhatsapp(body.whatsapp) : actual.whatsapp;
  const correo = body.correo !== undefined ? limpiarCorreo(body.correo) : actual.correo;
  if (correo === undefined) return json({ error: "correo no válido" }, 400);
  const nivel = body.nivel !== undefined ? body.nivel : actual.nivel;
  if (!NIVELES.includes(nivel)) return json({ error: "nivel no válido" }, 400);
  const estado = body.estado !== undefined ? body.estado : actual.estado;
  if (estado !== "activo" && estado !== "inactivo") {
    return json({ error: "estado no válido" }, 400);
  }

  const stmts = [];
  let movidos = 0;
  let movidosBodega = 0;

  if (estado === "inactivo" && actual.estado !== "inactivo") {
    // Libres: a destino_libres (otro vendedor activo) o a bodega si no hay destino.
    // Todos los demás displays del vendedor (no libres): a bodega.
    const destino = body.destino_libres === undefined || body.destino_libres === null ? null : String(body.destino_libres);
    if (destino) {
      if (destino === id) return json({ error: "destino no válido" }, 400);
      const d = await env.DB.prepare("SELECT id FROM vendedores WHERE id = ? AND estado = 'activo'").bind(destino).first();
      if (!d) return json({ error: "destino no válido" }, 400);
    }
    const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM folios WHERE vendedor_id = ? AND estado = 'libre'").bind(id).first();
    movidos = cnt ? cnt.n : 0;
    const cntB = await env.DB.prepare("SELECT COUNT(*) AS n FROM folios WHERE vendedor_id = ? AND estado <> 'libre'").bind(id).first();
    movidosBodega = cntB ? cntB.n : 0;
    stmts.push(
      env.DB.prepare("UPDATE folios SET vendedor_id = ?, updated_at = CURRENT_TIMESTAMP WHERE vendedor_id = ? AND estado = 'libre'").bind(destino, id)
    );
    stmts.push(
      env.DB.prepare("UPDATE folios SET vendedor_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE vendedor_id = ? AND estado <> 'libre'").bind(id)
    );
    stmts.push(
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(
        usuario,
        `Desactivó vendedor ${id}; ${movidos} libres pasaron a ${destino || "bodega"}; ${movidosBodega} no libres pasaron a bodega`
      )
    );
  } else if (estado !== actual.estado) {
    stmts.push(
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Reactivó vendedor ${id}`)
    );
  }

  stmts.push(
    env.DB.prepare("UPDATE vendedores SET nombre = ?, whatsapp = ?, correo = ?, nivel = ?, estado = ? WHERE id = ?").bind(nombre, whatsapp, correo, nivel, estado, id)
  );
  await env.DB.batch(stmts);

  return json({ success: true, id, estado, displays_movidos: movidos, displays_a_bodega: movidosBodega });
}

async function asignarDisplays(request, env, usuario) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  if (!Array.isArray(body.folios) || body.folios.length === 0 || body.folios.length > MAX_ASIGNAR) {
    return json({ error: `folios debe tener entre 1 y ${MAX_ASIGNAR} elementos` }, 400);
  }
  const folios = body.folios.map((f) => String(f).toUpperCase());
  if (folios.some((f) => !FOLIO_RE.test(f)) || new Set(folios).size !== folios.length) {
    return json({ error: "Lista de folios no válida" }, 400);
  }

  const vendedor = body.vendedor_id === undefined || body.vendedor_id === null ? null : String(body.vendedor_id);
  if (vendedor) {
    const v = await env.DB.prepare("SELECT id FROM vendedores WHERE id = ? AND estado = 'activo'").bind(vendedor).first();
    if (!v) return json({ error: "Vendedor no válido o inactivo" }, 400);
  }

  const marcas = folios.map(() => "?").join(",");
  const { results } = await env.DB.prepare(`SELECT folio, estado FROM folios WHERE folio IN (${marcas})`).bind(...folios).all();
  if (results.length !== folios.length) {
    return json({ error: "Algún folio no existe" }, 404);
  }
  if (results.some((r) => r.estado !== "libre")) {
    return json({ error: "Solo se asignan displays libres" }, 409);
  }

  const stmts = [];
  for (const folio of folios) {
    stmts.push(
      env.DB.prepare("UPDATE folios SET vendedor_id = ?, updated_at = CURRENT_TIMESTAMP WHERE folio = ?").bind(vendedor, folio)
    );
    stmts.push(
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(
        usuario,
        `Asignó display a ${vendedor || "bodega"}`,
        folio
      )
    );
  }
  await env.DB.batch(stmts);

  return json({ success: true, total: folios.length, vendedor_id: vendedor });
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

// ---------- Historial: auditoría de acciones y cambios de estado ----------
async function listarAuditoria(env) {
  const { results } = await env.DB.prepare(
    `SELECT fecha, usuario, accion, folio_afectado FROM auditoria
     UNION ALL
     SELECT fecha, cambiado_por AS usuario, 'Estado: ' || COALESCE(estado_anterior, 'nuevo') || ' → ' || estado_nuevo AS accion, folio AS folio_afectado FROM auditoria_estados
     ORDER BY fecha DESC LIMIT 300`
  ).all();
  return json(results);
}

// ---------- Configuración (precios, promoción, comisión, pruebas, topes) ----------
const CONFIG_CLAVES = [
  "precio_display", "promo_n", "promo_precio", "comision_display", "prueba_minutos", "tope_nuevo", "tope_confianza",
  "horas", "recibo_min", "lim_rep", "dias_bono", "lead_d", "colch", "parado_d", "esc_bajo", "bonos_on",
  "bono1_n", "bono1_b", "bono2_n", "bono2_b", "bono3_n", "bono3_b",
];
// Valores que pueden ser 0. El resto debe ser mayor que cero.
const CONFIG_PUEDE_CERO = ["lim_rep", "recibo_min", "bonos_on"];

async function leerConfig(env) {
  const { results } = await env.DB.prepare("SELECT clave, valor FROM config").all();
  const cfg = {};
  for (const r of results) cfg[r.clave] = r.valor;
  for (const k of CONFIG_CLAVES) {
    if (!(k in cfg)) throw new Error("Falta la configuración: " + k);
  }
  return cfg;
}

const CLAVES_PRECIO = ["precio_display", "comision_display", "promo_n", "promo_precio"];

async function actualizarConfig(request, env, usuario) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const nota = typeof body.nota === "string" && body.nota.trim() ? body.nota.trim().slice(0, 100) : null;
  delete body.nota;
  const claves = Object.keys(body);
  if (claves.length === 0) return json({ error: "Nada que actualizar" }, 400);
  for (const k of claves) {
    if (!CONFIG_CLAVES.includes(k)) return json({ error: `Clave no válida: ${k}` }, 400);
    const v = body[k];
    const minimo = CONFIG_PUEDE_CERO.includes(k) ? 0 : 1;
    if (typeof v !== "number" || !Number.isFinite(v) || v < minimo) {
      return json({ error: `${k} no es válido` }, 400);
    }
    if (k === "bonos_on" && v !== 0 && v !== 1) {
      return json({ error: "bonos_on debe ser 0 o 1" }, 400);
    }
    if ((k === "bono1_n" || k === "bono2_n" || k === "bono3_n") && !Number.isInteger(v)) {
      return json({ error: `${k} debe ser un número entero` }, 400);
    }
    if (k === "promo_n" && (!Number.isInteger(v) || v < 2)) {
      return json({ error: "promo_n debe ser un entero de 2 o más" }, 400);
    }
    if (k === "prueba_minutos" && (v < 5 || v > 120)) {
      return json({ error: "prueba_minutos debe estar entre 5 y 120" }, 400);
    }
  }

  const stmts = [];
  for (const k of claves) {
    stmts.push(
      env.DB.prepare("UPDATE config SET valor = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE clave = ?").bind(body[k], usuario, k)
    );
    stmts.push(
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Config ${k} = ${body[k]}`)
    );
  }
  const antes = await leerConfig(env);
  await env.DB.batch(stmts);
  const despues = await leerConfig(env);

  // Historial de precios: solo si cambia precio, comisión o promoción.
  const cambioPrecio = CLAVES_PRECIO.some((k) => antes[k] !== despues[k]);
  if (cambioPrecio) {
    await env.DB.prepare(
      "INSERT INTO precios_historial (precio, comision, promo_n, promo_precio, usuario, nota) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(despues.precio_display, despues.comision_display, despues.promo_n, despues.promo_precio, usuario, nota || "Cambio desde Ajustes").run();
  }
  return json(despues);
}

// ---------- Ventas y cortes (bloque 3a) ----------
// Precios, promoción y comisión salen de la tabla config (ver leerConfig).
// La comisión no cambia con la promoción. Al vendedor se le entrega el total menos su comisión.
const MAX_VENTA = 50;
const METODOS = ["efectivo", "transferencia"];
const FACTURAS = ["no", "pide", "emitida"];

function calcularVenta(n, cfg) {
  const pares = Math.floor(n / cfg.promo_n);
  const total = pares * cfg.promo_precio + (n % cfg.promo_n) * cfg.precio_display;
  const comision = n * cfg.comision_display;
  return { total, comision, aEntregar: total - comision, enPromo: pares * cfg.promo_n };
}

function limpiarTexto(valor, max) {
  return typeof valor === "string" && valor.trim() ? valor.trim().slice(0, max) : null;
}

function limpiarFoliosVenta(lista) {
  if (!Array.isArray(lista) || lista.length === 0 || lista.length > MAX_VENTA) return null;
  const folios = lista.map((f) => String(f).toUpperCase());
  if (folios.some((f) => !FOLIO_RE.test(f)) || new Set(folios).size !== folios.length) return null;
  return folios;
}

async function listarVentas(env) {
  const { results: ventas } = await env.DB.prepare("SELECT * FROM ventas ORDER BY created_at DESC").all();
  const { results: vf } = await env.DB.prepare("SELECT folio, venta_id, precio, comision FROM venta_folios").all();
  const porVenta = {};
  for (const r of vf) {
    (porVenta[r.venta_id] ||= []).push({ folio: r.folio, precio: r.precio, comision: r.comision });
  }
  return json(ventas.map((v) => ({ ...v, folios: porVenta[v.id] || [] })));
}

async function crearVenta(request, env, usuario) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const vendedor = typeof body.vendedor_id === "string" ? body.vendedor_id : null;
  if (!vendedor) return json({ error: "vendedor_id es obligatorio" }, 400);
  const negocio = limpiarTexto(body.negocio, 200);
  if (!negocio) return json({ error: "negocio es obligatorio" }, 400);
  if (!METODOS.includes(body.metodo)) return json({ error: "metodo no válido" }, 400);
  const folios = limpiarFoliosVenta(body.folios);
  if (!folios) return json({ error: `folios debe tener entre 1 y ${MAX_VENTA} displays distintos` }, 400);

  const v = await env.DB.prepare("SELECT id FROM vendedores WHERE id = ? AND estado = 'activo'").bind(vendedor).first();
  if (!v) return json({ error: "Vendedor no válido o inactivo" }, 400);

  const marcas = folios.map(() => "?").join(",");
  const { results: fs } = await env.DB.prepare(`SELECT folio, estado, vendedor_id FROM folios WHERE folio IN (${marcas})`).bind(...folios).all();
  if (fs.length !== folios.length) return json({ error: "Algún folio no existe" }, 404);
  if (fs.some((f) => f.estado !== "libre" || f.vendedor_id !== vendedor)) {
    return json({ error: "Solo se venden displays libres asignados a ese vendedor" }, 409);
  }
  const { results: ocupados } = await env.DB.prepare(`SELECT folio FROM venta_folios WHERE folio IN (${marcas})`).bind(...folios).all();
  if (ocupados.length) return json({ error: "Algún display ya está en otra venta" }, 409);

  const cfg = await leerConfig(env);
  const calc = calcularVenta(folios.length, cfg);
  const id = "VN-" + crypto.randomUUID().slice(0, 8);
  const stmts = [
    env.DB.prepare(
      "INSERT INTO ventas (id, vendedor_id, negocio, contacto, whatsapp, metodo, total, comision_total, a_entregar) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(id, vendedor, negocio, limpiarTexto(body.contacto, 120), limpiarWhatsapp(body.whatsapp), body.metodo, calc.total, calc.comision, calc.aEntregar),
  ];
  folios.forEach((folio, i) => {
    const precio = i < calc.enPromo ? cfg.promo_precio / cfg.promo_n : cfg.precio_display;
    stmts.push(
      env.DB.prepare("INSERT INTO venta_folios (folio, venta_id, precio, comision) VALUES (?, ?, ?, ?)").bind(folio, id, precio, cfg.comision_display)
    );
  });
  stmts.push(
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Creó venta ${id} (${negocio}, ${folios.length} displays)`)
  );
  await env.DB.batch(stmts);

  return json({ success: true, id, total: calc.total, comision_total: calc.comision, a_entregar: calc.aEntregar }, 201);
}

async function actualizarVenta(request, env, url, usuario) {
  const id = decodeURIComponent(url.pathname.slice("/api/ventas/".length));
  if (!/^VN-[0-9a-f]{8}$/.test(id)) return json({ error: "Venta inválida" }, 400);

  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const venta = await env.DB.prepare("SELECT * FROM ventas WHERE id = ?").bind(id).first();
  if (!venta) return json({ error: "Venta no encontrada" }, 404);

  if (body.accion === "enviar_revision") return enviarRevision(env, venta, body);
  if (body.accion === "cobrar") return cobrarVenta(env, venta, body, usuario);
  if (body.accion === "anular") return anularVenta(env, venta, usuario);
  if (body.accion === "factura") {
    if (!FACTURAS.includes(body.factura)) return json({ error: "factura no válida" }, 400);
    await env.DB.batch([
      env.DB.prepare("UPDATE ventas SET factura = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(body.factura, id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Factura de venta ${id}: ${body.factura}`),
    ]);
    return json({ success: true, id, factura: body.factura });
  }
  return json({ error: "accion no válida" }, 400);
}

// Confirmar cobro: la venta pasa a cobrada, sus displays a activo con la URL de reseña.
// Exige URL de Google válida. Si algún display ya no está libre, no se cobra nada.
// Pendiente -> rev: el vendedor avisa que ya se pagó y se revisa el pago. Transferencia exige referencia.
async function enviarRevision(env, venta, body) {
  if (venta.estado !== "pendiente") return json({ error: "Solo una venta pendiente pasa a revisión" }, 409);
  const referencia = limpiarTexto(body.referencia, 100) || venta.referencia;
  if (venta.metodo === "transferencia" && !referencia) {
    return json({ error: "La transferencia requiere referencia" }, 400);
  }
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE ventas SET estado = 'rev', referencia = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'"
    ).bind(referencia, venta.id),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(
      "sistema",
      `Venta ${venta.id} enviada a revisión`
    ),
  ]);
  return json({ success: true, id: venta.id, estado: "rev" });
}

// Cobro desde pendiente o rev. Exige URL de Google válida.
async function cobrarVenta(env, venta, body, usuario) {
  if (venta.estado !== "pendiente" && venta.estado !== "rev") {
    return json({ error: "Solo se cobra una venta pendiente o en revisión" }, 409);
  }
  if (!esUrlResena(body.url_resena)) return json({ error: "url_resena debe ser una URL https de Google" }, 400);
  const referencia = limpiarTexto(body.referencia, 100) || venta.referencia;
  if (venta.metodo === "transferencia" && !referencia) {
    return json({ error: "La transferencia requiere referencia" }, 400);
  }

  const { results: fs } = await env.DB.prepare(
    "SELECT vf.folio, f.estado FROM venta_folios vf JOIN folios f ON f.folio = vf.folio WHERE vf.venta_id = ?"
  ).bind(venta.id).all();
  if (fs.some((f) => f.estado !== "libre")) return json({ error: "Algún display ya no está libre" }, 409);

  const stmts = [
    env.DB.prepare(
      "UPDATE ventas SET estado = 'cobrada', referencia = ?, url_resena = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND estado IN ('pendiente','rev')"
    ).bind(referencia, body.url_resena, venta.id),
  ];
  for (const f of fs) {
    stmts.push(
      env.DB.prepare(
        "UPDATE folios SET estado = 'activo', url_destino = ?, negocio_asignado = ?, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'libre'"
      ).bind(body.url_resena, venta.negocio, f.folio)
    );
    stmts.push(
      env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'libre', 'activo', ?)").bind(f.folio, usuario)
    );
  }
  stmts.push(
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Cobró venta ${venta.id} (${venta.negocio})`)
  );
  await env.DB.batch(stmts);

  return json({ success: true, id: venta.id, estado: "cobrada" });
}

// Anular: permitido en pendiente, rev o cobrada, siempre que no haya entregas (entregado = 0).
// Si la venta ya estaba cobrada, sus displays activos vuelven a libre y se registran en auditoría de estados.
async function anularVenta(env, venta, usuario) {
  if (!["pendiente", "rev", "cobrada"].includes(venta.estado)) {
    return json({ error: "Esta venta no se puede anular" }, 409);
  }
  if (Number(venta.entregado) > 0) return json({ error: "La venta ya tiene entregas; no se puede anular" }, 409);

  const stmts = [
    env.DB.prepare("UPDATE ventas SET estado = 'anulada', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = ?").bind(venta.id, venta.estado),
  ];
  if (venta.estado === "cobrada") {
    const { results: activos } = await env.DB.prepare(
      "SELECT vf.folio FROM venta_folios vf JOIN folios f ON f.folio = vf.folio WHERE vf.venta_id = ? AND f.estado = 'activo'"
    ).bind(venta.id).all();
    for (const f of activos) {
      stmts.push(
        env.DB.prepare(
          "UPDATE folios SET estado = 'libre', negocio_asignado = NULL, url_destino = NULL, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'activo'"
        ).bind(f.folio)
      );
      stmts.push(
        env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'activo', 'libre', ?)").bind(f.folio, usuario)
      );
    }
  }
  stmts.push(env.DB.prepare("DELETE FROM venta_folios WHERE venta_id = ?").bind(venta.id));
  stmts.push(env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Anuló venta ${venta.id} (estado previo: ${venta.estado})`));
  await env.DB.batch(stmts);
  return json({ success: true, id: venta.id, estado: "anulada" });
}

// Saldo del vendedor = lo que debe entregar de ventas cobradas o entregadas, menos lo ya entregado (monto + ajuste de cortes).
const SQL_SALDOS = `SELECT v.id AS vendedor_id,
  COALESCE((SELECT SUM(a_entregar) FROM ventas WHERE vendedor_id = v.id AND estado IN ('cobrada','entregada')), 0)
  - COALESCE((SELECT SUM(monto + ajuste) FROM cortes WHERE vendedor_id = v.id), 0) AS saldo
  FROM vendedores v`;

async function listarCortes(env) {
  const { results: cortes } = await env.DB.prepare("SELECT * FROM cortes ORDER BY created_at DESC").all();
  const { results: saldos } = await env.DB.prepare(SQL_SALDOS).all();
  return json({ cortes, saldos });
}

// Corte = entrega del vendedor a Bien Visto. El ajuste descuenta del saldo sin dinero
// (por ejemplo, una anulación ya cobrada). No puede pasar del saldo.
async function crearCorte(request, env, usuario) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const vendedor = typeof body.vendedor_id === "string" ? body.vendedor_id : null;
  const v = vendedor ? await env.DB.prepare("SELECT id FROM vendedores WHERE id = ?").bind(vendedor).first() : null;
  if (!v) return json({ error: "Vendedor no válido" }, 400);

  const monto = Number(body.monto);
  if (!Number.isFinite(monto) || monto <= 0) return json({ error: "monto debe ser mayor que cero" }, 400);
  const ajuste = body.ajuste === undefined ? 0 : Number(body.ajuste);
  if (!Number.isFinite(ajuste) || ajuste < 0) return json({ error: "ajuste no válido" }, 400);
  if (!METODOS.includes(body.metodo)) return json({ error: "metodo no válido" }, 400);
  const referencia = limpiarTexto(body.referencia, 100);
  if (body.metodo === "transferencia" && !referencia) return json({ error: "La transferencia requiere referencia" }, 400);

  const fila = await env.DB.prepare(`${SQL_SALDOS} WHERE v.id = ?`).bind(vendedor).first();
  const saldo = fila ? Math.round(fila.saldo * 100) / 100 : 0;
  const pedido = Math.round((monto + ajuste) * 100) / 100;
  if (pedido > saldo + 0.001) return json({ error: `El corte supera el saldo pendiente (${saldo})` }, 409);

  // Asignación FIFO: el corte se aplica a las ventas más antiguas con saldo pendiente.
  // Una venta queda 'entregada' cuando su a_entregar está cubierto por completo.
  const { results: abiertas } = await env.DB.prepare(
    "SELECT id, a_entregar, entregado FROM ventas WHERE vendedor_id = ? AND estado IN ('cobrada','entregada') AND a_entregar - entregado > 0.001 ORDER BY created_at ASC, id ASC"
  ).bind(vendedor).all();

  const id = "CO-" + crypto.randomUUID().slice(0, 8);
  const stmts = [
    env.DB.prepare(
      "INSERT INTO cortes (id, vendedor_id, monto, metodo, referencia, ajuste, usuario) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(id, vendedor, monto, body.metodo, referencia, ajuste, usuario),
  ];
  let resto = pedido;
  for (const v of abiertas) {
    if (resto <= 0.001) break;
    const pendiente = Math.round((v.a_entregar - v.entregado) * 100) / 100;
    const toma = Math.min(resto, pendiente);
    const nuevoEntregado = Math.round((v.entregado + toma) * 100) / 100;
    const nuevoEstado = nuevoEntregado >= v.a_entregar - 0.001 ? "entregada" : "cobrada";
    stmts.push(
      env.DB.prepare("UPDATE ventas SET entregado = ?, estado = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(nuevoEntregado, nuevoEstado, v.id)
    );
    resto = Math.round((resto - toma) * 100) / 100;
  }
  if (resto > 0.001) return json({ error: "No hay ventas suficientes para aplicar el corte" }, 409);

  stmts.push(
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Corte ${id} de ${vendedor}: ${monto} (ajuste ${ajuste})`)
  );
  await env.DB.batch(stmts);
  return json({ success: true, id, saldo_restante: Math.round((saldo - pedido) * 100) / 100 }, 201);
}

// ---------- Comprobantes (R2) ----------
// Binding requerido: COMPROBANTES -> bucket bienvisto-comprobantes.
const COMPROBANTE_TIPOS = ["image/jpeg", "image/png", "image/webp", "application/pdf"];
const COMPROBANTE_MAX = 5 * 1024 * 1024;

function idVentaDesde(url) {
  const id = decodeURIComponent(url.pathname.split("/")[3] || "");
  return /^VN-[0-9a-f]{8}$/.test(id) ? id : null;
}

async function guardarComprobante(request, env, url, usuario) {
  const id = idVentaDesde(url);
  if (!id) return json({ error: "Venta inválida" }, 400);
  if (!env.COMPROBANTES) return json({ error: "Almacenamiento de comprobantes no configurado" }, 503);

  const venta = await env.DB.prepare("SELECT id, estado, comprobante_key FROM ventas WHERE id = ?").bind(id).first();
  if (!venta) return json({ error: "Venta no encontrada" }, 404);
  if (venta.estado === "anulada") return json({ error: "La venta está anulada" }, 409);

  const tipo = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  if (!COMPROBANTE_TIPOS.includes(tipo)) return json({ error: "Tipo de archivo no permitido (jpg, png, webp o pdf)" }, 415);
  const bytes = await request.arrayBuffer();
  if (bytes.byteLength === 0) return json({ error: "Archivo vacío" }, 400);
  if (bytes.byteLength > COMPROBANTE_MAX) return json({ error: "El archivo supera 5 MB" }, 413);

  const key = `comprobantes/${id}/${crypto.randomUUID()}`;
  await env.COMPROBANTES.put(key, bytes, { httpMetadata: { contentType: tipo } });
  await env.DB.batch([
    env.DB.prepare("UPDATE ventas SET comprobante_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(key, id),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Comprobante cargado en venta ${id}`),
  ]);
  if (venta.comprobante_key) {
    try {
      await env.COMPROBANTES.delete(venta.comprobante_key);
    } catch (err) {
      console.error("no se pudo borrar comprobante anterior", err);
    }
  }
  return json({ success: true, id, comprobante_key: key }, 201);
}

async function leerComprobante(env, url) {
  const id = idVentaDesde(url);
  if (!id) return json({ error: "Venta inválida" }, 400);
  if (!env.COMPROBANTES) return json({ error: "Almacenamiento de comprobantes no configurado" }, 503);

  const venta = await env.DB.prepare("SELECT comprobante_key FROM ventas WHERE id = ?").bind(id).first();
  if (!venta) return json({ error: "Venta no encontrada" }, 404);
  if (!venta.comprobante_key) return json({ error: "La venta no tiene comprobante" }, 404);

  const obj = await env.COMPROBANTES.get(venta.comprobante_key);
  if (!obj) return json({ error: "Comprobante no encontrado" }, 404);
  return new Response(obj.body, {
    headers: {
      "content-type": obj.httpMetadata?.contentType || "application/octet-stream",
      "cache-control": "private, no-store",
    },
  });
}

// ---------- Solicitudes de reposición y cambio de negocio ----------
// reponer: el display activo se retira y su lugar lo toma un display libre del mismo vendedor (con la misma URL y negocio).
// cambiar: el display sigue activo, con un negocio nuevo y su URL de reseña.
const TIPOS_SOLICITUD = ["reponer", "cambiar"];

async function listarSolicitudes(env) {
  const { results } = await env.DB.prepare("SELECT * FROM solicitudes ORDER BY created_at DESC").all();
  return json(results);
}

async function crearSolicitud(request, env, usuario) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  if (!TIPOS_SOLICITUD.includes(body.tipo)) return json({ error: "tipo no válido" }, 400);
  const folio = typeof body.folio === "string" ? body.folio.toUpperCase() : "";
  if (!FOLIO_RE.test(folio)) return json({ error: "Folio inválido" }, 400);
  const vendedor = typeof body.vendedor_id === "string" ? body.vendedor_id : null;
  if (!vendedor) return json({ error: "vendedor_id es obligatorio" }, 400);
  const nuevoNegocio = limpiarTexto(body.nuevo_negocio, 200);
  if (body.tipo === "cambiar" && !nuevoNegocio) return json({ error: "nuevo_negocio es obligatorio para cambiar" }, 400);

  const d = await env.DB.prepare("SELECT estado, vendedor_id FROM folios WHERE folio = ?").bind(folio).first();
  if (!d) return json({ error: "Folio no encontrado" }, 404);
  if (d.vendedor_id !== vendedor) return json({ error: "El display no pertenece a ese vendedor" }, 409);
  if (d.estado !== "activo") return json({ error: "Solo se reponen o cambian displays activos" }, 409);
  const pendiente = await env.DB.prepare("SELECT id FROM solicitudes WHERE folio = ? AND estado = 'pendiente'").bind(folio).first();
  if (pendiente) return json({ error: "Ya hay una solicitud pendiente para ese display" }, 409);

  const id = "SO-" + crypto.randomUUID().slice(0, 8);
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO solicitudes (id, tipo, folio, vendedor_id, motivo, nota, nuevo_negocio, foto_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(id, body.tipo, folio, vendedor, limpiarTexto(body.motivo, 200), limpiarTexto(body.nota, 500), nuevoNegocio, limpiarTexto(body.foto_key, 300)),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Solicitud ${id} (${body.tipo})`, folio),
  ]);
  return json({ success: true, id }, 201);
}

async function actualizarSolicitud(request, env, url, usuario) {
  const id = decodeURIComponent(url.pathname.slice("/api/solicitudes/".length));
  if (!/^SO-[0-9a-f]{8}$/.test(id)) return json({ error: "Solicitud inválida" }, 400);

  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const s = await env.DB.prepare("SELECT * FROM solicitudes WHERE id = ?").bind(id).first();
  if (!s) return json({ error: "Solicitud no encontrada" }, 404);
  if (s.estado !== "pendiente") return json({ error: "La solicitud ya fue resuelta" }, 409);

  if (body.accion === "rechazar") {
    await env.DB.batch([
      env.DB.prepare("UPDATE solicitudes SET estado = 'rechazada', resuelto_por = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(usuario, id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Solicitud ${id} rechazada`, s.folio),
    ]);
    return json({ success: true, id, estado: "rechazada" });
  }
  if (body.accion !== "aprobar") return json({ error: "accion no válida" }, 400);

  const viejo = await env.DB.prepare("SELECT folio, estado, vendedor_id, url_destino, negocio_asignado FROM folios WHERE folio = ?").bind(s.folio).first();
  if (!viejo || viejo.estado !== "activo") return json({ error: "El display ya no está activo" }, 409);

  if (s.tipo === "reponer") {
    const nuevo = typeof body.folio_nuevo === "string" ? body.folio_nuevo.toUpperCase() : "";
    if (!FOLIO_RE.test(nuevo) || nuevo === s.folio) return json({ error: "folio_nuevo no válido" }, 400);
    if (!viejo.url_destino) return json({ error: "El display a reponer no tiene URL de reseña" }, 409);

    const f = await env.DB.prepare("SELECT estado, vendedor_id FROM folios WHERE folio = ?").bind(nuevo).first();
    if (!f) return json({ error: "folio_nuevo no existe" }, 404);
    if (f.estado !== "libre" || f.vendedor_id !== s.vendedor_id) {
      return json({ error: "El display nuevo debe estar libre y asignado al mismo vendedor" }, 409);
    }
    const enVenta = await env.DB.prepare("SELECT venta_id FROM venta_folios WHERE folio = ?").bind(nuevo).first();
    if (enVenta) return json({ error: "El display nuevo ya está en una venta" }, 409);

    await env.DB.batch([
      env.DB.prepare("UPDATE folios SET estado = 'retirado', updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'activo'").bind(s.folio),
      env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'activo', 'retirado', ?)").bind(s.folio, usuario),
      env.DB.prepare(
        "UPDATE folios SET estado = 'activo', url_destino = ?, negocio_asignado = ?, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'libre'"
      ).bind(viejo.url_destino, viejo.negocio_asignado, nuevo),
      env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'libre', 'activo', ?)").bind(nuevo, usuario),
      env.DB.prepare("UPDATE venta_folios SET folio = ? WHERE folio = ?").bind(nuevo, s.folio),
      env.DB.prepare("UPDATE solicitudes SET estado = 'aprobada', resuelto_por = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(usuario, id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Reposición ${s.folio} → ${nuevo} (solicitud ${id})`, nuevo),
    ]);
    return json({ success: true, id, estado: "aprobada", folio_nuevo: nuevo });
  }

  // cambiar
  const url_resena = body.url_resena;
  if (!esUrlResena(url_resena)) return json({ error: "url_resena debe ser una URL https de Google" }, 400);
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE folios SET url_destino = ?, negocio_asignado = ?, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'activo'"
    ).bind(url_resena, s.nuevo_negocio, s.folio),
    env.DB.prepare("UPDATE solicitudes SET estado = 'aprobada', resuelto_por = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(usuario, id),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Cambio de negocio ${s.folio} → ${s.nuevo_negocio} (solicitud ${id})`, s.folio),
  ]);
  return json({ success: true, id, estado: "aprobada" });
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

  await aplicarVencimientos(env, usuario, folio, (await leerConfig(env)).prueba_minutos);
  const actual = await env.DB.prepare("SELECT estado FROM folios WHERE folio = ?").bind(folio).first();
  if (!actual) {
    return json({ error: "Folio no encontrado" }, 404);
  }

  const nuevoEstado = body.estado !== undefined ? body.estado : actual.estado;

  const sets = ["estado = ?", "updated_at = CURRENT_TIMESTAMP"];
  const params = [nuevoEstado];
  if (nuevoEstado === "prueba" && actual.estado !== "prueba") {
    sets.push("prueba_inicio = CURRENT_TIMESTAMP");
  } else if (nuevoEstado !== "prueba" && actual.estado === "prueba") {
    sets.push("prueba_inicio = NULL");
  }
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

  await aplicarVencimientos(env, "sistema", folio, (await leerConfig(env)).prueba_minutos);
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
