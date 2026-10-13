// bienvisto-api: redirector público (ir.bienvisto.com.mx) + API del panel (admini.bienvisto.com.mx/api/*)
// Versión 2: valida el JWT de Cloudflare Access en la API.

const ADMIN_HOST = "admini.bienvisto.com.mx";
// App de vendedores: API pública (sin Access), solo rutas /api/vendedor/*.
const VENDOR_HOST = "vendedores.bienvisto.com.mx";
const CODIGO_VIGENCIA_MIN = 10;
const CODIGO_MAX_INTENTOS = 5;
const CODIGO_COOLDOWN_SEG = 60;
const LIM_FALLOS_24H = 10;
const LIM_CODIGOS_24H = 5;
const SESION_DIAS = 30;
const COOKIE_SESION = "bv_sesion";
const CORREO_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Cloudflare Access: equipo y audiencia de la aplicación "Panel Administrador".
const ACCESS_ISS = "https://late-tooth-db48.cloudflareaccess.com";
const ACCESS_AUD = "a5f1705fbfaa8e73babb09229132db7fe09a0dd8807a2581380daecbee4f00fd";
const LLAVES_TTL_MS = 60 * 60 * 1000;
let llavesCache = null;
let llavesCacheAt = 0;

// Catálogo único de estados (en español). Debe coincidir con el panel y con la base.
const ESTADOS = ["libre", "activo", "pausa", "retirado", "adeudo", "prueba"];


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
    if (url.pathname.startsWith("/pago/") && (request.method === "GET" || request.method === "HEAD")) {
      return pagoPublico(env, url);
    }
    return handleRedirect(request, env, url);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(enviarPendientes(env));
  },
};

// ==========================================
// 1. API DEL PANEL (solo admini, solo con identidad de Access)
// ==========================================
async function handleApi(request, env, url) {
  // Valores públicos que el sitio bienvisto.com.mx muestra (precio, comisión, promoción, plazos). Los toma de Ajustes.
  if (url.pathname === "/api/publico/config") {
    return configPublica(request, env);
  }

  // Formularios públicos del sitio (factura, queja, solicitud de vendedor): llegan por correo a contacto@.
  if (url.pathname.startsWith("/api/formularios/")) {
    return handleFormulario(request, env, url);
  }

  // Host de vendedores: su propia API, con sesión propia (no usa Access).
  if (url.hostname === VENDOR_HOST) {
    return handleVendedorApi(request, env, url);
  }

  // La API solo existe en el host de administración. En cualquier otro host, 404.
  if (url.hostname !== ADMIN_HOST) {
    return json({ error: "No encontrado" }, 404);
  }

  // Identidad verificada por firma del JWT de Access. Sin JWT válido, no hay acceso.
  const usuario = await verificarAccess(request);
  if (!usuario) {
    return json({ error: "No autorizado" }, 401);
  }

  // Perfil y permisos del panel. Access decide quién llega; esta tabla decide qué puede hacer cada persona.
  const admin = await cargarAdmin(env, usuario);
  if (!admin) {
    return json({ error: "Tu correo no tiene acceso al panel" }, 403);
  }

  try {
    const method = request.method;
    const path = url.pathname;

    if (path === "/api/admin/me" && method === "GET") {
      return json(admin);
    }
    if (path === "/api/admin/datos-pago") {
      if (!admin.permisos.includes("accesos")) return json({ error: "Tu perfil no permite esta acción" }, 403);
      if (method === "GET") return leerDatosPagoAdmin(env);
      if (method === "PATCH") return guardarDatosPago(request, env, usuario);
      return json({ error: "Endpoint no encontrado" }, 404);
    }
    if (path.startsWith("/api/admin/perfiles") || path.startsWith("/api/admin/accesos")) {
      return rutasAccesos(request, env, url, usuario, admin);
    }

    const req = await permisosRequeridos(request, env, url, method, path);
    const tiene = (p) => admin.permisos.includes(p);
    if (!req.todos.every(tiene) || (req.alguno.length && !req.alguno.some(tiene))) {
      return json({ error: "Tu perfil no permite esta acción" }, 403);
    }

    if (path === "/api/displays" && method === "GET") {
      return listarFolios(env);
    }

    if (path === "/api/admin/app-vendedor" && method === "GET") {
      return appVendedorPublicada();
    }
    if (path === "/api/admin/documentacion" && method === "GET") {
      return documentacionAdmin(env, usuario);
    }

    if (path.startsWith("/api/admin/vista/") && method === "GET") {
      return vistaVendedor(request, env, url, usuario);
    }

    if (path === "/api/seguimiento/hoy" && method === "GET") {
      return resumenesDeHoy(env);
    }
    const segAccion = path.match(/^\/api\/seguimiento\/([A-Za-z0-9-]{1,40})\/(consentimiento|saludo|respondio|baja|envio\/([1-6])\/(enviado|omitir))$/);
    if (segAccion && method === "POST") {
      const [, ventaId, a, num, accionEnvio] = segAccion;
      return accionSeguimiento(env, ventaId, num ? accionEnvio : a, num ? Number(num) : null, usuario);
    }
    if (path === "/api/escaneos/serie" && method === "GET") {
      return serieEscaneos(env);
    }
    if (path === "/api/pruebas/resumen" && method === "GET") {
      return resumenPruebas(env);
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

    if (path === "/api/altas-vendedor" && method === "GET") {
      return listarAltasVendedor(env);
    }
    if (path.startsWith("/api/altas-vendedor/") && method === "PATCH") {
      return resolverAltaVendedor(request, env, url, usuario);
    }

    if (path === "/api/cuentas-cobro/aprobar" && method === "POST") {
      return resolverCambioCuenta(request, env, usuario, true);
    }
    if (path === "/api/cuentas-cobro/rechazar" && method === "POST") {
      return resolverCambioCuenta(request, env, usuario, false);
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
      return actualizarLote(request, env, url, usuario);
    }

    if (path.startsWith("/api/lotes/") && method === "DELETE") {
      return borrarLote(env, url, usuario);
    }

    if (path === "/api/displays/batch" && method === "POST") {
      return generarLote(request, env, usuario);
    }

    if (path === "/api/displays/alta" && method === "POST") {
      return altaDisplays(request, env, usuario);
    }

    if (path.startsWith("/api/displays/") && method === "PATCH") {
      return actualizarFolio(request, env, url, usuario);
    }

    if (path === "/api/auditoria" && method === "GET") {
      return listarAuditoria(env);
    }
    if (path === "/api/auditoria/csv" && method === "GET") {
      return auditoriaCsv(env);
    }
    if (path === "/api/precios" && method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT fecha, precio, comision, promo_n, promo_precio, usuario, nota FROM precios_historial ORDER BY id DESC LIMIT 200"
      ).all();
      return json(results);
    }
    if (path === "/api/config" && method === "GET") {
      return json({ ...(await leerConfig(env)), ...(await leerConfigAdmin(env)) });
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
    if (path === "/api/avisos-entrega" && method === "GET") {
      return listarAvisosEntrega(env);
    }
    const avisoAdmin = path.match(/^\/api\/avisos-entrega\/(AE-[0-9a-f]{8})(\/comprobante|\/confirmar|\/rechazar)?$/);
    if (avisoAdmin) {
      const [, avisoId, accion] = avisoAdmin;
      if (accion === "/comprobante" && method === "GET") return leerComprobanteAviso(env, avisoId);
      if (accion === "/confirmar" && method === "POST") return confirmarAviso(env, avisoId, usuario);
      if (accion === "/rechazar" && method === "POST") return rechazarAviso(request, env, avisoId, usuario);
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
    `SELECT f.folio, f.estado, f.negocio_asignado, f.url_destino, f.lote_id, f.vendedor_id, f.prueba_inicio, f.created_at, f.updated_at,
      (SELECT COUNT(*) FROM escaneos e WHERE e.folio = f.folio AND e.contado = 1 AND e.created_at >= datetime('now', '-7 days')) AS esc7,
      (SELECT COUNT(*) FROM escaneos e WHERE e.folio = f.folio AND e.contado = 1 AND e.created_at >= datetime('now', '-30 days')) AS esc30
     FROM folios f ORDER BY f.created_at DESC`
  ).all();
  return json(results);
}

// Alta de displays con folios que ya escribió el admin (una sola transacción).
async function altaDisplays(request, env, usuario) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const folios = Array.isArray(body.folios) ? body.folios.map((f) => String(f).trim().toUpperCase()) : [];
  if (folios.length < 1 || folios.length > MAX_LOTE) {
    return json({ error: `folios debe tener entre 1 y ${MAX_LOTE} elementos` }, 400);
  }
  if (folios.some((f) => !FOLIO_RE.test(f)) || new Set(folios).size !== folios.length) {
    return json({ error: "Folios inválidos o repetidos" }, 400);
  }

  const costo = body.costo === undefined ? 0 : Number(body.costo);
  if (!Number.isInteger(costo) || costo < 0 || costo > 9999) {
    return json({ error: "costo no válido" }, 400);
  }
  const tipo = typeof body.tipo === "string" && body.tipo.trim() ? body.tipo.trim().slice(0, 100) : "Reseñas de Google";
  const destino = typeof body.destino === "string" && body.destino.trim() ? body.destino.trim().slice(0, 200) : null;
  const nota = typeof body.nota === "string" && body.nota.trim() ? body.nota.trim().slice(0, 300) : null;

  // D1 limita los parámetros por consulta: se revisa folio por folio.
  const repetidos = [];
  for (const folio of folios) {
    const existe = await env.DB.prepare("SELECT folio FROM folios WHERE folio = ?").bind(folio).first();
    if (existe) repetidos.push(folio);
  }
  if (repetidos.length) {
    return json({ error: "Ya existen en el inventario: " + repetidos.join(", "), folios: repetidos }, 409);
  }

  const loteId = "LOTE-" + Date.now();
  const stmts = [
    env.DB.prepare(
      "INSERT INTO lotes (id, tipo, costo, destino, nota, cantidad, created_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)"
    ).bind(loteId, tipo, costo, destino, nota, folios.length),
  ];
  for (const folio of folios) {
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

  return json({ success: true, lote_id: loteId, total: folios.length }, 201);
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

// Escaneos por día de los últimos 30 días (UTC), del más antiguo al más reciente, con ceros donde no hubo.
async function serieEscaneos(env) {
  const { results } = await env.DB.prepare(
    "SELECT date(created_at) AS dia, COUNT(*) AS n FROM escaneos WHERE contado = 1 AND created_at >= datetime('now', '-29 days') GROUP BY dia"
  ).all();
  const porDia = new Map(results.map((r) => [r.dia, Number(r.n)]));
  const serie = [];
  for (let i = 29; i >= 0; i--) {
    const dia = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    serie.push(porDia.get(dia) || 0);
  }
  return json(serie);
}

// Pruebas de los últimos 30 días según la auditoría de estados:
// ini = displays que entraron a prueba, vend = pasaron de prueba a activo (venta), exp = expiraron sin venta.
async function resumenPruebas(env) {
  const row = await env.DB.prepare(
    `SELECT
      (SELECT COUNT(DISTINCT folio) FROM auditoria_estados WHERE estado_nuevo = 'prueba' AND fecha >= datetime('now', '-30 days')) AS ini,
      (SELECT COUNT(DISTINCT folio) FROM auditoria_estados WHERE estado_anterior = 'prueba' AND estado_nuevo = 'activo' AND fecha >= datetime('now', '-30 days')) AS vend,
      (SELECT COUNT(DISTINCT folio) FROM auditoria_estados WHERE estado_anterior = 'prueba' AND estado_nuevo = 'libre' AND fecha >= datetime('now', '-30 days')) AS exp,
      (SELECT COUNT(*) FROM folios WHERE estado = 'prueba') AS en_curso`
  ).first();
  return json({ ini: Number(row.ini), vend: Number(row.vend), exp: Number(row.exp), en_curso: Number(row.en_curso) });
}

async function listarVendedores(env) {
  const { results } = await env.DB.prepare(
    `SELECT id, nombre, whatsapp, correo, nivel, estado, fecha_registro,
      (SELECT COUNT(*) FROM solicitudes s WHERE s.vendedor_id = vendedores.id AND s.tipo = 'reponer' AND s.resuelto_por = 'directo' AND s.created_at >= ?) AS rep_mes
     FROM vendedores ORDER BY fecha_registro DESC`
  ).bind(inicioMesMX()).all();
  // Cuenta de cobro vigente y cambio en revisión de cada vendedor (para la pantalla de aprobación).
  const { results: cuentas } = await env.DB.prepare(
    "SELECT id, vendedor_id, titular, clabe, cuenta, tipo, estado, created_at FROM cuentas_cobro WHERE estado IN ('vigente', 'pendiente') ORDER BY id DESC"
  ).all();
  const porVendedor = new Map();
  for (const c of cuentas) {
    const e = porVendedor.get(c.vendedor_id) || {};
    if (c.estado === "vigente" && !e.cu) e.cu = presentarCuenta(c);
    if (c.estado === "pendiente" && !e.cuP) e.cuP = { ...presentarCuenta(c), t: c.created_at, id: c.id };
    porVendedor.set(c.vendedor_id, e);
  }
  return json(results.map((v) => ({ ...v, ...(porVendedor.get(v.id) || {}) })));
}

// Aprobar o rechazar un cambio de cuenta de cobro pendiente (solo administrador).
// Aprobar: la vigente pasa a 'sustituida' y la pendiente a 'vigente', en un solo batch.
async function resolverCambioCuenta(request, env, usuario, aprobar) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);
  const id = Number(body.id);
  if (!Number.isInteger(id) || id <= 0) return json({ error: "Falta el cambio a resolver" }, 400);

  const pend = await env.DB.prepare("SELECT id, vendedor_id FROM cuentas_cobro WHERE id = ? AND estado = 'pendiente'").bind(id).first();
  if (!pend) return json({ error: "Ese cambio ya no está pendiente." }, 409);
  const vend = await env.DB.prepare("SELECT nombre FROM vendedores WHERE id = ?").bind(pend.vendedor_id).first();
  const nombre = vend ? vend.nombre : pend.vendedor_id;

  if (aprobar) {
    await env.DB.batch([
      env.DB.prepare("UPDATE cuentas_cobro SET estado = 'sustituida' WHERE vendedor_id = ? AND estado = 'vigente'").bind(pend.vendedor_id),
      env.DB.prepare("UPDATE cuentas_cobro SET estado = 'vigente' WHERE id = ? AND estado = 'pendiente'").bind(id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, "Aprobó cambio de cuenta de cobro de " + nombre),
    ]);
  } else {
    await env.DB.batch([
      env.DB.prepare("UPDATE cuentas_cobro SET estado = 'rechazada' WHERE id = ? AND estado = 'pendiente'").bind(id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, "Rechazó cambio de cuenta de cobro de " + nombre),
    ]);
  }
  return json({ success: true });
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

// El correo es la llave de acceso del vendedor: dos vendedores con el mismo correo recibirían el código del otro.
async function correoVendedorUsado(env, correo, excluirId) {
  const r = await env.DB.prepare("SELECT id FROM vendedores WHERE lower(correo) = lower(?) AND id <> ? LIMIT 1").bind(correo, excluirId || "").first();
  return !!r;
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

  if (correo && (await correoVendedorUsado(env, correo, null))) return json({ error: "Ese correo ya es de otro vendedor" }, 409);

  const id = "V-" + crypto.randomUUID().slice(0, 8);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO vendedores (id, nombre, whatsapp, correo, nivel, estado) VALUES (?, ?, ?, ?, ?, 'activo')").bind(id, nombre, whatsapp, correo, nivel),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Alta de vendedor ${id} (${nombre})`),
  ]);
  return json({ success: true, id }, 201);
}

// ---------- Solicitudes de alta de vendedor (formulario de bienvisto.com.mx/vendedores) ----------
async function listarAltasVendedor(env) {
  const { results } = await env.DB.prepare(
    "SELECT id, nombre, whatsapp, correo, zona, invito, estado, vendedor_id, motivo_rechazo, resuelto_por, resolved_at, created_at FROM altas_vendedor ORDER BY created_at DESC LIMIT 200"
  ).all();
  return json(results || []);
}

async function resolverAltaVendedor(request, env, url, usuario) {
  const id = decodeURIComponent(url.pathname.slice("/api/altas-vendedor/".length));
  if (!/^AV-[0-9a-f]{8}$/.test(id)) return json({ error: "Solicitud inválida" }, 400);
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);
  const alta = await env.DB.prepare("SELECT * FROM altas_vendedor WHERE id = ?").bind(id).first();
  if (!alta) return json({ error: "Solicitud no encontrada" }, 404);
  if (alta.estado !== "pendiente") return json({ error: "La solicitud ya fue resuelta" }, 409);

  if (body.accion === "rechazar") {
    const motivo = typeof body.motivo === "string" ? body.motivo.trim().slice(0, 300) : "";
    await env.DB.batch([
      env.DB.prepare("UPDATE altas_vendedor SET estado = 'rechazada', motivo_rechazo = ?, resuelto_por = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(motivo || null, usuario, id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Rechazó la solicitud de vendedor ${id} (${alta.nombre})`),
    ]);
    return json({ success: true });
  }

  if (body.accion === "aprobar") {
    if (await correoVendedorUsado(env, alta.correo, null)) return json({ error: "Ese correo ya es de otro vendedor" }, 409);
    const vid = "V-" + crypto.randomUUID().slice(0, 8);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO vendedores (id, nombre, whatsapp, correo, nivel, estado) VALUES (?, ?, ?, ?, 'nuevo', 'activo')").bind(vid, alta.nombre, limpiarWhatsapp(alta.whatsapp), alta.correo),
      env.DB.prepare("UPDATE altas_vendedor SET estado = 'aprobada', vendedor_id = ?, resuelto_por = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(vid, usuario, id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Aprobó la solicitud de vendedor ${id}: alta de ${vid} (${alta.nombre})`),
    ]);
    return json({ success: true, vendedor_id: vid });
  }
  return json({ error: "accion debe ser aprobar o rechazar" }, 400);
}

// Guarda la solicitud para que aparezca en el panel. Si la base falla, el correo sale de todos modos.
// Devuelve { id } si es nueva, { id, repetida: true } si ese correo ya tenía una pendiente, o null si no se pudo guardar.
async function registrarAltaVendedor(env, d) {
  try {
    const previa = await env.DB.prepare("SELECT id FROM altas_vendedor WHERE lower(correo) = lower(?) AND estado = 'pendiente' LIMIT 1").bind(d.correo).first();
    if (previa) return { id: previa.id, repetida: true };
    const id = "AV-" + crypto.randomUUID().slice(0, 8);
    await env.DB.prepare("INSERT INTO altas_vendedor (id, nombre, whatsapp, correo, zona, invito) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(id, d.nombre, d.whatsapp || null, d.correo, d.zona || null, d.invito || null).run();
    return { id };
  } catch (e) {
    console.log("altas_vendedor: no se pudo guardar " + (e && e.message));
    return null;
  }
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
  if (correo && correo !== actual.correo && (await correoVendedorUsado(env, correo, id))) {
    return json({ error: "Ese correo ya es de otro vendedor" }, 409);
  }
  if (estado === "inactivo" && actual.estado !== "inactivo") {
    // Sus displays libres pasan a otro vendedor o a bodega. Si alguno está en una venta sin cobrar, esa venta quedaría atorada.
    const abiertas = await env.DB.prepare("SELECT COUNT(*) AS n FROM ventas WHERE vendedor_id = ? AND estado IN ('pendiente','rev')").bind(id).first();
    if (abiertas && abiertas.n > 0) {
      return json({ error: `Tiene ${abiertas.n} venta${abiertas.n === 1 ? "" : "s"} sin cobrar. Cóbralas o anúlalas antes de desactivarlo.` }, 409);
    }
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
  const enVenta = await env.DB.prepare(`SELECT folio FROM venta_folios WHERE folio IN (${marcas}) LIMIT 1`).bind(...folios).first();
  if (enVenta) return json({ error: `El display ${enVenta.folio} está en una venta sin cobrar. Cóbrala o anúlala antes de reasignarlo.` }, 409);

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

async function actualizarLote(request, env, url, usuario) {
  const id = decodeURIComponent(url.pathname.slice("/api/lotes/".length));
  if (!/^LOTE-\d+$/.test(id)) {
    return json({ error: "Lote inválido" }, 400);
  }

  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const existe = await env.DB.prepare("SELECT id, tipo, costo, destino, nota FROM lotes WHERE id = ?").bind(id).first();
  if (!existe) return json({ error: "Lote no encontrado" }, 404);

  // Solo cambia lo que viene en el cuerpo; lo demás conserva su valor (antes, un campo ausente se borraba o el costo quedaba en 0).
  const tipo = "tipo" in body ? (typeof body.tipo === "string" && body.tipo.trim() ? body.tipo.trim().slice(0, 100) : "Reseñas de Google") : existe.tipo;
  const costo = "costo" in body ? Number(body.costo) : existe.costo;
  if (!Number.isFinite(costo) || costo < 0 || costo > 100000) {
    return json({ error: "costo no válido" }, 400);
  }
  const destino = "destino" in body ? (typeof body.destino === "string" && body.destino.trim() ? body.destino.trim().slice(0, 200) : null) : existe.destino;
  const nota = "nota" in body ? (typeof body.nota === "string" && body.nota.trim() ? body.nota.trim().slice(0, 300) : null) : existe.nota;

  await env.DB.batch([
    env.DB.prepare("UPDATE lotes SET tipo = ?, costo = ?, destino = ?, nota = ? WHERE id = ?").bind(tipo, costo, destino, nota, id),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Editó el lote ${id} (costo ${costo})`),
  ]);

  return json({ success: true, id });
}

// Borra un lote y sus folios solo si ninguno está en uso (todos libres, sin negocio,
// sin cambios registrados). Todo en una sola transacción.
async function borrarLote(env, url, usuario) {
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

  const enVenta = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM venta_folios WHERE folio IN (SELECT folio FROM folios WHERE lote_id = ?)"
  ).bind(id).first();
  if (enVenta && enVenta.n > 0) {
    return json({ error: "El lote tiene displays en una venta. No se puede borrar." }, 409);
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
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Borró el lote ${id} (${folios ? folios.n : 0} displays)`),
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

// Historial completo en CSV (sin el límite de la pantalla). Hora en Ciudad de México (UTC-6, sin horario de verano).
async function auditoriaCsv(env) {
  const { results } = await env.DB.prepare(
    `SELECT datetime(fecha, '-6 hours') AS fecha, usuario, accion, folio_afectado FROM auditoria
     UNION ALL
     SELECT datetime(fecha, '-6 hours') AS fecha, cambiado_por AS usuario, 'Estado: ' || COALESCE(estado_anterior, 'nuevo') || ' → ' || estado_nuevo AS accion, folio AS folio_afectado FROM auditoria_estados
     ORDER BY fecha DESC`
  ).all();
  // Escapa comillas, saltos de línea y fórmulas (=, +, -, @) para que Excel no las ejecute.
  const celda = (v) => {
    let t = v == null ? "" : String(v);
    if (/^[=+\-@]/.test(t)) t = "'" + t;
    return /[",\n\r]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t;
  };
  const lineas = ["fecha (hora Ciudad de México),usuario,accion,folio"];
  for (const r of results) lineas.push([r.fecha, r.usuario, r.accion, r.folio_afectado].map(celda).join(","));
  return new Response("\uFEFF" + lineas.join("\r\n") + "\r\n", {
    headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="historial-bienvisto.csv"', "Cache-Control": "no-store", "X-Robots-Tag": "noindex" },
  });
}

// ---------- Configuración (precios, promoción, comisión, pruebas, topes) ----------
const CONFIG_CLAVES = [
  "precio_display", "promo_n", "promo_precio", "comision_display", "prueba_minutos", "tope_nuevo", "tope_confianza",
  "horas", "recibo_min", "lim_rep", "dias_bono", "lead_d", "colch", "parado_d", "esc_bajo", "bonos_on",
  "bono1_n", "bono1_b", "bono2_n", "bono2_b", "bono3_n", "bono3_b",
];
// Valores que pueden ser 0 (coinciden con los mínimos del panel de Ajustes). El resto debe ser mayor que cero.
const CONFIG_PUEDE_CERO = ["lim_rep", "recibo_min", "bonos_on", "comision_display", "colch", "esc_bajo"];

const ISR_TASAS = [1, 1.1, 1.5, 2, 2.5];

// Tasa de IVA en porcentaje entero (0..30). Se usa en el panel y en el recibo; por defecto 16.
const IVA_TASA_MAX = 30;

// Valores opcionales: si nunca se han guardado, costo_produccion es null (se usa el promedio de lotes) e isr_tasa es 1.
async function leerConfigAdmin(env) {
  const { results } = await env.DB.prepare("SELECT clave, valor FROM config WHERE clave IN ('costo_produccion', 'isr_tasa', 'iva_tasa', 'referidos_on')").all();
  const out = { costo_produccion: null, isr_tasa: 1, iva_tasa: 16, referidos_on: 0 };
  for (const r of results) out[r.clave] = r.valor;
  return out;
}

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

  // Costo de producción e ISR: no son reglas del vendedor, se guardan aparte con valores por defecto.
  const admin = {};
  if ("costo_produccion" in body) {
    const v = Number(body.costo_produccion);
    if (!Number.isInteger(v) || v < 0 || v > 9999) return json({ error: "costo_produccion no válido" }, 400);
    admin.costo_produccion = v;
    delete body.costo_produccion;
  }
  if ("isr_tasa" in body) {
    const v = Number(body.isr_tasa);
    if (!ISR_TASAS.includes(v)) return json({ error: "isr_tasa no válida" }, 400);
    admin.isr_tasa = v;
    delete body.isr_tasa;
  }
  // Programa de referidos: apagado por defecto. Solo guarda la bandera; la lógica del vendedor aún no existe.
  if ("referidos_on" in body) {
    const v = Number(body.referidos_on);
    if (v !== 0 && v !== 1) return json({ error: "referidos_on debe ser 0 o 1" }, 400);
    admin.referidos_on = v;
    delete body.referidos_on;
  }
  if ("iva_tasa" in body) {
    const v = Number(body.iva_tasa);
    if (!Number.isInteger(v) || v < 0 || v > IVA_TASA_MAX) return json({ error: "iva_tasa no válida" }, 400);
    admin.iva_tasa = v;
    delete body.iva_tasa;
  }
  if (Object.keys(admin).length) {
    const stmtsAdmin = Object.entries(admin).map(([k, v]) =>
      env.DB.prepare(
        "INSERT INTO config (clave, valor, updated_by, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP"
      ).bind(k, v, usuario)
    );
    stmtsAdmin.push(
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(
        usuario,
        Object.entries(admin).map(([k, v]) => `Config ${k} = ${v}`).join("; ")
      )
    );
    await env.DB.batch(stmtsAdmin);
  }

  const claves = Object.keys(body);
  if (claves.length === 0) {
    if (Object.keys(admin).length) return json({ ...(await leerConfig(env)), ...(await leerConfigAdmin(env)) });
    return json({ error: "Nada que actualizar" }, 400);
  }
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

  // Reglas entre campos, revisadas sobre cómo quedaría la configuración completa.
  {
    const c = { ...(await leerConfig(env)) };
    for (const k of claves) c[k] = body[k];
    const n = (k) => Number(c[k]);
    if (n("comision_display") > n("precio_display")) return json({ error: "La comisión no puede ser mayor que el precio del display" }, 400);
    if (n("promo_precio") > n("promo_n") * n("precio_display")) return json({ error: "La promoción no puede costar más que comprar los displays por separado" }, 400);
    if (n("comision_display") * n("promo_n") > n("promo_precio")) return json({ error: "Con esa comisión, la promoción deja al vendedor más de lo que paga el cliente" }, 400);
    if (n("tope_nuevo") > n("tope_confianza")) return json({ error: "El tope de un vendedor nuevo no puede ser mayor que el de confianza" }, 400);
    if (!(n("bono1_n") < n("bono2_n") && n("bono2_n") < n("bono3_n"))) return json({ error: "Las metas de bono deben ir de menor a mayor" }, 400);
    if (!(n("bono1_b") <= n("bono2_b") && n("bono2_b") <= n("bono3_b"))) return json({ error: "Los bonos deben ir de menor a mayor" }, 400);
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

// ==========================================
// CUENTA DE COBRO DEL VENDEDOR (transferencias)
// ==========================================
const BANCOS_CLABE = {'002':'Banamex','006':'Bancomext','009':'Banobras','012':'BBVA','014':'Santander','019':'Banjército','021':'HSBC','030':'BanBajío','032':'IXE','036':'Inbursa','037':'Interacciones','042':'Mifel','044':'Scotiabank','058':'Banregio','059':'Invex','060':'Bansí','062':'Afirme','072':'Banorte','103':'American Express','106':'Bank of America','108':'MUFG','110':'JP Morgan','112':'BMonex','113':'Ve por Más','127':'Azteca','130':'Compartamos','131':'Famsa','132':'Multiva','133':'Actinver','135':'Nafin','136':'Inter Banco','137':'BanCoppel','138':'ABC Capital','140':'Consubanco','143':'CIBanco','145':'BBase','147':'Bankaool','148':'PagaTodo','152':'Bancrea','154':'Covalto','155':'ICBC','156':'Sabadell','157':'Shinhan','158':'Mizuho','159':'Bank of China','160':'Banco S3','166':'Banco del Bienestar','168':'Hipotecaria Federal','638':'Nu México','646':'STP','722':'Mercado Pago','728':'Spin by OXXO'};
const TIPOS_CUENTA = ["Débito", "Nómina", "Ahorro", "Cheques"];

function sinAcentos(texto) {
  return String(texto || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/\s+/g, " ").trim();
}

function digitoClabe(c) {
  const pesos = [3, 7, 1];
  let total = 0;
  for (let i = 0; i < 17; i++) total += (Number(c[i]) * pesos[i % 3]) % 10;
  return (10 - (total % 10)) % 10;
}

// Devuelve un mensaje de error (string) o los datos limpios.
function validarCuentaCobro(body, nombreVendedor) {
  const titular = limpiarTexto(body.titular, 120);
  if (!titular || titular.length < 5) return "Escribe el nombre del titular, tal como aparece en tu banco.";
  const palabras = sinAcentos(nombreVendedor).split(" ").filter(Boolean);
  const b = sinAcentos(titular);
  if (!palabras.every((w) => b.includes(w))) return "El titular debe ser " + nombreVendedor + ". No se aceptan cuentas de otra persona.";
  const clabe = String(body.clabe || "").replace(/[\s-]/g, "");
  if (!/^\d{18}$/.test(clabe)) return "La CLABE son 18 dígitos. Revisa que no tenga letras ni espacios de más.";
  if (!BANCOS_CLABE[clabe.slice(0, 3)]) return "Los primeros 3 dígitos no son de un banco reconocido. Revisa que sea la CLABE y no otro número.";
  if (digitoClabe(clabe) !== Number(clabe[17])) return "El último dígito no coincide: hay un error de dedo en la CLABE. Compárala con tu app del banco.";
  const cuenta = String(body.cuenta || "").replace(/\s/g, "");
  if (!/^\d{8,11}$/.test(cuenta)) return "El número de cuenta debe tener entre 8 y 11 dígitos.";
  if (!TIPOS_CUENTA.includes(body.tipo)) return "Elige el tipo de cuenta.";
  return { titular, clabe, cuenta, tipo: body.tipo };
}

function presentarCuenta(r) {
  return { titular: r.titular, banco: BANCOS_CLABE[r.clabe.slice(0, 3)] || "", clabe: r.clabe, cuenta: r.cuenta, tipo: r.tipo, desde: r.created_at };
}

async function vendedorCuentaCobro(env, vendedor) {
  const { results } = await env.DB.prepare(
    "SELECT id, titular, clabe, cuenta, tipo, estado, created_at FROM cuentas_cobro WHERE vendedor_id = ? AND estado IN ('vigente', 'pendiente', 'rechazada', 'cancelada', 'sustituida') ORDER BY id DESC"
  ).bind(vendedor.id).all();
  const vigente = results.find((r) => r.estado === "vigente");
  const pendiente = results.find((r) => r.estado === "pendiente");
  // Avisos según la última solicitud del vendedor. Si pide otro cambio, el aviso anterior deja de mostrarse.
  // 'sustituida' solo existe cuando Bien Visto aprobó un cambio; así se distingue una aprobación de la primera cuenta.
  const ultima = results[0];
  const rechazada = ultima && ultima.estado === "rechazada" ? presentarCuenta(ultima) : null;
  const aprobada = ultima && ultima.estado === "vigente" && results.some((r) => r.estado === "sustituida") ? presentarCuenta(ultima) : null;
  return json({
    vigente: vigente ? presentarCuenta(vigente) : null,
    pendiente: pendiente ? presentarCuenta(pendiente) : null,
    rechazada,
    aprobada,
  });
}

// Primera carga: queda vigente de inmediato. Después, cualquier cambio queda pendiente de aprobación de Bien Visto
// y sigue vigente la cuenta anterior hasta que se apruebe.
async function guardarCuentaCobro(request, env, vendedor) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);
  const datos = validarCuentaCobro(body, vendedor.nombre);
  if (typeof datos === "string") return json({ error: datos }, 400);

  const vigente = await env.DB.prepare("SELECT titular, clabe, cuenta, tipo FROM cuentas_cobro WHERE vendedor_id = ? AND estado = 'vigente'").bind(vendedor.id).first();
  if (vigente && vigente.titular === datos.titular && vigente.clabe === datos.clabe && vigente.cuenta === datos.cuenta && vigente.tipo === datos.tipo) {
    return json({ error: "No cambiaste nada" }, 409);
  }
  const estado = vigente ? "pendiente" : "vigente";
  const stmts = [];
  if (estado === "pendiente") {
    stmts.push(env.DB.prepare("UPDATE cuentas_cobro SET estado = 'cancelada' WHERE vendedor_id = ? AND estado = 'pendiente'").bind(vendedor.id));
  }
  stmts.push(
    env.DB.prepare("INSERT INTO cuentas_cobro (vendedor_id, titular, clabe, cuenta, tipo, estado) VALUES (?, ?, ?, ?, ?, ?)").bind(vendedor.id, datos.titular, datos.clabe, datos.cuenta, datos.tipo, estado),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind("vendedor:" + vendedor.id, (estado === "pendiente" ? "Pidió cambio de cuenta de cobro (en revisión)" : "Cargó su cuenta de cobro")),
  );
  await env.DB.batch(stmts);
  return json({ success: true, estado }, 201);
}

async function cancelarCambioCuenta(env, vendedor) {
  await env.DB.batch([
    env.DB.prepare("UPDATE cuentas_cobro SET estado = 'cancelada' WHERE vendedor_id = ? AND estado = 'pendiente'").bind(vendedor.id),
  ]);
  return json({ success: true });
}

// Página pública de pago para el cliente: solo datos de la cuenta de cobro de esa venta.
const escHtml = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
// Isologo reverso de la marca (archivo del Brand Book). Va fijo en el código, nunca viene de datos.
const ISOLOGO_REVERSO = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 711.85 156.25" role="img" aria-labelledby="t"><title id="t">Bien Visto isologo reverso</title><rect width="711.85" height="156.25" rx="78.12" fill="#FBF6EC"/><g transform="translate(22.49 4.52) scale(0.52)"><path fill="#0E6B5C" d="M62 163 L62 78 A16 16 0 0 0 30 78 L30 163 A16 16 0 0 0 62 163 Z"/><path fill="#0E6B5C" fill-rule="evenodd" d="M30 163 A59 59 0 1 1 148 163 A59 59 0 1 1 30 163 Z M62 163 A27 27 0 1 0 116 163 A27 27 0 1 0 62 163 Z"/><path fill="#F2A71B" d="M159.53 150 L197.35 215.5 A15 15 0 0 0 223.33 215.5 L298.96 84.5 A15 15 0 0 0 272.98 69.5 L210.34 178 L185.51 135 A15 15 0 0 0 159.53 150 Z"/></g><g transform="translate(212.08 118.25) scale(0.5)"><path fill="#12302B" transform="translate(0 0)" d="M0 -59V-148.68C0 -155.86 5.82 -161.68 13 -161.68C20.18 -161.68 26 -155.86 26 -148.68V-108.97C35.91 -115.92 47.98 -120 61 -120C94.69 -120 122 -92.69 122 -59C122 -25.31 94.69 2 61 2C27.31 2 0 -25.31 0 -59ZM26.78 -59C26.78 -40.1 42.1 -24.78 61 -24.78C79.9 -24.78 95.22 -40.1 95.22 -59C95.22 -77.9 79.9 -93.22 61 -93.22C42.1 -93.22 26.78 -77.9 26.78 -59Z"/><path fill="#12302B" transform="translate(137.84 0)" d="M26 -11.8C26 -4.62 20.18 1.2 13 1.2C5.82 1.2 0 -4.62 0 -11.8V-106.2C0 -113.38 5.82 -119.2 13 -119.2C20.18 -119.2 26 -113.38 26 -106.2ZM-2.08 -146.5C-2.08 -154.83 4.67 -161.58 13 -161.58C21.33 -161.58 28.08 -154.83 28.08 -146.5C28.08 -138.17 21.33 -131.42 13 -131.42C4.67 -131.42 -2.08 -138.17 -2.08 -146.5Z"/><path fill="#12302B" transform="translate(179.69 0)" d="M121.11 -69.39C122.39 -61.99 122.29 -54.41 120.82 -47.04H28.94C30.71 -42.28 33.57 -37.86 37.44 -34.18C48.76 -23.44 65.9 -21.72 79.13 -29.98C85.4 -33.9 93.66 -32 97.58 -25.73C101.51 -19.45 99.6 -11.19 93.33 -7.27C69.75 7.47 39.19 4.39 19.01 -14.75C-1.16 -33.89 -5.83 -64.25 7.65 -88.57C21.13 -112.89 49.35 -125.02 76.27 -118.06C99.78 -111.98 117.1 -92.69 121.11 -69.39ZM93.07 -70.96C89.24 -81.2 80.63 -89.27 69.57 -92.13C54.47 -96.04 38.64 -89.24 31.07 -75.6C30.24 -74.09 29.52 -72.54 28.93 -70.96H93.07Z"/><path fill="#12302B" transform="translate(312.49 0)" d="M26 -11.8C26 -4.62 20.18 1.2 13 1.2C5.82 1.2 0 -4.62 0 -11.8V-106.2C0 -113.38 5.82 -119.2 13 -119.2C17.76 -119.2 21.92 -116.64 24.19 -112.83C31.72 -117.38 40.55 -120 50 -120C77.61 -120 100 -97.61 100 -70V-11.8C100 -4.62 94.18 1.2 87 1.2C79.82 1.2 74 -4.62 74 -11.8V-70C74 -83.25 63.25 -94 50 -94C36.75 -94 26 -83.25 26 -70Z"/><path fill="#12302B" transform="translate(456.15 0)" d="M1.45 -101.05 52.49 -5.05C54.63 -1.02 58.83 1.5 63.4 1.5C67.96 1.5 72.16 -1.02 74.3 -5.05L125.34 -101.05C128.54 -107.07 126.26 -114.55 120.24 -117.75C114.21 -120.96 106.73 -118.67 103.53 -112.65L63.39 -37.16L23.25 -112.65C19.97 -118.51 12.6 -120.67 6.68 -117.51C0.75 -114.36 -1.57 -107.05 1.45 -101.05Z"/><path fill="#12302B" transform="translate(593.63 0)" d="M26 -11.8C26 -4.62 20.18 1.2 13 1.2C5.82 1.2 0 -4.62 0 -11.8V-106.2C0 -113.38 5.82 -119.2 13 -119.2C20.18 -119.2 26 -113.38 26 -106.2ZM-2.08 -146.5C-2.08 -154.83 4.67 -161.58 13 -161.58C21.33 -161.58 28.08 -154.83 28.08 -146.5C28.08 -138.17 21.33 -131.42 13 -131.42C4.67 -131.42 -2.08 -138.17 -2.08 -146.5Z"/><path fill="#12302B" transform="translate(633.81 0)" d="M67.33 -104.48C71.15 -98.82 69.66 -91.15 64 -87.33C58.34 -83.51 50.67 -85 46.85 -90.66C44.05 -94.82 38.7 -96.43 34.07 -94.5C29.44 -92.57 26.82 -87.64 27.81 -82.72C28.79 -77.81 33.11 -74.27 38.12 -74.27L38.13 -74.27C56.63 -74.27 72.47 -60.98 75.68 -42.76C78.89 -24.54 68.56 -6.64 51.17 -0.31C33.79 6.02 14.36 -1.05 5.11 -17.07C1.76 -22.97 3.8 -30.47 9.68 -33.86C15.55 -37.25 23.06 -35.27 26.5 -29.42C29.76 -23.78 36.6 -21.29 42.72 -23.52C48.85 -25.75 52.49 -32.06 51.35 -38.47C50.22 -44.89 44.65 -49.57 38.13 -49.57C21.35 -49.57 6.89 -61.41 3.59 -77.87C0.3 -94.33 9.07 -110.82 24.56 -117.29C40.05 -123.76 57.95 -118.4 67.33 -104.48Z"/><path fill="#12302B" transform="translate(721.98 0)" d="M2 -95.28C-4.61 -95.28 -9.96 -100.63 -9.96 -107.24C-9.96 -113.85 -4.61 -119.2 2 -119.2H16.22C17.35 -125.23 22.64 -129.8 29 -129.8C35.36 -129.8 40.65 -125.23 41.78 -119.2H63C69.61 -119.2 74.96 -113.85 74.96 -107.24C74.96 -100.63 69.61 -95.28 63 -95.28H42V-43.8C42 -33.31 50.51 -24.8 61 -24.8C68.18 -24.8 74 -18.98 74 -11.8C74 -4.62 68.18 1.2 61 1.2C36.15 1.2 16 -18.95 16 -43.8V-95.28Z"/><path fill="#12302B" transform="translate(793.55 0)" d="M0 -59C0 -92.69 27.31 -120 61 -120C94.69 -120 122 -92.69 122 -59C122 -25.31 94.69 2 61 2C27.31 2 0 -25.31 0 -59ZM26.78 -59C26.78 -40.1 42.1 -24.78 61 -24.78C79.9 -24.78 95.22 -40.1 95.22 -59C95.22 -77.9 79.9 -93.22 61 -93.22C42.1 -93.22 26.78 -77.9 26.78 -59Z"/></g></svg>`;

function paginaPago(titulo, mensaje, status, bloque = "") {
  // Marca Bien Visto (Brand Book): Bricolage Grotesque para títulos, Figtree para texto, colores de la marca e isologo reverso.
  const isologo = `${ISOLOGO_REVERSO}`;
  const html = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${escHtml(titulo)} · Bien Visto</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500..800&family=Figtree:wght@400..700&display=swap" rel="stylesheet">
<style>:root{--verde:#0E6B5C;--tinta:#12302B;--crema:#FBF6EC;--menta:#E7F0EC;--muted:#4A5F59;--borde:#CFDDD6;--borde-s:#6B897E;--ambar:#F2A71B;--ambar-claro:#FFF3D6;--danger:#B3261E;--fd:"Bricolage Grotesque","Arial Narrow",system-ui,sans-serif;--fb:"Figtree",system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--crema);color:var(--tinta);font:400 16px/1.5 var(--fb)}
header{background:var(--verde);padding:18px 16px;display:flex;justify-content:center}header svg{width:min(260px,72%);height:auto;display:block}
main{max-width:460px;margin:0 auto;padding:20px 16px 32px}
h1{font:600 30px/1.1 var(--fd);margin:4px 0 8px;color:var(--tinta)}main>p{color:var(--muted);margin:0 0 4px}
.card{background:#fff;border:1px solid var(--borde);border-radius:16px;padding:14px 16px;margin:12px 0}
.monto{font:600 40px/1 var(--fd);color:var(--verde);margin:4px 0 0}
.lbl{font:600 13px/1.2 var(--fb);color:var(--muted);margin:0;letter-spacing:.02em}
.fila{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-top:1px solid var(--menta)}
.card .fila:first-child{border-top:0;padding-top:4px}
.val{font:600 17px/1.3 var(--fb);margin:2px 0 0;word-break:break-all}
.fila button{background:#fff;color:var(--tinta);border:2px solid var(--borde-s);border-radius:999px;padding:8px 14px;font:600 14px/1 var(--fb);cursor:pointer;flex:none;min-height:40px}
.fila button:focus-visible{outline:3px solid var(--ambar);outline-offset:2px}
footer{max-width:460px;margin:8px auto 0;padding:18px 16px 32px;border-top:1px solid var(--borde);text-align:center;font:400 14px/1.7 var(--fb);color:var(--muted)}
footer a{color:var(--verde);font-weight:600;text-decoration:underline;text-underline-offset:3px}footer a:focus-visible{outline:3px solid var(--ambar);outline-offset:2px;border-radius:4px}
footer .enlaces{display:flex;flex-wrap:wrap;justify-content:center;gap:4px 18px;margin:0 0 6px}footer p{margin:0}
.aviso{background:var(--ambar-claro);border:2px solid var(--ambar);border-radius:16px;padding:12px 14px;font-size:15px;margin:12px 0 0}
</style></head>
<body><header>${isologo}</header><main><h1>${escHtml(titulo)}</h1><p>${escHtml(mensaje)}</p>${bloque}</main>
<footer><p class="enlaces"><a href="https://bienvisto.com.mx/terminos-clientes" target="_blank" rel="noopener">Términos y condiciones</a><a href="https://bienvisto.com.mx/privacidad" target="_blank" rel="noopener">Aviso de privacidad</a></p><p><a href="https://bienvisto.com.mx/">bienvisto.com.mx</a></p></footer>
<script>document.querySelectorAll("[data-copiar]").forEach(function(b){b.addEventListener("click",function(){var t=b.getAttribute("data-copiar");(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).catch(function(){});b.textContent="Copiado";setTimeout(function(){b.textContent="Copiar"},1800)})});</script></body></html>`;
  return new Response(html, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex" } });
}

async function pagoPublico(env, url) {
  const id = decodeURIComponent(url.pathname.slice("/pago/".length));
  if (!/^VN-[0-9a-f]{8}$/.test(id)) return paginaPago("Enlace no válido", "Revisa el enlace que te compartió tu vendedor.", 404);
  const v = await env.DB.prepare(
    "SELECT v.estado, v.metodo, v.total, c.titular, c.clabe, c.cuenta, c.tipo FROM ventas v LEFT JOIN cuentas_cobro c ON c.id = v.cuenta_cobro_id WHERE v.id = ?"
  ).bind(id).first();
  if (!v) return paginaPago("No encontramos esa venta", "Revisa el enlace que te compartió tu vendedor.", 404);
  if (v.estado === "anulada" || v.estado === "rechazada") {
    return paginaPago("Esta venta fue cancelada", "No hagas el pago. Pregunta a tu vendedor.", 410);
  }
  if (v.estado === "cobrada" || v.estado === "entregada") {
    return paginaPago("Este pago ya fue registrado", "No necesitas pagar de nuevo. Si tienes dudas, pregunta a tu vendedor.", 200);
  }
  if (v.estado === "rev") {
    return paginaPago("Tu pago está en revisión", "Tu vendedor ya avisó que pagaste. No pagues de nuevo; si tienes dudas, pregúntale.", 200);
  }
  if (v.metodo !== "transferencia" || !v.clabe) {
    return paginaPago("Esta venta no se paga por transferencia", "Paga en efectivo a tu vendedor.", 404);
  }
  const monto = Number(v.total).toLocaleString("es-MX", { style: "currency", currency: "MXN", minimumFractionDigits: Number.isInteger(Number(v.total)) ? 0 : 2 });
  const fila = (etiqueta, valor) => `<div class="fila"><div><p class="lbl">${escHtml(etiqueta)}</p><p class="val">${escHtml(valor)}</p></div><button type="button" data-copiar="${escHtml(valor)}">Copiar</button></div>`;
  const bloque = `<div class="card"><div class="fila"><div><p class="lbl">Monto a pagar</p><p class="val">${escHtml(monto)}</p></div></div>
${fila("Titular", v.titular)}${fila("Banco", BANCOS_CLABE[v.clabe.slice(0, 3)] || "")}${fila("CLABE", v.clabe)}${fila("Cuenta", v.cuenta)}${fila("Concepto", id)}</div>
<p class="aviso">Escribe el concepto tal cual aparece para que tu vendedor encuentre tu pago.</p>`;
  return paginaPago("Datos para pagar", "Transfiere el monto exacto a esta cuenta.", 200, bloque);
}

async function crearVenta(request, env, usuario, vendedorSesion = null) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const vendedor = vendedorSesion ? vendedorSesion.id : (typeof body.vendedor_id === "string" ? body.vendedor_id : null);
  if (!vendedor) return json({ error: "vendedor_id es obligatorio" }, 400);
  const negocio = limpiarTexto(body.negocio, 200);
  if (!negocio) return json({ error: "negocio es obligatorio" }, 400);
  if (!METODOS.includes(body.metodo)) return json({ error: "metodo no válido" }, 400);
  const folios = limpiarFoliosVenta(body.folios);
  if (!folios) return json({ error: `folios debe tener entre 1 y ${MAX_VENTA} displays distintos` }, 400);

  const v = await env.DB.prepare("SELECT id, nivel FROM vendedores WHERE id = ? AND estado = 'activo'").bind(vendedor).first();
  if (!v) return json({ error: "Vendedor no válido o inactivo" }, 400);
  const adeudo = await env.DB.prepare("SELECT 1 AS x FROM ventas WHERE vendedor_id = ? AND impago = 1 AND estado <> 'anulada' LIMIT 1").bind(vendedor).first();
  if (adeudo) return json({ error: "El vendedor tiene un adeudo por impago; no puede activar displays nuevos" }, 409);

  const marcas = folios.map(() => "?").join(",");
  await aplicarVencimientos(env, "sistema", null, (await leerConfig(env)).prueba_minutos);
  const { results: fs } = await env.DB.prepare(`SELECT folio, estado, vendedor_id FROM folios WHERE folio IN (${marcas})`).bind(...folios).all();
  if (fs.length !== folios.length) return json({ error: "Algún folio no existe" }, 404);
  if (fs.some((f) => !(f.estado === "libre" || f.estado === "prueba") || f.vendedor_id !== vendedor)) {
    return json({ error: "Solo se venden displays libres asignados a ese vendedor" }, 409);
  }
  let reemplazadas = [];
  const { results: ocupados } = await env.DB.prepare(
    `SELECT vf.folio, vf.venta_id, v.estado, v.vendedor_id FROM venta_folios vf JOIN ventas v ON v.id = vf.venta_id WHERE vf.folio IN (${marcas})`
  ).bind(...folios).all();
  if (ocupados.length) {
    // Reintento: si esos mismos displays (y solo esos) ya están en una venta pendiente de este vendedor,
    // se reutiliza en vez de fallar. Pasa cuando el vendedor compartió o generó el QR y luego volvió a la pantalla.
    // Solo se tocan ventas pendientes del mismo vendedor. Una venta en revisión, cobrada o de otro vendedor sí bloquea.
    if (!ocupados.every((o) => o.estado === "pendiente" && o.vendedor_id === vendedor)) {
      return json({ error: "Algún display ya está en otra venta" }, 409);
    }
    const previas = [...new Set(ocupados.map((o) => o.venta_id))];
    const previa = previas[0];
    let mismaVenta = previas.length === 1 && ocupados.length === folios.length;
    if (mismaVenta) {
      const { n } = await env.DB.prepare("SELECT COUNT(*) AS n FROM venta_folios WHERE venta_id = ?").bind(previa).first();
      mismaVenta = n === folios.length;
    }
    if (mismaVenta) {
      // Si el precio cambió desde que se creó, la venta pendiente se rehace con el precio vigente.
      const prev = await env.DB.prepare("SELECT total FROM ventas WHERE id = ?").bind(previa).first();
      const vigente = calcularVenta(folios.length, await leerConfig(env));
      if (!prev || Math.abs(Number(prev.total) - vigente.total) > 0.001) mismaVenta = false;
    }
    if (!mismaVenta) {
      // Cambió la composición (por ejemplo, de 1 display a 3): las ventas pendientes anteriores se anulan al crear la nueva.
      reemplazadas = previas;
    }
  }
  if (ocupados.length && !reemplazadas.length) {
    const previa = ocupados[0].venta_id;
    let cuentaPrevia = null;
    if (body.metodo === "transferencia") {
      const vig = await env.DB.prepare("SELECT id FROM cuentas_cobro WHERE vendedor_id = ? AND estado = 'vigente'").bind(vendedor).first();
      if (!vig) return json({ error: "Carga tus datos de cobro antes de cobrar por transferencia." }, 409);
      cuentaPrevia = vig.id;
    }
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE ventas SET negocio = ?, direccion = ?, contacto = ?, whatsapp = ?, correo = ?, metodo = ?, cuenta_cobro_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'"
      ).bind(negocio, limpiarTexto(body.direccion, 300), limpiarTexto(body.contacto, 120), limpiarWhatsapp(body.whatsapp), limpiarCorreo(body.correo) || null, body.metodo, cuentaPrevia, previa),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Reutilizó venta pendiente ${previa} (${negocio}, ${folios.length} displays)`),
    ]);
    const calcPrevia = calcularVenta(folios.length, await leerConfig(env));
    return json({ success: true, id: previa, total: calcPrevia.total, comision_total: calcPrevia.comision, a_entregar: calcPrevia.aEntregar, reutilizada: true }, 201);
  }

  const cfg = await leerConfig(env);
  const calc = calcularVenta(folios.length, cfg);

  // Exposición = saldo por entregar más ventas en revisión. Las pendientes no cuentan aquí:
  // el tope se vuelve a revisar al cobrar cada venta, así varias pendientes no pueden rebasarlo.
  const exposicion = await exposicionVendedor(env, vendedor);
  // Plazo: solo ventas cobradas con saldo. Cuenta desde fecha_cobro (created_at si una venta no la tiene).
  const plazo = await env.DB.prepare(
    "SELECT MIN(COALESCE(fecha_cobro, created_at)) AS mas_antigua FROM ventas WHERE vendedor_id = ? AND estado IN ('cobrada','entregada') AND a_entregar - COALESCE(entregado, 0) > 0.001"
  ).bind(vendedor).first();
  if (plazo && plazo.mas_antigua) {
    const horas = (Date.now() - Date.parse(plazo.mas_antigua.replace(" ", "T") + "Z")) / 3600000;
    if (horas >= cfg.horas) {
      return json({ error: "Tienes ventas cobradas que vencieron el plazo de entrega; no puedes activar displays nuevos" }, 409);
    }
  }
  const tope = v.nivel === "confianza" ? Number(cfg.tope_confianza) : Number(cfg.tope_nuevo);
  // Compara la venta completa: exposición actual más lo que esta venta deja al vendedor (a_entregar, con promoción incluida).
  if (exposicion + calc.aEntregar > tope + 0.001) {
    return json({ error: `Esta venta pasaría tu tope de ${fmtMXN(tope)}. Entrega lo que tienes antes de activar más displays.` }, 409);
  }

  let cuentaId = null;
  if (body.metodo === "transferencia") {
    const vig = await env.DB.prepare("SELECT id FROM cuentas_cobro WHERE vendedor_id = ? AND estado = 'vigente'").bind(vendedor).first();
    if (!vig) return json({ error: "Carga tus datos de cobro antes de cobrar por transferencia." }, 409);
    cuentaId = vig.id;
  }

  const id = "VN-" + crypto.randomUUID().slice(0, 8);
  const stmts = [];
  for (const vieja of reemplazadas) {
    stmts.push(
      env.DB.prepare("UPDATE ventas SET estado = 'anulada', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(vieja),
      env.DB.prepare("DELETE FROM venta_folios WHERE venta_id = ?").bind(vieja),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Anuló venta pendiente ${vieja}: reemplazada por ${id}`)
    );
  }
  stmts.push(
    env.DB.prepare(
      "INSERT INTO ventas (id, vendedor_id, negocio, direccion, contacto, whatsapp, correo, metodo, total, comision_total, a_entregar, cuenta_cobro_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(id, vendedor, negocio, limpiarTexto(body.direccion, 300), limpiarTexto(body.contacto, 120), limpiarWhatsapp(body.whatsapp), limpiarCorreo(body.correo) || null, body.metodo, calc.total, calc.comision, calc.aEntregar, cuentaId),
  );
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

  if (body.accion === "enviar_revision") return enviarRevision(env, venta, body, usuario);
  if (body.accion === "impago") return marcarImpago(env, venta, body, usuario);
  if (body.accion === "cobrar") return cobrarVenta(env, venta, body, usuario);
  if (body.accion === "anular") return anularVenta(env, venta, usuario);
  if (body.accion === "recuperar") return recuperarDisplays(env, venta, usuario);
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
async function enviarRevision(env, venta, body, usuario) {
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
      usuario,
      `Venta ${venta.id} enviada a revisión`
    ),
  ]);
  return json({ success: true, id: venta.id, estado: "rev" });
}

// Marca o desmarca la venta como impagada (retirada por impago). Solo mientras está pendiente o en revisión.
async function marcarImpago(env, venta, body, usuario) {
  if (body.valor !== 0 && body.valor !== 1) return json({ error: "valor debe ser 0 o 1" }, 400);
  if (body.valor === 1 && !["pendiente", "rev", "cobrada"].includes(venta.estado)) {
    return json({ error: "Solo una venta pendiente, en revisión o cobrada puede marcarse por impago" }, 409);
  }
  if (body.valor === 0 && venta.estado === "anulada") return json({ error: "La venta está anulada" }, 409);
  await env.DB.batch([
    env.DB.prepare("UPDATE ventas SET impago = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(body.valor, venta.id),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(
      usuario,
      `${body.valor ? "Marcó" : "Quitó"} impago en venta ${venta.id}`
    ),
  ]);
  return json({ success: true, id: venta.id, impago: body.valor });
}

// Días desde la activación en que sale cada resumen; el sexto es el de cierre.
const SEGUIMIENTO_DIAS = [15, 30, 45, 60, 75, 90];

// Plan de cobro compartido por el panel y la app del vendedor: la venta pasa a cobrada, sus displays a activo
// con la reseña (la prueba termina al cobrar) y se programa el recibo al cliente. Devuelve { error } o { stmts, n }.
async function planCobro(env, venta, urlResena, referencia, usuario, cfg) {
  const { results: fs } = await env.DB.prepare(
    "SELECT vf.folio, f.estado, f.vendedor_id FROM venta_folios vf JOIN folios f ON f.folio = vf.folio WHERE vf.venta_id = ?"
  ).bind(venta.id).all();
  if (!fs.length) return { error: json({ error: "La venta no tiene displays" }, 409) };
  if (fs.some((f) => !(f.estado === "libre" || f.estado === "prueba") || f.vendedor_id !== venta.vendedor_id)) {
    return { error: json({ error: "Algún display ya no está libre o no es de ese vendedor" }, 409) };
  }
  const stmts = [
    env.DB.prepare(
      "UPDATE ventas SET estado = 'cobrada', referencia = ?, url_resena = ?, impago = 0, fecha_cobro = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND estado IN ('pendiente','rev')"
    ).bind(referencia, urlResena, venta.id),
  ];
  for (const f of fs) {
    stmts.push(
      env.DB.prepare(
        "UPDATE folios SET estado = 'activo', url_destino = ?, negocio_asignado = ?, direccion = ?, prueba_inicio = NULL, conteo_desde = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado IN ('libre','prueba')"
      ).bind(urlResena, venta.negocio, venta.direccion || null, f.folio),
      env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, ?, 'activo', ?)").bind(f.folio, f.estado, usuario)
    );
  }
  // Seguimiento de 90 días: solo si hay WhatsApp y el interruptor general no está apagado (seguimiento_on = 0).
  const seg = await env.DB.prepare("SELECT valor FROM config WHERE clave = 'seguimiento_on'").first();
  if (String(venta.whatsapp || "").trim() && !(seg && Number(seg.valor) === 0)) {
    stmts.push(env.DB.prepare("INSERT OR IGNORE INTO seguimientos (venta_id, inicio) VALUES (?, date('now', '-6 hours'))").bind(venta.id));
    SEGUIMIENTO_DIAS.forEach((dias, i) => {
      stmts.push(
        env.DB.prepare(
          "INSERT OR IGNORE INTO seguimiento_envios (venta_id, numero, programado_para) SELECT venta_id, ?, date(inicio, '+' || ? || ' days') FROM seguimientos WHERE venta_id = ?"
        ).bind(i + 1, dias, venta.id)
      );
    });
  }
  stmts.push(
    env.DB.prepare("INSERT OR IGNORE INTO envios (venta_id, tipo, destinatario, programado_para) VALUES (?, 'recibo', 'cliente', datetime('now', '+' || ? || ' minutes'))").bind(venta.id, cfg.recibo_min),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Cobró y activó venta ${venta.id} (${venta.negocio}, ${fs.length} displays)`)
  );
  return { stmts, n: fs.length };
}

// Cobro desde el panel (pendiente o rev). Exige URL de Google válida. Es la autoridad: no revisa tope ni plazo.
async function cobrarVenta(env, venta, body, usuario) {
  if (venta.estado !== "pendiente" && venta.estado !== "rev") {
    return json({ error: "Solo se cobra una venta pendiente o en revisión" }, 409);
  }
  if (!esUrlResena(body.url_resena)) return json({ error: "url_resena debe ser una URL https de Google" }, 400);
  const referencia = limpiarTexto(body.referencia, 100) || venta.referencia;
  if (venta.metodo === "transferencia" && !referencia) {
    return json({ error: "La transferencia requiere referencia" }, 400);
  }
  const cfg = await leerConfig(env);
  const plan = await planCobro(env, venta, body.url_resena, referencia, usuario, cfg);
  if (plan.error) return plan.error;
  await env.DB.batch(plan.stmts);
  return json({ success: true, id: venta.id, estado: "cobrada", displays_activos: plan.n });
}

// Marcar por recuperar: el cliente no pagó y el display sigue en su local. Los displays activos de una venta
// cobrada dejan de llevar a reseñas (retirado); la venta y el dinero siguen vigentes hasta anularla.
async function recuperarDisplays(env, venta, usuario) {
  if (venta.estado !== "cobrada") return json({ error: "Solo se marcan por recuperar los displays de una venta cobrada" }, 409);
  const { results: activos } = await env.DB.prepare(
    "SELECT vf.folio FROM venta_folios vf JOIN folios f ON f.folio = vf.folio WHERE vf.venta_id = ? AND f.estado = 'activo'"
  ).bind(venta.id).all();
  if (!activos.length) return json({ error: "Los displays de esta venta ya no están activos" }, 409);
  const stmts = [];
  for (const f of activos) {
    stmts.push(
      env.DB.prepare("UPDATE folios SET estado = 'retirado', updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'activo'").bind(f.folio),
      env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'activo', 'retirado', ?)").bind(f.folio, usuario)
    );
  }
  stmts.push(...stmtsCancelarSeguimiento(env, venta.id));
  stmts.push(env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Marcó por recuperar ${activos.length} displays de la venta ${venta.id}`));
  await env.DB.batch(stmts);
  return json({ success: true, id: venta.id, retirados: activos.length });
}

// Anular: permitido en pendiente, rev o cobrada, siempre que no haya entregas (entregado = 0).
// Si la venta ya estaba cobrada, sus displays activos vuelven a libre y se registran en auditoría de estados.
async function anularVenta(env, venta, usuario) {
  const plan = await planAnular(env, venta, usuario);
  if (plan.error) return plan.error;
  await env.DB.batch(plan.stmts);
  return json({ success: true, id: venta.id, estado: "anulada" });
}

// ==========================================
// Seguimiento de 90 días: resúmenes quincenales por WhatsApp (envío manual desde el panel)
// ==========================================
const SEG_UMBRAL_BAJO = 10;   // menos de esto por display en la quincena = actividad baja
const SEG_UMBRAL_ALTO = 50;   // esto o más por display = actividad alta
const DIAS_SEMANA = ["domingo", "lunes", "martes", "miércoles", "jueves", "viernes", "sábado"];

function sumarDias(dia, n) {
  const d = new Date(dia + "T12:00:00Z");
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

function hora12(h) {
  const h12 = h % 12 === 0 ? 12 : h % 12;
  return `${h12}${h < 12 ? " am" : " pm"}`;
}

// Cifras de una venta (sumando todos sus displays) entre dos días en hora de México. Solo escaneos contados
// y posteriores al último cambio de negocio de cada display.
async function cifrasVenta(env, ventaId, desde, hasta) {
  const { results } = await env.DB.prepare(
    `SELECT e.dia_mx AS dia, CAST(strftime('%H', e.created_at, '-6 hours') AS INTEGER) AS h, e.origen, e.dispositivo
     FROM escaneos e JOIN venta_folios vf ON vf.folio = e.folio JOIN folios f ON f.folio = e.folio
     WHERE vf.venta_id = ? AND e.contado = 1 AND e.dia_mx BETWEEN ? AND ? AND e.created_at >= COALESCE(f.conteo_desde, '')
     LIMIT 20000`
  ).bind(ventaId, desde, hasta).all();
  return results;
}

function resumirCifras(filas, desde, dias) {
  const porDia = [];
  for (let i = 0; i < dias; i++) porDia.push({ dia: sumarDias(desde, i), n: 0 });
  const idx = Object.fromEntries(porDia.map((x, i) => [x.dia, i]));
  const horas = new Array(24).fill(0);
  const sem = new Array(7).fill(0);
  let qr = 0, nfc = 0, ios = 0, android = 0;
  for (const f of filas) {
    if (f.dia in idx) porDia[idx[f.dia]].n++;
    horas[f.h]++;
    sem[new Date(f.dia + "T12:00:00Z").getUTCDay()]++;
    if (f.origen === "qr") qr++; else nfc++;
    if (f.dispositivo === "ios") ios++; else if (f.dispositivo === "android") android++;
  }
  const total = filas.length;
  const mejorDiaSem = total ? sem.indexOf(Math.max(...sem)) : null;
  // Franja de 2 horas con más escaneos.
  let mejorH = null, mejorN = 0;
  for (let h = 0; h < 24; h += 2) {
    const n = horas[h] + horas[h + 1];
    if (n > mejorN) { mejorN = n; mejorH = h; }
  }
  const finde = sem[0] + sem[6];
  return {
    total, por_dia: porDia,
    mejor_dia: mejorDiaSem === null ? null : { nombre: DIAS_SEMANA[mejorDiaSem], n: sem[mejorDiaSem] },
    mejor_franja: mejorH === null ? null : { desde: hora12(mejorH), hasta: hora12((mejorH + 2) % 24), n: mejorN, pct: Math.round((mejorN / total) * 100) },
    pct_finde: total ? Math.round((finde / total) * 100) : 0,
    qr, nfc, ios, android,
  };
}

function hashNum(texto) {
  let h = 0;
  for (let i = 0; i < texto.length; i++) h = (h * 31 + texto.charCodeAt(i)) >>> 0;
  return h;
}

// Elige la recomendación: del nivel, sin repetir las ya enviadas a esa venta, prefiriendo las del momento del seguimiento.
function elegirRecomendacion(recs, nivel, numero, ventaId, usadas) {
  const fase = numero <= 2 ? "inicio" : numero <= 4 ? "medio" : "cierre";
  const delNivel = recs.filter((r) => r.nivel === nivel && r.activa === 1);
  const libres = delNivel.filter((r) => !usadas.has(r.id));
  const orden = (lista) => [...lista].sort((a, b) => hashNum(ventaId + numero + a.id) - hashNum(ventaId + numero + b.id));
  for (const lista of [libres.filter((r) => r.momento === fase), libres.filter((r) => r.momento === "todos"), libres, delNivel]) {
    if (lista.length) return orden(lista)[0];
  }
  return null;
}

function telefonoWa(tel) {
  const t = String(tel || "").replace(/\D/g, "");
  if (t.length === 10) return "52" + t;
  if (t.length === 12 && t.startsWith("52")) return t;
  return "";
}

async function umbralesSeguimiento(env) {
  const { results } = await env.DB.prepare("SELECT clave, valor FROM config WHERE clave IN ('seg_umbral_bajo', 'seg_umbral_alto', 'seguimiento_on')").all();
  const c = Object.fromEntries(results.map((r) => [r.clave, Number(r.valor)]));
  return { bajo: c.seg_umbral_bajo || SEG_UMBRAL_BAJO, alto: c.seg_umbral_alto || SEG_UMBRAL_ALTO, activo: c.seguimiento_on !== 0 };
}

// Todo lo que lleva un resumen: periodo, cifras, nivel, recomendación y datos de contacto.
async function armarResumen(env, s, e, recs, um) {
  const { results: fol } = await env.DB.prepare("SELECT vf.folio FROM venta_folios vf WHERE vf.venta_id = ? ORDER BY vf.folio").bind(s.venta_id).all();
  const folios = fol.map((f) => f.folio);
  const fin = sumarDias(e.programado_para, -1);
  const ini = sumarDias(e.programado_para, -15);
  const actual = resumirCifras(await cifrasVenta(env, s.venta_id, ini, fin), ini, 15);
  let anterior = null;
  if (e.numero > 1) anterior = (await cifrasVenta(env, s.venta_id, sumarDias(ini, -15), sumarDias(ini, -1))).length;
  const acum = (await cifrasVenta(env, s.venta_id, s.inicio, fin)).length;
  const nDisplays = Math.max(1, folios.length);
  const porDisplay = actual.total / nDisplays;
  const nivel = porDisplay < um.bajo ? "bajo" : porDisplay >= um.alto ? "alto" : "medio";
  const { results: prev } = await env.DB.prepare("SELECT datos FROM seguimiento_envios WHERE venta_id = ? AND estado = 'enviado'").bind(s.venta_id).all();
  const usadas = new Set(prev.map((p) => { try { return JSON.parse(p.datos).rec_id; } catch { return null; } }).filter(Boolean));
  const rec = e.numero === 6 ? null : elegirRecomendacion(recs, nivel, e.numero, s.venta_id, usadas);
  return {
    venta_id: s.venta_id, numero: e.numero, programado_para: e.programado_para,
    negocio: s.negocio, contacto: s.contacto, whatsapp: telefonoWa(s.whatsapp), folios,
    periodo: { desde: ini, hasta: fin }, cifras: actual, anterior, acumulado: acum, nivel,
    rec: rec ? { id: rec.id, texto: rec.texto } : null,
  };
}

const SEG_SELECT = "s.venta_id, s.inicio, s.consentimiento_at, s.saludo_at, s.respondio_at, v.negocio, v.contacto, v.whatsapp";

async function resumenesDeHoy(env) {
  const um = await umbralesSeguimiento(env);
  const hoy = new Date(Date.now() - 6 * 3600 * 1000).toISOString().slice(0, 10);
  const { results: recs } = await env.DB.prepare("SELECT id, nivel, momento, texto, activa FROM seguimiento_recs").all();
  const { results: sinConsent } = await env.DB.prepare(
    `SELECT ${SEG_SELECT} FROM seguimientos s JOIN ventas v ON v.id = s.venta_id WHERE s.estado = 'activo' AND s.consentimiento_at IS NULL ORDER BY s.inicio LIMIT 100`
  ).all();
  const { results: saludos } = await env.DB.prepare(
    `SELECT ${SEG_SELECT} FROM seguimientos s JOIN ventas v ON v.id = s.venta_id WHERE s.estado = 'activo' AND s.consentimiento_at IS NOT NULL AND s.saludo_at IS NULL ORDER BY s.inicio LIMIT 100`
  ).all();
  const { results: debidos } = await env.DB.prepare(
    `SELECT ${SEG_SELECT}, e.numero, e.programado_para FROM seguimiento_envios e JOIN seguimientos s ON s.venta_id = e.venta_id JOIN ventas v ON v.id = e.venta_id
     WHERE e.estado = 'pendiente' AND e.programado_para <= ? AND s.estado = 'activo' AND s.consentimiento_at IS NOT NULL AND s.saludo_at IS NOT NULL
     ORDER BY e.programado_para, e.numero LIMIT 100`
  ).bind(hoy).all();
  const envios = [];
  for (const d of debidos) envios.push({ ...(await armarResumen(env, d, d, recs, um)), respondio: !!d.respondio_at });
  // Promedio de la red: solo se muestra cuando hay al menos 20 displays activos.
  let promedio = null;
  const act = await env.DB.prepare("SELECT COUNT(*) AS n FROM folios WHERE estado = 'activo'").first();
  if (Number(act.n) >= 20) {
    const t = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM escaneos e JOIN folios f ON f.folio = e.folio WHERE e.contado = 1 AND f.estado = 'activo' AND e.dia_mx BETWEEN ? AND ? AND e.created_at >= COALESCE(f.conteo_desde, '')"
    ).bind(sumarDias(hoy, -15), sumarDias(hoy, -1)).first();
    promedio = Math.round(Number(t.n) / Number(act.n));
  }
  const mapa = (s) => ({ venta_id: s.venta_id, negocio: s.negocio, contacto: s.contacto, whatsapp: telefonoWa(s.whatsapp), inicio: s.inicio });
  return json({ activo: um.activo, hoy, umbrales: { bajo: um.bajo, alto: um.alto }, promedio_red: promedio, envios, saludos: saludos.map(mapa), sin_consentimiento: sinConsent.map(mapa) });
}

async function accionSeguimiento(env, ventaId, accion, numero, usuario) {
  const s = await env.DB.prepare(
    `SELECT ${SEG_SELECT} FROM seguimientos s JOIN ventas v ON v.id = s.venta_id WHERE s.venta_id = ?`
  ).bind(ventaId).first();
  if (!s) return json({ error: "Esa venta no tiene seguimiento" }, 404);
  const aud = (txt) => env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `${txt} (venta ${ventaId})`);
  if (accion === "consentimiento") {
    await env.DB.batch([env.DB.prepare("UPDATE seguimientos SET consentimiento_at = COALESCE(consentimiento_at, CURRENT_TIMESTAMP) WHERE venta_id = ?").bind(ventaId), aud("Registró el consentimiento del seguimiento")]);
  } else if (accion === "saludo") {
    await env.DB.batch([env.DB.prepare("UPDATE seguimientos SET saludo_at = COALESCE(saludo_at, CURRENT_TIMESTAMP) WHERE venta_id = ?").bind(ventaId), aud("Marcó enviado el saludo del seguimiento")]);
  } else if (accion === "respondio") {
    await env.DB.batch([env.DB.prepare("UPDATE seguimientos SET respondio_at = COALESCE(respondio_at, CURRENT_TIMESTAMP) WHERE venta_id = ?").bind(ventaId), aud("Marcó que el cliente respondió al saludo")]);
  } else if (accion === "baja") {
    await env.DB.batch([
      env.DB.prepare("UPDATE seguimientos SET estado = 'baja', baja_at = CURRENT_TIMESTAMP WHERE venta_id = ? AND estado = 'activo'").bind(ventaId),
      env.DB.prepare("UPDATE seguimiento_envios SET estado = 'omitido' WHERE venta_id = ? AND estado = 'pendiente'").bind(ventaId),
      aud("Dio de baja el seguimiento"),
    ]);
  } else if (accion === "enviado" || accion === "omitir") {
    const e = await env.DB.prepare("SELECT numero, programado_para, estado FROM seguimiento_envios WHERE venta_id = ? AND numero = ?").bind(ventaId, numero).first();
    if (!e) return json({ error: "Ese envío no existe" }, 404);
    if (e.estado !== "pendiente") return json({ error: "Ese envío ya no está pendiente" }, 409);
    if (accion === "omitir") {
      await env.DB.batch([env.DB.prepare("UPDATE seguimiento_envios SET estado = 'omitido' WHERE venta_id = ? AND numero = ? AND estado = 'pendiente'").bind(ventaId, numero), aud(`Omitió el resumen ${numero}`)]);
    } else {
      // Se guardan las cifras y la recomendación del momento para no repetirlas y poder revisar qué se mandó.
      const um = await umbralesSeguimiento(env);
      const { results: recs } = await env.DB.prepare("SELECT id, nivel, momento, texto, activa FROM seguimiento_recs").all();
      const r = await armarResumen(env, s, e, recs, um);
      const datos = JSON.stringify({ rec_id: r.rec ? r.rec.id : null, total: r.cifras.total, anterior: r.anterior, acumulado: r.acumulado, periodo: r.periodo });
      const stmts = [
        env.DB.prepare("UPDATE seguimiento_envios SET estado = 'enviado', enviado_at = CURRENT_TIMESTAMP, nivel = ?, datos = ? WHERE venta_id = ? AND numero = ? AND estado = 'pendiente'").bind(r.nivel, datos, ventaId, numero),
        aud(`Marcó enviado el resumen ${numero}`),
      ];
      if (numero === 6) stmts.push(env.DB.prepare("UPDATE seguimientos SET estado = 'terminado' WHERE venta_id = ? AND estado = 'activo'").bind(ventaId));
      await env.DB.batch(stmts);
    }
  } else {
    return json({ error: "Acción no válida" }, 400);
  }
  return json({ success: true });
}

// Si la venta se anula o sus displays se recuperan, el seguimiento se detiene y los envíos pendientes se omiten.
function stmtsCancelarSeguimiento(env, ventaId) {
  return [
    env.DB.prepare("UPDATE seguimientos SET estado = 'cancelado' WHERE venta_id = ? AND estado = 'activo'").bind(ventaId),
    env.DB.prepare("UPDATE seguimiento_envios SET estado = 'omitido' WHERE venta_id = ? AND estado = 'pendiente'").bind(ventaId),
  ];
}

// Plan de anulación: devuelve { error } o { stmts } para ejecutar en un solo batch.
// Lo usan anularVenta y la aprobación de solicitudes de anulación.
async function planAnular(env, venta, usuario) {
  if (!["pendiente", "rev", "cobrada"].includes(venta.estado)) {
    return { error: json({ error: "Esta venta no se puede anular" }, 409) };
  }
  if (Number(venta.entregado) > 0) {
    return { error: json({ error: "La venta ya tiene entregas; no se puede anular" }, 409) };
  }

  const stmts = [
    env.DB.prepare("UPDATE ventas SET estado = 'anulada', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = ?").bind(venta.id, venta.estado),
  ];
  if (venta.estado === "cobrada") {
    const { results: activos } = await env.DB.prepare(
      "SELECT vf.folio, f.estado FROM venta_folios vf JOIN folios f ON f.folio = vf.folio WHERE vf.venta_id = ? AND f.estado IN ('activo','retirado')"
    ).bind(venta.id).all();
    for (const f of activos) {
      stmts.push(
        env.DB.prepare(
          "UPDATE folios SET estado = 'libre', negocio_asignado = NULL, url_destino = NULL, direccion = NULL, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado IN ('activo','retirado')"
        ).bind(f.folio)
      );
      stmts.push(
        env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, ?, 'libre', ?)").bind(f.folio, f.estado, usuario)
      );
    }
  }
  stmts.push(...stmtsCancelarSeguimiento(env, venta.id));
  stmts.push(env.DB.prepare("DELETE FROM venta_folios WHERE venta_id = ?").bind(venta.id));
  stmts.push(env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Anuló venta ${venta.id} (estado previo: ${venta.estado})`));
  return { stmts };
}

// Saldo del vendedor = lo que debe entregar de ventas cobradas o entregadas, menos lo ya entregado (monto + ajuste de cortes).
// Equivale a saldoVendedor(): cada corte se reparte completo entre esas ventas (FIFO).
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
  const plan = await planCorte(env, body, usuario);
  if (plan.error) return plan.error;
  await env.DB.batch(plan.stmts);
  return json({ success: true, id: plan.id, saldo_restante: plan.saldo_restante, subio_nivel: plan.subio }, 201);
}

// Plan de corte: devuelve { error } o { stmts, id, saldo_restante, subio } para ejecutar en un solo batch.
// Lo usan el corte manual del panel y la confirmación de avisos de entrega.
// Si un vendedor nuevo queda con saldo en cero, sube a confianza (su tope sube al de confianza).
async function planCorte(env, body, usuario) {
  const vendedor = typeof body.vendedor_id === "string" ? body.vendedor_id : null;
  const v = vendedor ? await env.DB.prepare("SELECT id, nivel FROM vendedores WHERE id = ?").bind(vendedor).first() : null;
  if (!v) return { error: json({ error: "Vendedor no válido" }, 400) };

  const monto = Number(body.monto);
  if (!Number.isFinite(monto) || monto <= 0) return { error: json({ error: "monto debe ser mayor que cero" }, 400) };
  const ajuste = body.ajuste === undefined ? 0 : Number(body.ajuste);
  if (!Number.isFinite(ajuste) || ajuste < 0) return { error: json({ error: "ajuste no válido" }, 400) };
  if (!METODOS.includes(body.metodo)) return { error: json({ error: "metodo no válido" }, 400) };
  const referencia = limpiarTexto(body.referencia, 100);
  if (body.metodo === "transferencia" && !referencia) return { error: json({ error: "La transferencia requiere referencia" }, 400) };

  const saldo = await saldoVendedor(env, vendedor);
  const pedido = Math.round((monto + ajuste) * 100) / 100;
  if (pedido > saldo + 0.001) return { error: json({ error: `El corte supera el saldo pendiente (${fmtMXN(saldo)})` }, 409) };

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
  for (const venta of abiertas) {
    if (resto <= 0.001) break;
    const pendiente = Math.round((venta.a_entregar - venta.entregado) * 100) / 100;
    const toma = Math.min(resto, pendiente);
    const nuevoEntregado = Math.round((venta.entregado + toma) * 100) / 100;
    const nuevoEstado = nuevoEntregado >= venta.a_entregar - 0.001 ? "entregada" : "cobrada";
    stmts.push(
      nuevoEstado === "entregada"
        ? env.DB.prepare("UPDATE ventas SET entregado = ?, estado = ?, entregada_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(nuevoEntregado, nuevoEstado, venta.id)
        : env.DB.prepare("UPDATE ventas SET entregado = ?, estado = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(nuevoEntregado, nuevoEstado, venta.id)
    );
    if (nuevoEstado === "entregada") {
      stmts.push(
        env.DB.prepare("INSERT OR IGNORE INTO envios (venta_id, tipo, destinatario, programado_para) VALUES (?, 'comprobante', 'vendedor', CURRENT_TIMESTAMP)").bind(venta.id)
      );
    }
    resto = Math.round((resto - toma) * 100) / 100;
  }
  if (resto > 0.001) return { error: json({ error: "No hay ventas suficientes para aplicar el corte" }, 409) };

  const saldoRestante = Math.round((saldo - pedido) * 100) / 100;
  stmts.push(
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Corte ${id} de ${vendedor}: ${monto} (ajuste ${ajuste})`)
  );
  const subio = v.nivel === "nuevo" && saldoRestante <= 0.001;
  if (subio) {
    stmts.push(
      env.DB.prepare("UPDATE vendedores SET nivel = 'confianza' WHERE id = ? AND nivel = 'nuevo'").bind(vendedor),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Vendedor ${vendedor} subió a confianza por entregar todo su saldo`)
    );
  }
  return { stmts, id, saldo_restante: saldoRestante, subio };
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
const TIPOS_SOLICITUD = ["reponer", "cambiar", "anular"];

async function listarSolicitudes(env) {
  const { results } = await env.DB.prepare("SELECT * FROM solicitudes ORDER BY created_at DESC").all();
  return json(results);
}

// Inicio del mes en hora de México (UTC-6 todo el año), en formato de created_at.
function inicioMesMX() {
  const mx = new Date(Date.now() - 6 * 3600000);
  return new Date(Date.UTC(mx.getUTCFullYear(), mx.getUTCMonth(), 1, 6)).toISOString().slice(0, 19).replace("T", " ");
}

async function crearSolicitud(request, env, usuario, vendedorSesion = null) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  if (!TIPOS_SOLICITUD.includes(body.tipo)) return json({ error: "tipo no válido" }, 400);
  const vendedor = vendedorSesion ? vendedorSesion.id : (typeof body.vendedor_id === "string" ? body.vendedor_id : null);
  if (!vendedor) return json({ error: "vendedor_id es obligatorio" }, 400);
  const motivo = limpiarTexto(body.motivo, 200);
  const nota = limpiarTexto(body.nota, 500);
  const fotoKey = limpiarTexto(body.foto_key, 300);

  if (body.tipo === "anular") {
    const ventaId = typeof body.venta_id === "string" ? body.venta_id : "";
    if (!/^VN-[0-9a-f]{8}$/.test(ventaId)) return json({ error: "venta_id no válido" }, 400);
    const venta = await env.DB.prepare("SELECT vendedor_id, estado, entregado FROM ventas WHERE id = ?").bind(ventaId).first();
    if (!venta) return json({ error: "Venta no encontrada" }, 404);
    if (venta.vendedor_id !== vendedor) return json({ error: "La venta no pertenece a ese vendedor" }, 409);
    if (!["pendiente", "rev", "cobrada"].includes(venta.estado) || Number(venta.entregado) > 0) {
      return json({ error: "Esta venta ya no se puede anular" }, 409);
    }
    const pend = await env.DB.prepare("SELECT id FROM solicitudes WHERE venta_id = ? AND tipo = 'anular' AND estado = 'pendiente'").bind(ventaId).first();
    if (pend) return json({ error: "Ya hay una solicitud de anulación pendiente para esa venta" }, 409);
    const id = "SO-" + crypto.randomUUID().slice(0, 8);
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO solicitudes (id, tipo, venta_id, vendedor_id, motivo, nota, foto_key) VALUES (?, 'anular', ?, ?, ?, ?, ?)"
      ).bind(id, ventaId, vendedor, motivo, nota, fotoKey),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Solicitud ${id} (anular venta ${ventaId})`),
    ]);
    return json({ success: true, id }, 201);
  }

  const folio = typeof body.folio === "string" ? body.folio.toUpperCase() : "";
  if (!FOLIO_RE.test(folio)) return json({ error: "Folio inválido" }, 400);
  const nuevoNegocio = limpiarTexto(body.nuevo_negocio, 200);
  if (body.tipo === "cambiar" && !nuevoNegocio) return json({ error: "nuevo_negocio es obligatorio para cambiar" }, 400);
  const urlResena = body.tipo === "cambiar" ? body.url_resena : null;
  if (body.tipo === "cambiar" && !esUrlResena(urlResena)) return json({ error: "url_resena debe ser una URL https de Google" }, 400);

  const d = await env.DB.prepare("SELECT estado, vendedor_id FROM folios WHERE folio = ?").bind(folio).first();
  if (!d) return json({ error: "Folio no encontrado" }, 404);
  if (d.vendedor_id !== vendedor) return json({ error: "El display no pertenece a ese vendedor" }, 409);
  if (d.estado !== "activo") return json({ error: "Solo se reponen o cambian displays activos" }, 409);
  const pendiente = await env.DB.prepare("SELECT id FROM solicitudes WHERE folio = ? AND estado = 'pendiente'").bind(folio).first();
  if (pendiente) return json({ error: "Ya hay una solicitud pendiente para ese display" }, 409);

  const id = "SO-" + crypto.randomUUID().slice(0, 8);
  const motivoLimpio = limpiarTexto(body.motivo, 200);
  const notaLimpia = limpiarTexto(body.nota, 500);
  const fotoLimpia = limpiarTexto(body.foto_key, 300);

  // Vendedor de confianza: el cambio de negocio se aplica directo; la reposición también, hasta lim_rep al mes
  // y si eligió el display nuevo. Pasado el límite, la reposición sigue como solicitud que aprueba Bien Visto.
  let limiteUsado = false;
  if (vendedorSesion) {
    const nv = await env.DB.prepare("SELECT nivel FROM vendedores WHERE id = ?").bind(vendedor).first();
    if (nv && nv.nivel === "confianza") {
      const registro = (estadoExtra) =>
        env.DB.prepare(
          "INSERT INTO solicitudes (id, tipo, folio, vendedor_id, motivo, nota, nuevo_negocio, url_resena, foto_key, estado, resuelto_por, resolved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'aprobada', 'directo', CURRENT_TIMESTAMP)"
        ).bind(id, body.tipo, folio, vendedor, motivoLimpio, notaLimpia, nuevoNegocio, urlResena, fotoLimpia);
      if (body.tipo === "cambiar") {
        await env.DB.batch([
          env.DB.prepare("UPDATE folios SET url_destino = ?, negocio_asignado = ?, conteo_desde = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'activo'").bind(urlResena, nuevoNegocio, folio),
          registro(),
          env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Cambio de negocio directo ${folio} → ${nuevoNegocio} (${id})`, folio),
        ]);
        return json({ success: true, id, estado: "aprobada", directo: true }, 201);
      }
      const nuevo = typeof body.folio_nuevo === "string" ? body.folio_nuevo.trim().toUpperCase() : "";
      if (body.tipo === "reponer" && nuevo) {
        const cfg = await leerConfig(env);
        const usadas = await env.DB.prepare(
          "SELECT COUNT(*) AS n FROM solicitudes WHERE vendedor_id = ? AND tipo = 'reponer' AND resuelto_por = 'directo' AND created_at >= ?"
        ).bind(vendedor, inicioMesMX()).first();
        if (Number(usadas.n) < Number(cfg.lim_rep)) {
          const viejo = await env.DB.prepare("SELECT folio, estado, vendedor_id, url_destino, negocio_asignado, direccion FROM folios WHERE folio = ?").bind(folio).first();
          const plan = await planReponer(env, { folio, vendedor_id: vendedor }, viejo, nuevo, usuario);
          if (plan.error) return plan.error;
          await env.DB.batch([
            ...plan.stmts,
            registro(),
            env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Reposición directa ${folio} → ${nuevo} (${id})`, nuevo),
          ]);
          return json({ success: true, id, estado: "aprobada", directo: true, folio_nuevo: nuevo, usadas: Number(usadas.n) + 1, limite: Number(cfg.lim_rep) }, 201);
        }
        limiteUsado = true;
      }
    }
  }

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO solicitudes (id, tipo, folio, vendedor_id, motivo, nota, nuevo_negocio, url_resena, foto_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(id, body.tipo, folio, vendedor, motivoLimpio, notaLimpia, nuevoNegocio, urlResena, fotoLimpia),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Solicitud ${id} (${body.tipo})`, folio),
  ]);
  return json({ success: true, id, estado: "pendiente", limite_usado: limiteUsado }, 201);
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
    const motivo = limpiarTexto(body.motivo, 200);
    if (!motivo || motivo.length < 5) return json({ error: "Escribe el motivo del rechazo (mínimo 5 caracteres)" }, 400);
    await env.DB.batch([
      env.DB.prepare("UPDATE solicitudes SET estado = 'rechazada', motivo_rechazo = ?, resuelto_por = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(motivo, usuario, id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Solicitud ${id} rechazada`, s.folio),
    ]);
    return json({ success: true, id, estado: "rechazada" });
  }
  if (body.accion !== "aprobar") return json({ error: "accion no válida" }, 400);

  if (s.tipo === "anular") {
    const venta = await env.DB.prepare("SELECT * FROM ventas WHERE id = ?").bind(s.venta_id).first();
    if (!venta) return json({ error: "Venta no encontrada" }, 404);
    // Misma regla que anular desde el panel: solo sin entregas. La anulación y el cierre de la solicitud van en un solo batch.
    const plan = await planAnular(env, venta, usuario);
    if (plan.error) return plan.error;
    await env.DB.batch([
      ...plan.stmts,
      env.DB.prepare("UPDATE solicitudes SET estado = 'aprobada', resuelto_por = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(usuario, id),
    ]);
    return json({ success: true, id, estado: "aprobada" });
  }

  const viejo = await env.DB.prepare("SELECT folio, estado, vendedor_id, url_destino, negocio_asignado, direccion FROM folios WHERE folio = ?").bind(s.folio).first();
  if (!viejo || viejo.estado !== "activo") return json({ error: "El display ya no está activo" }, 409);

  if (s.tipo === "reponer") {
    const nuevo = typeof body.folio_nuevo === "string" ? body.folio_nuevo.toUpperCase() : "";
    const plan = await planReponer(env, s, viejo, nuevo, usuario);
    if (plan.error) return plan.error;
    await env.DB.batch([
      ...plan.stmts,
      env.DB.prepare("UPDATE solicitudes SET estado = 'aprobada', resuelto_por = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(usuario, id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Reposición ${s.folio} → ${nuevo} (solicitud ${id})`, nuevo),
    ]);
    return json({ success: true, id, estado: "aprobada", folio_nuevo: nuevo });
  }

  // cambiar: la URL viene de la solicitud. Si la solicitud es anterior a la columna url_resena, se acepta la del admin.
  const url_resena = s.url_resena || body.url_resena;
  if (!esUrlResena(url_resena)) return json({ error: "La solicitud no tiene una URL https de Google válida" }, 400);
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE folios SET url_destino = ?, negocio_asignado = ?, conteo_desde = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'activo'"
    ).bind(url_resena, s.nuevo_negocio, s.folio),
    env.DB.prepare("UPDATE solicitudes SET estado = 'aprobada', resuelto_por = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(usuario, id),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, ?)").bind(usuario, `Cambio de negocio ${s.folio} → ${s.nuevo_negocio} (solicitud ${id})`, s.folio),
  ]);
  return json({ success: true, id, estado: "aprobada" });
}

// Reposición: el display activo se retira y un folio libre del mismo vendedor toma su lugar, con la misma URL y negocio.
// Devuelve { error } o { stmts }. Lo usan la aprobación del admin y la reposición directa de un vendedor de confianza.
async function planReponer(env, s, viejo, nuevo, usuario) {
  if (!FOLIO_RE.test(nuevo) || nuevo === s.folio) return { error: json({ error: "folio_nuevo no válido" }, 400) };
  if (!viejo.url_destino) return { error: json({ error: "El display a reponer no tiene URL de reseña" }, 409) };

  const f = await env.DB.prepare("SELECT estado, vendedor_id FROM folios WHERE folio = ?").bind(nuevo).first();
  if (!f) return { error: json({ error: "folio_nuevo no existe" }, 404) };
  if (f.estado !== "libre" || f.vendedor_id !== s.vendedor_id) {
    return { error: json({ error: "El display nuevo debe estar libre y asignado al mismo vendedor" }, 409) };
  }
  const enVenta = await env.DB.prepare("SELECT venta_id FROM venta_folios WHERE folio = ?").bind(nuevo).first();
  if (enVenta) return { error: json({ error: "El display nuevo ya está en una venta" }, 409) };

  return {
    stmts: [
      env.DB.prepare("UPDATE folios SET estado = 'retirado', updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'activo'").bind(s.folio),
      env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'activo', 'retirado', ?)").bind(s.folio, usuario),
      env.DB.prepare(
        "UPDATE folios SET estado = 'activo', url_destino = ?, negocio_asignado = ?, direccion = ?, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'libre'"
      ).bind(viejo.url_destino, viejo.negocio_asignado, viejo.direccion || null, nuevo),
      env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'libre', 'activo', ?)").bind(nuevo, usuario),
      env.DB.prepare("UPDATE venta_folios SET folio = ? WHERE folio = ?").bind(nuevo, s.folio),
    ],
  };
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

  // Un display de una venta ya cobrada o entregada no cambia de estado a mano: el dinero
  // de esa venta sigue vigente. Para liberarlo hay que anular la venta (revierte displays y deuda).
  if (nuevoEstado !== actual.estado) {
    const enVenta = await env.DB.prepare(
      "SELECT v.id FROM venta_folios vf JOIN ventas v ON v.id = vf.venta_id WHERE vf.folio = ? AND v.estado IN ('cobrada', 'entregada') LIMIT 1"
    ).bind(folio).first();
    if (enVenta) {
      return json({ error: `El display está en la venta ${enVenta.id}, ya cobrada o entregada. Anula la venta primero para cambiar su estado.` }, 409);
    }
  }

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
// Agentes que no son una persona escaneando: robots, vistas previas de mensajería, herramientas de línea de comandos.
const BOT_RE = /bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|slack|discord|skype|linkedin|twitter|curl|wget|python|java\/|go-http|okhttp|axios|node-fetch|headless|lighthouse|monitor|uptime|pingdom|google-read-aloud|bingpreview/i;

async function hashHex(texto) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(texto));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

function tipoDispositivo(ua) {
  if (/iphone|ipad|ipod/i.test(ua)) return "ios";
  if (/android/i.test(ua)) return "android";
  if (/windows|macintosh|linux|cros/i.test(ua)) return "escritorio";
  return "otro";
}

// Guarda cada visita con su detalle y decide si cuenta: solo displays activos, personas (no robots),
// y una vez por día por dispositivo. La IP nunca se guarda; solo un hash que cambia cada día.
async function registrarEscaneo(env, request, url, folio, estado) {
  const ua = request.headers.get("User-Agent") || "";
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const cf = request.cf || {};
  const dia = new Date(Date.now() - 6 * 3600 * 1000).toISOString().slice(0, 10);
  const esBot = !ua || BOT_RE.test(ua) ? 1 : 0;
  const huella = await hashHex(`${env.HUELLA_SALT || "bv"}|${dia}|${folio}|${ip}|${ua}`);

  let motivo = null;
  if (esBot) motivo = "bot";
  else if (estado === "prueba") motivo = "prueba";
  else if (estado !== "activo") motivo = "no_activo";
  else {
    const previo = await env.DB.prepare(
      "SELECT 1 AS x FROM escaneos WHERE folio = ? AND dia_mx = ? AND huella = ? AND contado = 1 LIMIT 1"
    ).bind(folio, dia, huella).first();
    if (previo) motivo = "repetido";
  }

  await env.DB.prepare(
    "INSERT INTO escaneos (folio, dia_mx, huella, origen, dispositivo, pais, region, ciudad, estado_display, es_bot, contado, motivo_no) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    folio, dia, huella, url.searchParams.get("q") === "1" ? "qr" : "nfc", tipoDispositivo(ua),
    cf.country || null, cf.region || null, cf.city || null, estado, esBot, motivo ? 0 : 1, motivo
  ).run();
}

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

  if (request.method === "GET") {
    try {
      await registrarEscaneo(env, request, url, folio, display.estado);
    } catch (err) {
      console.error("escaneo no registrado", err);
    }
  }

  // 'activo' o 'prueba' (ya vencimos las pruebas caducas) con reseña válida redirige.
  if ((display.estado === "activo" || display.estado === "prueba") && esUrlResena(display.url_destino)) {
    return Response.redirect(display.url_destino, 302);
  }
  // Libre: landing de Bien Visto.
  if (display.estado === "libre") {
    return new Response(request.method === "HEAD" ? null : paginaLibre(folio), {
      status: 200,
      headers: { "Content-Type": "text/html;charset=UTF-8", "X-Robots-Tag": "noindex" },
    });
  }

  // Quien escanea es cliente del negocio: no se le dice si el display está en pausa, retirado o con adeudo.
  const html = `<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="robots" content="noindex"><title>Display no disponible</title><style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#f5f5f5;margin:0;}div{background:#fff;padding:40px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.1);text-align:center;}</style></head>
<body><div><h2>Este display no está disponible por ahora</h2><p>Gracias por querer dejar tu opinión. Puedes buscar el negocio en Google Maps para dejar tu reseña.</p><p style="font-size:13px;opacity:.7">Folio ${esc(folio)}</p></div></body>
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
const PERMISOS = [
  "ver_resumen", "ver_inventario", "ver_vendedores", "ver_cobros", "ver_historial", "ver_vista_vendedor",
  "inventario_registrar", "inventario_editar",
  "vendedores_gestionar", "solicitudes_resolver",
  "cobros_confirmar", "ventas_anular", "cortes_cerrar",
  "precios_venta", "costos_impuestos", "reglas_vendedores",
  "accesos",
];

// Qué campos de configuración pertenecen a cada permiso. Lo que no esté aquí cae en reglas_vendedores.
const GRUPO_CONFIG = {
  precio_display: "precios_venta", comision_display: "precios_venta", promo_n: "precios_venta", promo_precio: "precios_venta",
  costo_produccion: "costos_impuestos", isr_tasa: "costos_impuestos", iva_tasa: "costos_impuestos",
};

// Permisos que exige cada petición. "todos": cada uno obligatorio. "alguno": basta con uno.
// Lo que no aparece exige "accesos" (solo dueño), para que una ruta nueva quede cerrada por defecto.
async function permisosRequeridos(request, env, url, method, path) {
  const sin = (todos, alguno = []) => ({ todos, alguno });
  if (method === "GET") {
    if (path === "/api/escaneos/serie" || path === "/api/pruebas/resumen") return sin(["ver_resumen"]);
    if (path === "/api/seguimiento/hoy") return sin(["ver_cobros"]);
    if (path === "/api/displays" || path === "/api/lotes") return sin(["ver_inventario"]);
    if (path === "/api/vendedores" || path === "/api/solicitudes" || path === "/api/cuentas-cobro" || path === "/api/altas-vendedor") return sin(["ver_vendedores"]);
    if (path === "/api/ventas" || path === "/api/cortes" || path === "/api/avisos-entrega" || path === "/api/precios" || /^\/api\/ventas\/[^/]+\/comprobante$/.test(path) || /^\/api\/avisos-entrega\/[^/]+\/comprobante$/.test(path)) return sin(["ver_cobros"]);
    // Ajustes y Precios necesitan la configuración; cada sección se revisa en la UI y el PATCH se revisa por campo.
    if (path === "/api/config") return sin([], ["precios_venta", "costos_impuestos", "reglas_vendedores", "ver_cobros"]);
    if (path === "/api/auditoria" || path === "/api/auditoria/csv") return sin(["ver_historial"]);
    if (path === "/api/admin/app-vendedor" || path.startsWith("/api/admin/vista/")) return sin(["ver_vista_vendedor"]);
    if (path === "/api/admin/documentacion") return sin(["accesos"]);
    return sin(["accesos"]);
  }

  const cuerpo = async () => (await request.clone().json().catch(() => ({}))) || {};

  if (path === "/api/config" && method === "PATCH") {
    const b = await cuerpo();
    const grupos = new Set();
    for (const k of Object.keys(b)) {
      if (k === "nota") continue;
      grupos.add(GRUPO_CONFIG[k] || "reglas_vendedores");
    }
    return sin([...grupos]);
  }
  if (path === "/api/cortes" && method === "POST") return sin(["cortes_cerrar"]);
  if (path === "/api/displays/alta" || path === "/api/displays/batch" || path === "/api/lotes") return sin(["inventario_registrar"]);
  if (path === "/api/displays/asignar" || path.startsWith("/api/displays/") || path.startsWith("/api/lotes/")) return sin(["inventario_editar"]);
  if (path.startsWith("/api/vendedores")) return sin(["vendedores_gestionar"]);
  if (path.startsWith("/api/altas-vendedor/")) return sin(["vendedores_gestionar"]);
  if (path.startsWith("/api/cuentas-cobro/")) return sin(["solicitudes_resolver"]);
  if (path.startsWith("/api/solicitudes/") && method === "PATCH") {
    const b = await cuerpo();
    const id = decodeURIComponent(path.slice("/api/solicitudes/".length));
    const req = ["solicitudes_resolver"];
    if (b.accion === "aprobar") {
      const s = await env.DB.prepare("SELECT tipo FROM solicitudes WHERE id = ?").bind(id).first();
      if (s && s.tipo === "anular") req.push("ventas_anular");
    }
    return sin(req);
  }
  if (path === "/api/solicitudes") return sin(["solicitudes_resolver"]);
  if (path.startsWith("/api/ventas/") && method === "PATCH") {
    const b = await cuerpo();
    return sin([b.accion === "anular" || b.accion === "recuperar" ? "ventas_anular" : "cobros_confirmar"]);
  }
  if (path === "/api/ventas" && method === "POST") return sin(["cobros_confirmar"]);
  if (/^\/api\/ventas\/[^/]+\/comprobante$/.test(path) && method === "POST") return sin(["cobros_confirmar"]);
  if (path.startsWith("/api/avisos-entrega")) return sin(["cobros_confirmar"]);
  if (path.startsWith("/api/seguimiento/")) return sin(["cobros_confirmar"]);
  return sin(["accesos"]);
}

// Dos tipos: "dueno" tiene todos los permisos; "asociado" tiene solo los que le asignó el dueño (nunca "accesos").
const PERMISOS_ASIGNABLES = PERMISOS.filter((p) => p !== "accesos");

async function cargarAdmin(env, correo) {
  const r = await env.DB.prepare("SELECT correo, nombre, tipo, activo, permisos FROM admins WHERE correo = ?").bind(correo.toLowerCase()).first();
  if (!r || !r.activo) return null;
  if (r.tipo === "dueno") return { correo: r.correo, nombre: r.nombre, tipo: "dueno", permisos: [...PERMISOS] };
  let asignados = [];
  try { asignados = JSON.parse(r.permisos || "[]"); } catch { asignados = []; }
  return { correo: r.correo, nombre: r.nombre, tipo: "asociado", permisos: asignados.filter((p) => PERMISOS_ASIGNABLES.includes(p)) };
}

function validarPermisosAsociado(lista) {
  return Array.isArray(lista) && lista.every((p) => PERMISOS_ASIGNABLES.includes(p));
}

// ¿Queda alguien activo como dueño, aparte de "excluir"?
async function quedaOtroDueno(env, excluir) {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM admins WHERE tipo = 'dueno' AND activo = 1 AND correo <> ?").bind(excluir).first();
  return !!r && r.n > 0;
}

async function rutasAccesos(request, env, url, usuario, admin) {
  const path = url.pathname;
  const method = request.method;
  if (!admin.permisos.includes("accesos")) return json({ error: "Tu perfil no permite esta acción" }, 403);

  if (path === "/api/admin/accesos" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT correo, nombre, tipo, activo, permisos FROM admins ORDER BY tipo, nombre").all();
    return json(results.map((a) => ({ correo: a.correo, nombre: a.nombre, tipo: a.tipo, activo: a.activo, permisos: a.tipo === "dueno" ? [...PERMISOS] : JSON.parse(a.permisos || "[]") })));
  }

  if (path === "/api/admin/accesos" && method === "POST") {
    const body = await leerJson(request);
    if (body === null) return json({ error: "JSON inválido" }, 400);
    const correo = typeof body.correo === "string" ? body.correo.trim().toLowerCase() : "";
    const nombre = typeof body.nombre === "string" ? body.nombre.trim().slice(0, 60) : "";
    const permisos = Array.isArray(body.permisos) ? body.permisos : [];
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(correo)) return json({ error: "Correo no válido" }, 400);
    if (!nombre) return json({ error: "Escribe el nombre" }, 400);
    if (!validarPermisosAsociado(permisos)) return json({ error: "Permiso no válido para un asociado" }, 400);
    const ya = await env.DB.prepare("SELECT correo FROM admins WHERE correo = ?").bind(correo).first();
    if (ya) return json({ error: "Ese correo ya tiene acceso" }, 409);
    const unicos = [...new Set(permisos)];
    await env.DB.batch([
      env.DB.prepare("INSERT INTO admins (correo, nombre, perfil, tipo, permisos, activo, updated_by) VALUES (?, ?, 'asociado', 'asociado', ?, 1, ?)").bind(correo, nombre, JSON.stringify(unicos), usuario),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Acceso nuevo: ${correo} (asociado: ${unicos.join(", ") || "sin permisos"})`),
    ]);
    return json({ correo, nombre, tipo: "asociado", activo: 1, permisos: unicos }, 201);
  }

  const acceso = path.match(/^\/api\/admin\/accesos\/([^/]+)$/);
  if (acceso && method === "PATCH") {
    const correo = decodeURIComponent(acceso[1]).toLowerCase();
    const body = await leerJson(request);
    if (body === null) return json({ error: "JSON inválido" }, 400);
    const actual = await env.DB.prepare("SELECT correo, nombre, tipo, activo, permisos FROM admins WHERE correo = ?").bind(correo).first();
    if (!actual) return json({ error: "Acceso no encontrado" }, 404);
    const nombre = typeof body.nombre === "string" && body.nombre.trim() ? body.nombre.trim().slice(0, 60) : actual.nombre;
    const activo = body.activo === undefined ? actual.activo : body.activo ? 1 : 0;
    let permisos = JSON.parse(actual.permisos || "[]");
    if (actual.tipo === "asociado" && Array.isArray(body.permisos)) {
      if (!validarPermisosAsociado(body.permisos)) return json({ error: "Permiso no válido para un asociado" }, 400);
      permisos = [...new Set(body.permisos)];
    }
    if (actual.tipo === "dueno" && actual.activo === 1 && activo === 0 && !(await quedaOtroDueno(env, correo))) {
      return json({ error: "Debe quedar al menos otro dueño activo" }, 400);
    }
    await env.DB.batch([
      env.DB.prepare("UPDATE admins SET nombre = ?, activo = ?, permisos = ?, updated_by = ? WHERE correo = ?").bind(nombre, activo, JSON.stringify(permisos), usuario, correo),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Acceso ${correo}: ${activo ? "activo" : "inactivo"}, permisos = ${permisos.join(", ") || "ninguno"}`),
    ]);
    return json({ correo, nombre, tipo: actual.tipo, activo, permisos: actual.tipo === "dueno" ? [...PERMISOS] : permisos });
  }

  return json({ error: "No encontrado" }, 404);
}

// ==========================================
// DOCUMENTACIÓN DESCARGABLE (Ajustes > Documentación del sistema)
// La narrativa es fija y vive aquí. Las secciones "En vivo" se leen de D1 y de la configuración en cada descarga.
// Nunca incluye: claves o secretos, datos bancarios de Bien Visto, correos de personas ni datos de vendedores.
// ==========================================
const DOC_CONFIG_DESC = {
  precio_display: "Precio de un display para el negocio (MXN).",
  comision_display: "Comisión del vendedor por cada display vendido (MXN).",
  promo_n: "Cantidad de displays que entran en la promoción.",
  promo_precio: "Precio de la promoción completa (promo_n displays).",
  prueba_minutos: "Minutos que dura una prueba de display antes de volver a libre (entre 5 y 120).",
  tope_nuevo: "Exposición máxima de un vendedor nuevo: saldo pendiente más ventas en revisión (MXN).",
  tope_confianza: "Exposición máxima de un vendedor de confianza (MXN). Nunca menor que tope_nuevo.",
  horas: "Horas que tiene el vendedor para entregar el saldo de su venta cobrada más antigua. Si vence, no puede activar displays nuevos.",
  recibo_min: "Minutos entre el cobro y el correo de recibo al cliente. El envío corre cada minuto, así que en la práctica sale entre ese tiempo y 1 minuto después.",
  lim_rep: "Reposiciones directas al mes para vendedores de confianza. Con 0, todas pasan como solicitud al panel.",
  bonos_on: "Interno. 1 = bonos activos, 0 = apagados.",
  dias_bono: "Interno. Días de la ventana de bonos. El código no lo describe más: confirmar con el dueño.",
  bono1_n: "Interno. Meta 1 de bono (cantidad entera). Debe ser menor que bono2_n.",
  bono1_b: "Interno. Bono 1 (MXN). Debe ser menor o igual que bono2_b.",
  bono2_n: "Interno. Meta 2 de bono (cantidad entera).",
  bono2_b: "Interno. Bono 2 (MXN).",
  bono3_n: "Interno. Meta 3 de bono (cantidad entera).",
  bono3_b: "Interno. Bono 3 (MXN).",
  lead_d: "Interno. El código no lo describe: confirmar con el dueño.",
  colch: "Interno. El código no lo describe: confirmar con el dueño.",
  parado_d: "Interno. El código no lo describe: confirmar con el dueño.",
  esc_bajo: "Interno. El código no lo describe: confirmar con el dueño.",
};

const DOC_PERMISOS_DESC = {
  ver_resumen: "Ver el resumen, las pruebas y la serie de escaneos.",
  ver_inventario: "Ver displays y lotes.",
  ver_vendedores: "Ver vendedores, solicitudes y cuentas de cobro.",
  ver_cobros: "Ver ventas, cortes, avisos de entrega y precios.",
  ver_historial: "Ver el historial y descargarlo en CSV.",
  ver_vista_vendedor: "Ver la vista previa de la app de vendedores (solo lectura).",
  inventario_registrar: "Dar de alta lotes y displays.",
  inventario_editar: "Editar lotes y displays, y asignarlos a vendedores.",
  vendedores_gestionar: "Dar de alta y editar vendedores.",
  solicitudes_resolver: "Aprobar o rechazar solicitudes y cuentas de cobro.",
  cobros_confirmar: "Registrar y confirmar cobros, y confirmar avisos de entrega.",
  ventas_anular: "Anular ventas, y aprobar solicitudes de anulación.",
  cortes_cerrar: "Registrar cortes (entregas del vendedor a Bien Visto).",
  precios_venta: "Precio, comisión y promoción.",
  costos_impuestos: "Costo de producción, ISR e IVA.",
  reglas_vendedores: "Topes, plazos, pruebas, reposiciones y bonos.",
  accesos: "Gestionar accesos del panel y datos de pago. Solo el dueño.",
};

const DOC_CLAVES_OCULTAS = /clabe|titular|cuenta|token|secret|key|pass|correo|email/i;

async function consultaSegura(env, sql) {
  try {
    const { results } = await env.DB.prepare(sql).all();
    return results || [];
  } catch (err) {
    console.error("documentación: consulta fallida", err);
    return null;
  }
}

async function documentacionAdmin(env, usuario) {
  const md = await generarDocumentacion(env);
  await env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, "Descargó la documentación del sistema").run();
  const nombre = "bienvisto-documentacion-" + new Date().toISOString().slice(0, 10) + ".md";
  return new Response(md, {
    headers: {
      "content-type": "text/markdown; charset=utf-8",
      "content-disposition": `attachment; filename="${nombre}"`,
      "cache-control": "no-store",
    },
  });
}

export async function generarDocumentacion(env) {
  const [cfgFilas, esquema, folios, vendedores, ventas, saldo, pendientes, admins, precios, auditoriaN, cfgAdmin] = await Promise.all([
    consultaSegura(env, "SELECT clave, valor, updated_at FROM config ORDER BY clave"),
    consultaSegura(env, "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name NOT LIKE 'd1_%' ORDER BY name"),
    consultaSegura(env, "SELECT estado, COUNT(*) AS n FROM folios GROUP BY estado ORDER BY estado"),
    consultaSegura(env, "SELECT estado, nivel, COUNT(*) AS n FROM vendedores GROUP BY estado, nivel ORDER BY estado, nivel"),
    consultaSegura(env, "SELECT estado, COUNT(*) AS n FROM ventas GROUP BY estado ORDER BY estado"),
    consultaSegura(env, "SELECT COALESCE(SUM(a_entregar - COALESCE(entregado, 0)), 0) AS monto FROM ventas WHERE estado IN ('cobrada','entregada') AND a_entregar - COALESCE(entregado, 0) > 0.001"),
    consultaSegura(env, "SELECT 'Solicitudes pendientes' AS que, COUNT(*) AS n FROM solicitudes WHERE estado = 'pendiente' UNION ALL SELECT 'Cuentas de cobro pendientes de revisión', COUNT(*) FROM cuentas_cobro WHERE estado = 'pendiente' UNION ALL SELECT 'Avisos de entrega pendientes', COUNT(*) FROM avisos_entrega WHERE estado = 'pendiente' UNION ALL SELECT 'Ventas con impago abierto', COUNT(*) FROM ventas WHERE impago = 1 AND estado <> 'anulada' UNION ALL SELECT 'Correos sin enviar (sin_correo)', COUNT(*) FROM envios WHERE estado = 'sin_correo' UNION ALL SELECT 'Correos en cola', COUNT(*) FROM envios WHERE estado = 'pendiente'"),
    consultaSegura(env, "SELECT tipo, activo, COUNT(*) AS n FROM admins GROUP BY tipo, activo ORDER BY tipo, activo"),
    consultaSegura(env, "SELECT fecha, precio, comision, promo_n, promo_precio, nota FROM precios_historial ORDER BY id DESC LIMIT 10"),
    consultaSegura(env, "SELECT COUNT(*) AS n FROM auditoria"),
    leerConfigAdmin(env).catch(() => null),
  ]);
  const ahora = new Date().toLocaleString("es-MX", { timeZone: "America/Mexico_City", dateStyle: "long", timeStyle: "short" });
  const L = [];
  const add = (...xs) => L.push(...xs);
  const cuenta = (filas, etiqueta) => (filas === null
    ? ["- No disponible: la consulta falló al generar este archivo."]
    : filas.length === 0 ? ["- Sin registros."] : filas.map((f) => "- " + etiqueta(f)));
  const fmt = (n) => new Intl.NumberFormat("es-MX", { style: "currency", currency: "MXN" }).format(Number(n) || 0);

  // ---------- Portada ----------
  add("# Bien Visto: documentación del sistema", "");
  add("Generado: " + ahora + " (hora de Ciudad de México).", "");
  add("Este archivo se arma en el momento en que lo descargas. Las secciones marcadas **En vivo** salen de la base de datos y de Ajustes en ese instante. El resto describe cómo funciona el sistema y se revisa cuando cambia el código.", "");
  add("Qué no incluye: contraseñas, claves de API, secretos, datos bancarios de Bien Visto, correos de personas, ni datos de vendedores o clientes.", "");

  add("## Índice", "");
  add("1. Qué es Bien Visto", "2. Actores y modelo de dinero", "3. Ciclo de un display y de una venta", "4. Reglas de negocio y valores actuales (En vivo)", "5. Costos e impuestos (En vivo)", "6. Interfaces", "7. Permisos del panel", "8. Infraestructura y servicios", "9. Esquema de la base de datos (En vivo)", "10. Estado operativo ahora (En vivo)", "11. Historial reciente de precios (En vivo)", "12. Cómo operar y modificar el sistema", "13. Puntos a vigilar", "");

  // ---------- 1 ----------
  add("## 1. Qué es Bien Visto", "");
  add("Bien Visto vende displays con chip NFC y código QR para que los negocios consigan reseñas en Google. Cada display tiene un folio (cuatro caracteres, por ejemplo A2B3) y está ligado a la página de reseña de un negocio. Quien pasa por el display toca el chip o escanea el QR y llega directo a esa página. Si el display cambia de negocio, cambia el destino, no el display físico.", "");
  add("Los displays los vende una red de vendedores. El vendedor consigue al negocio, activa el display, cobra y entrega a Bien Visto la parte que le corresponde. El panel de administración lo lleva el dueño con su equipo de asociados.", "");

  // ---------- 2 ----------
  add("## 2. Actores y modelo de dinero", "");
  add("- **Dueño**: tiene todos los permisos. Puede dar accesos a asociados y cambiar datos de pago.", "- **Asociados**: personas con permisos que el dueño les asigna. Nunca tienen el permiso de accesos.", "- **Vendedores**: independientes. Tienen nivel **nuevo** o **confianza**. Usan su propia app.", "- **Negocios**: reciben el display y el servicio. Pagan la venta.", "");
  add("Cómo se calcula una venta de n displays:", "");
  add("- Total = (número de promociones completas × promo_precio) + (displays sueltos × precio_display). Una promoción completa son promo_n displays.", "- Comisión del vendedor = n × comision_display.", "- A entregar a Bien Visto = Total − Comisión. Es lo que el vendedor debe entregar.", "");
  add("Ejemplo con los valores de referencia del diseño (precio 350, comisión 150, promoción de 3 por 900): un display suelto deja al vendedor 150 y entrega 200; tres displays en promoción dejan al vendedor 450 y entrega 450. Los valores vigentes están en la sección 4.", "");
  add("Cómo fluye el dinero:", "");
  add("1. El negocio paga la venta al vendedor en efectivo o por transferencia. Si es transferencia, paga a la **cuenta de cobro vigente** del vendedor, que él registró en su app. La página pública `/pago/VN-xxxxxxxx` muestra esos datos al cliente.", "2. El vendedor confirma el cobro en su app con el enlace de reseña de Google y, si lo tiene, la clave de rastreo. Eso activa los displays. Un vendedor también puede avisar que ya cobró; entonces la venta queda en revisión hasta que el panel la cobre.", "3. El vendedor entrega a Bien Visto su saldo. Hay dos caminos: el **corte** que registra el panel (efectivo o transferencia) o un **aviso de entrega** con comprobante que el panel confirma (se convierte en corte) o rechaza con un motivo.", "4. Un corte se aplica por orden de antigüedad, FIFO, a las ventas con saldo pendiente. Cuando una venta queda cubierta por completo, pasa a **entregada**.", "5. Un **ajuste** en un corte descuenta saldo sin movimiento de dinero, por ejemplo una anulación que ya se había cobrado. No puede hacer que el saldo quede por debajo de cero.", "");
  add("Reglas de exposición y plazo:", "");
  add("- **Tope**: la exposición del vendedor es su saldo pendiente más las ventas en revisión. Ninguna venta nueva puede hacer que la exposición pase del tope de su nivel (tope_nuevo o tope_confianza).", "- **Plazo**: si la venta cobrada más antigua con saldo pendiente tiene más de `horas` desde el cobro, el vendedor no puede activar displays nuevos hasta entregar.", "- **Impago**: una venta marcada como impago bloquea activar displays nuevos y hacer pruebas, hasta que se resuelva.", "- **Pruebas**: un vendedor tiene máximo 2 pruebas a la vez (cada una dura prueba_minutos). Al día puede hacer 15 si es nuevo y 50 si es de confianza.", "- **Ascenso**: un vendedor nuevo que deja su saldo en cero pasa a confianza.","");

  // ---------- 3 ----------
  add("## 3. Ciclo de un display y de una venta", "");
  add("**Estados de un display (folio)**", "");
  add("- `libre`: en inventario. Puede estar asignado a un vendedor o no.", "- `prueba`: probando un negocio durante prueba_minutos. Al vencer, vuelve a `libre`.", "- `activo`: vendido y cobrado. Su enlace apunta al negocio.", "- `retirado`: fuera de servicio. Ocurre al recuperar los displays de una venta cobrada, o al reponer uno.", "- `pausa` y `adeudo`: están declarados en el código (lista ESTADOS), pero ningún flujo los asigna. Si se van a usar, hay que definir sus transiciones.", "");
  add("Las pruebas se liberan de forma perezosa: el sistema revisa las pruebas vencidas cuando llega una petición que las necesita. No hay un temporizador que las cierre en el momento exacto.", "");
  add("**Estados de una venta**", "");
  add("- `pendiente`: creada. Los displays están reservados para ella.", "- `rev`: el vendedor avisó que ya cobró y el panel debe revisarla.", "- `cobrada`: cobro confirmado. Los displays están activos. Se programa el recibo al cliente.", "- `entregada`: su saldo a entregar quedó cubierto por cortes.", "- `anulada`: cancelada. Anular una venta cobrada devuelve sus displays a `libre`.", "- `rechazada`: la página de pago la contempla, pero ningún flujo la asigna a una venta.", "");
  add("**Otros estados**", "");
  add("- Solicitudes (reponer, cambiar, anular): `pendiente` → `aprobada` o `rechazada`.", "- Cuentas de cobro: `pendiente` → `vigente` (aprobada, reemplaza a la anterior, que queda `sustituida`) o `rechazada`. Una `pendiente` puede `cancelarse`.", "- Avisos de entrega: `pendiente` → `confirmado` (crea un corte) o `rechazado`. `confirmando` es un estado transitorio durante la confirmación.", "- Envíos (correos): `pendiente` → `enviado` o `sin_correo` si fallan. Se reintentan hasta 5 veces.", "- Solicitudes de alta de vendedor (formulario del sitio): `pendiente` → `aprobada` (crea al vendedor en nivel nuevo) o `rechazada`.", "- Vendedores: `activo` o `inactivo`. Un vendedor inactivo con ventas abiertas no se puede desactivar.", "");
  add("**Reposiciones y cambios**", "");
  add("Un vendedor de confianza cambia el negocio de un display directo, sin aprobación. También repone directo hasta lim_rep veces al mes. Lo demás pasa como solicitud que el panel aprueba o rechaza.", "");

  // ---------- 4 ----------
  add("## 4. Reglas de negocio y valores actuales (En vivo)", "");
  add("Valores guardados en este momento. Se cambian en Ajustes del panel. El sitio público y la app de vendedores los leen de ahí.", "");
  add("Restricciones que el sistema exige al guardar:", "");
  add("- La comisión no puede ser mayor que el precio del display.", "- La promoción no puede costar más que comprar esos displays por separado.", "- Comisión × promo_n no puede ser mayor que promo_precio. Si no, el vendedor ganaría más de lo que paga el cliente.", "- promo_n es un entero de 2 o más. prueba_minutos está entre 5 y 120.", "- tope_nuevo no puede ser mayor que tope_confianza.", "- Las metas de bono van de menor a mayor, y los bonos también.", "");
  add("Configuración guardada (sin claves ni datos bancarios):", "");
  add(...(cfgFilas === null
    ? ["- No disponible: la consulta falló al generar este archivo."]
    : cfgFilas
        .filter((r) => !DOC_CLAVES_OCULTAS.test(r.clave))
        .map((r) => "- `" + r.clave + "` = " + r.valor + ". " + (DOC_CONFIG_DESC[r.clave] || "Sin descripción en el código."))));
  add("");

  // ---------- 5 ----------
  add("## 5. Costos e impuestos (En vivo)", "");
  if (cfgAdmin) {
    add("- Costo de producción por display: " + (cfgAdmin.costo_produccion === null || cfgAdmin.costo_produccion === undefined ? "sin capturar. El panel usa el promedio de los lotes." : fmt(cfgAdmin.costo_produccion)) + ".");
    add("- Tasa de ISR aplicada en la tabla de costos: " + cfgAdmin.isr_tasa + "%. Valores permitidos: 1, 1.1, 1.5, 2 y 2.5.");
    add("- Tasa de IVA: " + cfgAdmin.iva_tasa + "%. Va de 0 a 30. Se usa en el panel y en el recibo.");
  } else {
    add("- No disponible: la consulta falló al generar este archivo.");
  }
  add("");
  add("El costo de producción se captura al registrar displays y en Ajustes. La tabla de costos del panel usa estos valores para calcular costo e impuestos.", "");

  // ---------- 6 ----------
  add("## 6. Interfaces", "");
  add("**Panel de administración** (admini.bienvisto.com.mx)", "");
  add("- Entra con Google a través de Cloudflare Access. Solo entra quien tiene un registro activo en la tabla de administradores. Si no lo tiene, la API responde 403.", "- Secciones: Resumen, Vendedores, Displays, Inventario, Registrar, Clientes, Cobros, Ajustes, Historial, y Permisos (solo dueño). Cada una aparece según los permisos de la persona.", "- Ajustes: precios, costos e impuestos, reglas de vendedores, datos de pago (solo dueño), esta documentación, y la lectura de textos de la app de vendedor.", "- Botón Cerrar sesión: cierra la sesión de Access. No cierra la sesión de Google en el navegador.", "");
  add("**App de vendedores** (vendedores.bienvisto.com.mx)", "");
  add("- Entrada con un código de 6 dígitos que llega por correo (vence en 10 minutos; máximo 5 códigos y 10 fallos por día) o con Google, si el correo del vendedor está registrado.", "- La sesión dura 30 días desde que inicia. No se renueva por uso. Se guarda en una cookie HttpOnly y solo su huella (hash) queda en la base.", "- Pantallas: Hoy, Saldo, Ventas, Displays, Desempeño, Cuenta de cobro, Datos de cobro, Varios, Vender (con sus pasos de lote: nuevo, actual, cobro y listo), y Bloqueo (cuando tiene adeudo).", "");
  add("**Sitio público** (bienvisto.com.mx)", "");
  add("- Páginas estáticas: inicio, cómo funciona, servicios, preguntas frecuentes, términos, privacidad, blog, y formularios de factura, queja y solicitud de vendedor.", "- Los precios, comisiones, promociones y plazos que muestra se leen de /api/publico/config cada 60 segundos. Si la API no responde, muestra valores de respaldo que están en el código del sitio.", "- Los formularios llegan por correo a contacto@bienvisto.com.mx. Un formulario falla si el envío no está configurado.", "");
  add("**Enlaces públicos**", "");
  add("- `ir.bienvisto.com.mx/<folio en minúsculas>` redirige a la reseña del negocio que tiene el display activo. Si el display está libre, muestra una página de disponibilidad.", "- `/pago/VN-xxxxxxxx` muestra al cliente el monto y los datos de cobro de su venta. Si la venta ya está pagada o cancelada, lo dice.", "");
  add("**Correos**", "");
  add("- Recibo al cliente: sale recibo_min minutos después del cobro.", "- Comprobante al vendedor: sale cuando una venta queda entregada, es decir, cuando su saldo queda cubierto.", "- Los correos se envían desde Resend. El envío corre cada minuto y toma hasta 25 pendientes por corrida.", "");

  // ---------- 7 ----------
  add("## 7. Permisos del panel", "");
  add("Hay dos tipos de acceso. El **dueño** tiene todos los permisos. El **asociado** tiene solo los que le asigna el dueño, y nunca el de accesos. Siempre debe quedar al menos otro dueño activo.", "");
  add("Permisos y lo que habilitan:", "");
  add(...Object.entries(DOC_PERMISOS_DESC).map(([k, v]) => "- `" + k + "`: " + v));
  add("");
  add("Cada ruta de la API pide permisos concretos. Una ruta nueva que no esté en la lista exige el permiso de accesos, para que quede cerrada por defecto. Los cambios de Ajustes se revisan por campo: un cambio de precio exige precios_venta, y uno de regla exige reglas_vendedores.", "");

  // ---------- 8 ----------
  add("## 8. Infraestructura y servicios", "");
  add("- **Cloudflare Workers**: `bienvisto-api` es la API del panel, la API de la app de vendedores, los formularios del sitio y el envío de correos (cron cada minuto). `bienvisto-publico` sirve el sitio y lee los valores de la API.", "- **Cloudflare D1**: base `bienvisto-db`. Es la única fuente de datos.", "- **Cloudflare R2**: bucket `bienvisto-comprobantes` para comprobantes de cobro y de avisos de entrega.", "- **Cloudflare Access**: aplicación \"Panel Administrador\" sobre admini.bienvisto.com.mx. Identidad por Google (Instant Auth).", "- **Google Cloud**: dos clientes OAuth. Uno para la entrada de vendedores (Google Identity) y otro para el inicio de sesión del panel vía Access.", "- **Resend**: correos transaccionales. Remitentes vendedores@ y sitio@ dentro de bienvisto.com.mx.", "- **Google Places**: búsqueda de negocios, calificaciones y fotos para los vendedores.", "");
  add("Secretos y variables. Sus valores no están en este archivo. Aquí se muestra solo si están configurados:", "");
  add("- Base de datos (DB): " + (env.DB ? "configurada" : "NO configurada"));
  add("- Comprobantes (COMPROBANTES): " + (env.COMPROBANTES ? "configurado" : "NO configurado"));
  add("- Resend (RESEND_API_KEY): " + (env.RESEND_API_KEY ? "configurada" : "NO configurada"));
  add("- Google Places (GOOGLE_PLACES_KEY): " + (env.GOOGLE_PLACES_KEY ? "configurada" : "NO configurada"));
  add("- Google Identity (GOOGLE_CLIENT_ID): " + (env.GOOGLE_CLIENT_ID ? "configurado" : "NO configurado"));
  add("");
  add("Dónde vive el código: el API está en el archivo del worker `bienvisto-api`; el panel es un único `index.html` (repositorio bienvisto-admin); la app de vendedores es un único `index.html` (repositorio israelgb1-bienvisto-vendedores); y el sitio es un repositorio con HTML estático y un worker (bienvisto-publico). El código del API no tiene un repositorio fijo documentado: confirmar dónde se guarda antes de cambiarlo.", "");

  // ---------- 9 ----------
  add("## 9. Esquema de la base de datos (En vivo)", "");
  add("Tablas y columnas tal como están hoy en D1. No incluye datos.", "");
  if (esquema === null) {
    add("No disponible: la consulta falló al generar este archivo.", "");
  } else {
    for (const t of esquema) {
      add("### " + t.name, "", "```sql", t.sql + ";", "```", "");
    }
  }

  // ---------- 10 ----------
  add("## 10. Estado operativo ahora (En vivo)", "");
  add("**Displays por estado**", "");
  add(...cuenta(folios, (f) => "`" + f.estado + "`: " + f.n + " displays"));
  add("");
  add("**Vendedores por estado y nivel**", "");
  add(...cuenta(vendedores, (f) => f.estado + ", nivel " + f.nivel + ": " + f.n));
  add("");
  add("**Ventas por estado**", "");
  add(...cuenta(ventas, (f) => "`" + f.estado + "`: " + f.n));
  add("");
  add("**Saldo por entregar a Bien Visto (suma de todos los vendedores)**", "");
  add(saldo === null ? "- No disponible." : "- " + fmt(saldo[0] ? saldo[0].monto : 0) + ".");
  add("");
  add("**Pendientes que requieren atención**", "");
  add(...cuenta(pendientes, (f) => f.que + ": " + f.n));
  add("");
  add("**Administradores**", "");
  add(...cuenta(admins, (f) => (f.tipo === "dueno" ? "Dueños" : "Asociados") + (f.activo ? " activos" : " inactivos") + ": " + f.n));
  add("");
  add("**Historial**", "");
  add(auditoriaN === null ? "- No disponible." : "- Movimientos registrados en la auditoría: " + (auditoriaN[0] ? auditoriaN[0].n : 0) + ". Se consulta en Historial.");
  add("");

  // ---------- 11 ----------
  add("## 11. Historial reciente de precios (En vivo)", "");
  add(...(precios === null ? ["- No disponible."] : precios.length === 0 ? ["- Sin cambios registrados."] : precios.map((p) => "- " + String(p.fecha || "").slice(0, 10) + ": display " + fmt(p.precio) + ", comisión " + fmt(p.comision) + ", promoción " + p.promo_n + " por " + fmt(p.promo_precio) + (p.nota ? ". Nota: " + p.nota : ""))));
  add("");

  // ---------- 12 ----------
  add("## 12. Cómo operar y modificar el sistema", "");
  add("**Cambiar un precio, comisión o promoción**", "");
  add("Ajustes > Precios, con el permiso precios_venta. Al guardar, el sitio público se actualiza en menos de 60 segundos y la app de vendedores, al recargarse. Cada cambio queda en el historial de precios y en la auditoría.", "");
  add("**Cambiar una regla de vendedores** (topes, plazos, pruebas, reposiciones, bonos)", "");
  add("Ajustes > Reglas, con el permiso reglas_vendedores. Las restricciones de la sección 4 se revisan al guardar. Si una combinación rompe una regla, el panel muestra el error y no guarda nada.", "");
  add("**Agregar una clave de configuración**", "");
  add("1. Agregarla a CONFIG_CLAVES en el worker, y decidir si es de precios, costos o reglas en GRUPO_CONFIG.", "2. Validarla en actualizarConfig, con sus reglas entre campos si aplican.", "3. Si la app de vendedores o el sitio la necesitan, agregarla a su lista pública (CLAVES_PUBLICAS) o a la configuración del vendedor.", "4. Agregar el campo en Ajustes del panel y su descripción en DOC_CONFIG_DESC.", "");
  add("**Agregar un permiso**", "");
  add("Agregarlo a PERMISOS, a PERMISOS_ASIGNABLES (automático), a permisosRequeridos para las rutas que lo usen, y a la interfaz del panel. Sumar su descripción en DOC_PERMISOS_DESC.", "");
  add("**Cambiar el código**", "");
  add("- API: editar el worker `bienvisto-api` y desplegarlo desde Cloudflare. Probar antes con las pruebas de la API. Los archivos de prueba no están en un repositorio: hay que recrearlos o guardarlos.", "- Panel: cambiar index.html en bienvisto-admin, probar, y subirlo al servidor del panel. No se despliega solo.", "- App de vendedores: cambiar index.html en israelgb1-bienvisto-vendedores y subirlo. No se despliega solo.", "- Sitio: cambiar el HTML del repositorio bienvisto-publico y fusionar en main. Workers Builds lo despliega. Los precios no se editan aquí: se editan en Ajustes.", "");
  add("**Cambios en la base de datos**", "");
  add("Antes de cualquier migración, exportar la base desde Cloudflare D1. Las migraciones se corren una sola vez, en orden, y se guardan como archivo. Las tablas folios, ventas, venta_folios, cortes y auditoria tienen historial de dinero: no se borran filas sin respaldo.", "");
  add("**Qué no tocar sin respaldo**", "");
  add("- Los secretos (claves de Resend, Google y la base). Se cambian en Cloudflare, no en el código.", "- Los datos de pago de Bien Visto (datos_pago). Solo el dueño los cambia desde Ajustes.", "- Las reglas de dinero (saldo, exposición, corte). Cambiarlas altera lo que deben los vendedores.", "");

  // ---------- 13 ----------
  add("## 13. Puntos a vigilar", "");
  add("- Las pruebas vencidas se liberan cuando alguien pide un dato que las necesita, no por temporizador.", "- Los estados pausa y adeudo de folios, y rechazada de ventas, no tienen flujo que los asigne (sección 3).", "- El cierre de sesión del panel no cierra la sesión de Google en el navegador.", "- El envío de correos depende de la clave de Resend y de que el dominio esté verificado. Si hay correos en sin_correo, revisar Resend primero.", "- La sesión de vendedor no se renueva por uso: a los 30 días debe volver a entrar.", "- Esta documentación refleja el código actual. Si se cambia el código y no se actualiza la narrativa de las secciones 1 a 3, 6 a 8 y 12, la descripción queda vieja. Las secciones En vivo siempre están al día.", "");

  return L.join("\n") + "\n";
}

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


// ==========================================
// 2. API DE VENDEDORES (app.bienvisto.com.mx/api/vendedor/*)
// Acceso por código de un solo uso enviado al correo del vendedor.
// Sesión en cookie HttpOnly; en la base solo se guardan hashes.
// ==========================================
async function handleVendedorApi(request, env, url) {
  const method = request.method;
  const path = url.pathname;
  try {
    if (path === "/api/vendedor/codigo" && method === "POST") {
      return pedirCodigo(request, env);
    }
    if (path === "/api/vendedor/verificar" && method === "POST") {
      return verificarCodigo(request, env);
    }
    if (path === "/api/vendedor/acceso" && method === "GET") {
      // Formas de entrar disponibles. El ID de cliente de Google es público por diseño.
      return json({ google_client_id: env.GOOGLE_CLIENT_ID || null });
    }
    if (path === "/api/vendedor/google" && method === "POST") {
      return entrarConGoogle(request, env);
    }
    if (path === "/api/vendedor/salir" && method === "POST") {
      return cerrarSesion(request, env);
    }
    if (path === "/api/vendedor/yo" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      const perfil = await env.DB.prepare("SELECT correo, whatsapp, fecha_registro, nivel FROM vendedores WHERE id = ?").bind(vendedor.id).first();
      const cfgYo = await leerConfig(env);
      const rep = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM solicitudes WHERE vendedor_id = ? AND tipo = 'reponer' AND resuelto_por = 'directo' AND created_at >= ?"
      ).bind(vendedor.id, inicioMesMX()).first();
      return json({
        id: vendedor.id,
        nombre: vendedor.nombre,
        correo: perfil ? perfil.correo || null : null,
        whatsapp: perfil ? perfil.whatsapp || null : null,
        fecha_registro: perfil ? perfil.fecha_registro || null : null,
        nivel: perfil ? perfil.nivel : "nuevo",
        reposiciones_directas_mes: Number(rep && rep.n) || 0,
        lim_rep: Number(cfgYo.lim_rep),
      });
    }
    if (path === "/api/vendedor/config" && method === "GET") {
      // Importes que el vendedor necesita para sus textos de ayuda. Sin ajustes internos (lead_d, colch, parado_d, esc_bajo, bonos).
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      const c = await leerConfig(env);
      return json({
        precio_display: Number(c.precio_display), comision_display: Number(c.comision_display),
        promo_n: Number(c.promo_n), promo_precio: Number(c.promo_precio),
        tope_confianza: Number(c.tope_confianza), tope_nuevo: Number(c.tope_nuevo),
        horas: Number(c.horas), lim_rep: Number(c.lim_rep),
        prueba_minutos: Number(c.prueba_minutos), recibo_min: Number(c.recibo_min),
      });
    }
    if (path === "/api/vendedor/saldo" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return vendedorSaldo(env, vendedor);
    }
    if (path === "/api/vendedor/clientes" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return vendedorClientes(env, vendedor);
    }
    if (path === "/api/vendedor/ventas" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return vendedorVentas(env, vendedor);
    }
    if (path === "/api/vendedor/desempeno" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return vendedorDesempeno(env, vendedor);
    }
    if (path === "/api/vendedor/solicitudes" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return vendedorSolicitudes(env, vendedor);
    }
    const historial = path.match(/^\/api\/vendedor\/displays\/([A-Za-z0-9]{4})\/historial$/);
    if (historial && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return vendedorHistorial(env, vendedor, historial[1].toUpperCase());
    }
    if (path === "/api/vendedor/cuenta-cobro" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return vendedorCuentaCobro(env, vendedor);
    }
    if (path === "/api/vendedor/cuenta-cobro" && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return guardarCuentaCobro(request, env, vendedor);
    }
    if (path === "/api/vendedor/cuenta-cobro/cancelar" && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return cancelarCambioCuenta(env, vendedor);
    }
    if (path === "/api/vendedor/datos-pago" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return vendedorDatosPago(env);
    }
    if (path === "/api/vendedor/displays" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return vendedorDisplays(env, vendedor);
    }
    if (path === "/api/vendedor/avisos-entrega" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return listarAvisosVendedor(env, vendedor);
    }
    if (path === "/api/vendedor/avisos-entrega" && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return crearAvisoEntrega(request, env, vendedor);
    }
    const avisoComprobante = path.match(/^\/api\/vendedor\/avisos-entrega\/(AE-[0-9a-f]{8})\/comprobante$/);
    if (avisoComprobante && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return subirComprobanteAviso(request, env, vendedor, avisoComprobante[1]);
    }
    if (path === "/api/vendedor/ventas" && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return crearVenta(request, env, "vendedor:" + vendedor.id, vendedor);
    }
    const revision = path.match(/^\/api\/vendedor\/ventas\/(VN-[0-9a-f]{8})\/revision$/);
    if (revision && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      const venta = await env.DB.prepare("SELECT * FROM ventas WHERE id = ? AND vendedor_id = ?").bind(revision[1], vendedor.id).first();
      if (!venta) return json({ error: "Venta no encontrada" }, 404);
      return enviarRevision(env, venta, (await leerJson(request)) || {}, "vendedor:" + vendedor.id);
    }
    const cobro = path.match(/^\/api\/vendedor\/ventas\/(VN-[0-9a-f]{8})\/cobro$/);
    if (cobro && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      const venta = await env.DB.prepare("SELECT * FROM ventas WHERE id = ? AND vendedor_id = ?").bind(cobro[1], vendedor.id).first();
      if (!venta) return json({ error: "Venta no encontrada" }, 404);
      return cobrarVendedor(request, env, venta, vendedor);
    }
    // El vendedor puede deshacer una venta que aún no se cobró (por ejemplo, para cambiar de transferencia a efectivo).
    const anularPend = path.match(/^\/api\/vendedor\/ventas\/(VN-[0-9a-f]{8})\/anular-pendiente$/);
    if (anularPend && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      const venta = await env.DB.prepare("SELECT * FROM ventas WHERE id = ? AND vendedor_id = ?").bind(anularPend[1], vendedor.id).first();
      if (!venta) return json({ error: "Venta no encontrada" }, 404);
      if (venta.estado !== "pendiente") return json({ error: "Solo puedes cambiar el método de una venta que aún no se cobró" }, 409);
      const plan = await planAnular(env, venta, "vendedor:" + vendedor.id);
      if (plan.error) return plan.error;
      await env.DB.batch(plan.stmts);
      return json({ success: true, id: venta.id });
    }
    if (path === "/api/vendedor/ficha-negocio" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      const placeId = (url.searchParams.get("place_id") || "").trim();
      if (!/^[A-Za-z0-9_-]{5,200}$/.test(placeId)) return json({ error: "Negocio no válido" }, 400);
      return json({ google: await ratingPorPlaceId(env, placeId) });
    }
    if (path === "/api/vendedor/foto-negocio" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return fotoGoogle(env, (url.searchParams.get("ref") || "").trim());
    }
    if (path === "/api/vendedor/buscar-negocio" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      const consulta = (url.searchParams.get("q") || "").trim().slice(0, 100);
      if (consulta.length < 3) return json({ error: "Escribe al menos 3 letras" }, 400);
      // Ubicación opcional del vendedor: solo sesga el orden (no restringe), para que aparezcan primero los de su zona.
      const latTxt = (url.searchParams.get("lat") || "").trim();
      const lngTxt = (url.searchParams.get("lng") || "").trim();
      const lat = latTxt === "" ? NaN : Number(latTxt);
      const lng = lngTxt === "" ? NaN : Number(lngTxt);
      const sesgo = Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180 ? { lat, lng } : null;
      return buscarNegocioGoogle(env, consulta, sesgo);
    }
    if (path === "/api/vendedor/buscar-cercanos" && method === "GET") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      const latTxt = url.searchParams.get("lat") || "";
      const lngTxt = url.searchParams.get("lng") || "";
      const lat = latTxt.trim() === "" ? NaN : Number(latTxt);
      const lng = lngTxt.trim() === "" ? NaN : Number(lngTxt);
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) return json({ error: "Ubicación no válida" }, 400);
      // Caja aproximada de México: evita llamadas de pago con coordenadas fuera del servicio.
      if (lat < 14 || lat > 33 || lng < -118 || lng > -86) return json({ error: "Ubicación fuera de México" }, 400);
      return buscarCercanosGoogle(env, lat, lng);
    }
    if (path === "/api/vendedor/pruebas" && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return iniciarPrueba(request, env, vendedor);
    }
    const terminar = path.match(/^\/api\/vendedor\/pruebas\/([A-Z0-9]{4})\/terminar$/);
    if (terminar && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return terminarPrueba(env, vendedor, terminar[1]);
    }
    if (path === "/api/vendedor/solicitudes" && method === "POST") {
      const vendedor = await sesionVendedor(request, env);
      if (!vendedor) return json({ error: "No autorizado" }, 401);
      return crearSolicitud(request, env, "vendedor:" + vendedor.id, vendedor);
    }
    return json({ error: "Endpoint no encontrado" }, 404);
  } catch (err) {
    console.error("vendedor api error", err);
    return json({ error: "Error interno" }, 500);
  }
}

// Responde igual exista o no el correo, para no revelar qué vendedores hay.
// Bloqueo por vendedor: cuenta fallos y códigos de las últimas 24 horas (no por código),
// para que pedir códigos nuevos no reinicie el conteo.
async function bloqueoVendedor(env, vendedorId) {
  const r = await env.DB.prepare(
    "SELECT COUNT(*) AS codigos, COALESCE(SUM(intentos), 0) AS fallos FROM accesos WHERE vendedor_id = ? AND created_at > datetime('now', '-1 day')"
  ).bind(vendedorId).first();
  return Number(r.fallos) >= LIM_FALLOS_24H || Number(r.codigos) >= LIM_CODIGOS_24H;
}

async function pedirCodigo(request, env) {
  const respuesta = () =>
    json({ success: true, mensaje: "Si el correo está registrado, te enviamos un código." });

  const body = await leerJson(request);
  const correo = normalizarCorreo(body && body.correo);
  if (!CORREO_RE.test(correo)) return json({ error: "Correo no válido" }, 400);

  const vendedor = await env.DB.prepare(
    "SELECT id, nombre FROM vendedores WHERE lower(correo) = ? AND estado = 'activo'"
  ).bind(correo).first();
  if (!vendedor) return respuesta();
  if (await bloqueoVendedor(env, vendedor.id)) return respuesta();

  // Evita reenvíos seguidos: si hay un código reciente sin usar, no se manda otro.
  const reciente = await env.DB.prepare(
    "SELECT 1 AS x FROM accesos WHERE vendedor_id = ? AND usado_at IS NULL AND created_at > datetime('now', ?) LIMIT 1"
  ).bind(vendedor.id, `-${CODIGO_COOLDOWN_SEG} seconds`).first();
  if (reciente) return respuesta();

  const codigo = codigoAleatorio();
  const id = crypto.randomUUID();
  const ahora = new Date();
  const expira = new Date(ahora.getTime() + CODIGO_VIGENCIA_MIN * 60000).toISOString();
  const hash = await sha256(id + ":" + codigo);

  // Un solo código vigente por vendedor: los anteriores quedan consumidos.
  await env.DB.batch([
    env.DB.prepare("UPDATE accesos SET usado_at = ? WHERE vendedor_id = ? AND usado_at IS NULL").bind(ahora.toISOString(), vendedor.id),
    env.DB.prepare("INSERT INTO accesos (id, vendedor_id, canal, codigo_hash, expira_at) VALUES (?, ?, 'correo', ?, ?)").bind(id, vendedor.id, hash, expira),
  ]);

  const enviado = await enviarCodigo(env, correo, vendedor.nombre, codigo);
  if (!enviado) console.error("no se pudo enviar código de acceso a vendedor", vendedor.id);
  return respuesta();
}

async function verificarCodigo(request, env) {
  const body = await leerJson(request);
  const correo = normalizarCorreo(body && body.correo);
  const codigo = typeof body?.codigo === "string" ? body.codigo.trim() : "";
  if (!CORREO_RE.test(correo) || !/^\d{6}$/.test(codigo)) {
    return json({ error: "Correo o código no válido" }, 400);
  }

  const fallo = () => json({ error: "Código incorrecto o vencido" }, 401);

  const vendedor = await env.DB.prepare(
    "SELECT id, nombre FROM vendedores WHERE lower(correo) = ? AND estado = 'activo'"
  ).bind(correo).first();
  if (!vendedor) return fallo();
  if (await bloqueoVendedor(env, vendedor.id)) return fallo();

  const acceso = await env.DB.prepare(
    "SELECT id, codigo_hash, expira_at, intentos FROM accesos WHERE vendedor_id = ? AND usado_at IS NULL ORDER BY created_at DESC, rowid DESC LIMIT 1"
  ).bind(vendedor.id).first();
  if (!acceso) return fallo();
  if (acceso.intentos >= CODIGO_MAX_INTENTOS) return fallo();
  if (Date.parse(acceso.expira_at) <= Date.now()) return fallo();

  const hash = await sha256(acceso.id + ":" + codigo);
  if (hash !== acceso.codigo_hash) {
    await env.DB.prepare("UPDATE accesos SET intentos = intentos + 1 WHERE id = ?").bind(acceso.id).run();
    return fallo();
  }

  // Consumir el código solo si nadie lo usó a la vez.
  const consumido = await env.DB.prepare(
    "UPDATE accesos SET usado_at = ? WHERE id = ? AND usado_at IS NULL"
  ).bind(new Date().toISOString(), acceso.id).run();
  if (!consumido.meta || consumido.meta.changes !== 1) return fallo();

  return abrirSesion(env, vendedor);
}

async function abrirSesion(env, vendedor) {
  const token = tokenAleatorio();
  const sesionExpira = new Date(Date.now() + SESION_DIAS * 86400000).toISOString();
  await env.DB.prepare(
    "INSERT INTO sesiones (token_hash, vendedor_id, expira_at) VALUES (?, ?, ?)"
  ).bind(await sha256(token), vendedor.id, sesionExpira).run();

  return Response.json(
    { success: true, nombre: vendedor.nombre },
    {
      headers: {
        "Set-Cookie": `${COOKIE_SESION}=${token}; Path=/api/vendedor; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESION_DIAS * 86400}`,
      },
    }
  );
}

// ---------- Entrar con Google ----------
// La app recibe de Google un token firmado (ID token) y lo manda aquí. Se verifica la firma con las llaves públicas
// de Google, que sea para nuestra app (aud) y que no haya vencido. Entra si el correo de Google es el de un vendedor activo.
const GOOGLE_EMISORES = ["accounts.google.com", "https://accounts.google.com"];
const GOOGLE_LLAVES_URL = "https://www.googleapis.com/oauth2/v3/certs";
let googleLlaves = { hasta: 0, llaves: [] };

async function llaveGoogle(kid) {
  const buscar = () => googleLlaves.llaves.find((k) => k.kid === kid);
  if (Date.now() < googleLlaves.hasta && buscar()) return buscar();
  const res = await fetch(GOOGLE_LLAVES_URL);
  if (!res.ok) return null;
  const j = await res.json();
  const edad = /max-age=(\d+)/.exec(res.headers.get("Cache-Control") || "");
  googleLlaves = { hasta: Date.now() + (edad ? Number(edad[1]) * 1000 : 3600000), llaves: Array.isArray(j.keys) ? j.keys : [] };
  return buscar() || null;
}

async function verificarTokenGoogle(token, clienteId) {
  if (typeof token !== "string" || token.length > 4096) return null;
  const partes = token.split(".");
  if (partes.length !== 3) return null;
  let header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(b64uDecode(partes[0])));
    payload = JSON.parse(new TextDecoder().decode(b64uDecode(partes[1])));
  } catch {
    return null;
  }
  if (header.alg !== "RS256" || !header.kid) return null;
  if (!GOOGLE_EMISORES.includes(payload.iss)) return null;
  if (payload.aud !== clienteId) return null;
  const ahora = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= ahora) return null;
  if (typeof payload.iat === "number" && payload.iat > ahora + 300) return null;
  if (payload.email_verified !== true && payload.email_verified !== "true") return null;

  const jwk = await llaveGoogle(header.kid);
  if (!jwk) return null;
  const llave = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valida = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    llave,
    b64uDecode(partes[2]),
    new TextEncoder().encode(partes[0] + "." + partes[1])
  );
  if (!valida) return null;
  return normalizarCorreo(payload.email);
}

async function entrarConGoogle(request, env) {
  if (!env.GOOGLE_CLIENT_ID) return json({ error: "La entrada con Google no está activada." }, 404);
  const body = await leerJson(request);
  let correo = null;
  try {
    correo = await verificarTokenGoogle(body && body.credential, env.GOOGLE_CLIENT_ID);
  } catch {
    correo = null;
  }
  if (!correo || !CORREO_RE.test(correo)) return json({ error: "No pudimos confirmar tu cuenta de Google. Intenta de nuevo." }, 401);

  const vendedor = await env.DB.prepare(
    "SELECT id, nombre FROM vendedores WHERE lower(correo) = ? AND estado = 'activo'"
  ).bind(correo).first();
  if (!vendedor) {
    return json({ error: "no_registrado", correo }, 403);
  }
  return abrirSesion(env, vendedor);
}

async function cerrarSesion(request, env) {
  const token = leerCookie(request, COOKIE_SESION);
  if (token) {
    await env.DB.prepare("DELETE FROM sesiones WHERE token_hash = ?").bind(await sha256(token)).run();
  }
  return Response.json(
    { success: true },
    { headers: { "Set-Cookie": `${COOKIE_SESION}=; Path=/api/vendedor; HttpOnly; Secure; SameSite=Strict; Max-Age=0` } }
  );
}

// Devuelve { id, nombre } si la sesión es válida y el vendedor sigue activo; si no, null.
// Lectura para la app de vendedores. Siempre filtra por el vendedor de la sesión.
// Cobro desde la app del vendedor: mismo efecto que el cobro del administrador
// (venta cobrada + displays activos con su enlace de reseña), solo sobre ventas propias.
async function cobrarVendedor(request, env, venta, vendedor) {
  if (venta.estado !== "pendiente" && venta.estado !== "rev") {
    return json({ error: "Solo se cobra una venta pendiente o en revisión" }, 409);
  }
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);
  if (!esUrlResena(body.url_resena)) return json({ error: "El enlace de reseña debe ser de Google (https)" }, 400);
  // La clave de rastreo es opcional al activar desde la app (el vendedor revisa su banco antes).
  const referencia = limpiarTexto(body.referencia, 100) || venta.referencia;

  const cfg = await leerConfig(env);
  await aplicarVencimientos(env, "sistema", null, cfg.prueba_minutos);
  const adeudo = await env.DB.prepare(
    "SELECT 1 AS x FROM ventas WHERE vendedor_id = ? AND impago = 1 AND estado <> 'anulada' LIMIT 1"
  ).bind(vendedor.id).first();
  if (adeudo) return json({ error: "Tienes un adeudo por impago; no puedes activar displays" }, 409);

  const plazo = await env.DB.prepare(
    "SELECT MIN(COALESCE(fecha_cobro, created_at)) AS mas_antigua FROM ventas WHERE vendedor_id = ? AND estado IN ('cobrada','entregada') AND a_entregar - COALESCE(entregado, 0) > 0.001"
  ).bind(vendedor.id).first();
  if (plazo && plazo.mas_antigua) {
    const horas = (Date.now() - Date.parse(plazo.mas_antigua.replace(" ", "T") + "Z")) / 3600000;
    if (horas >= cfg.horas) {
      return json({ error: "Tienes ventas cobradas que vencieron el plazo de entrega; no puedes activar displays nuevos" }, 409);
    }
  }

  // El tope se revisa al cobrar cada venta: así varias ventas pendientes no pueden rebasarlo juntas.
  const tope = await topeVendedor(env, vendedor.id, cfg);
  const exposicion = await exposicionVendedor(env, vendedor.id, venta.id);
  if (exposicion + Number(venta.a_entregar) > tope + 0.001) {
    return json({ error: `Al cobrar esta venta pasarías tu tope de ${fmtMXN(tope)}. Entrega lo que tienes y vuelve a intentarlo.` }, 409);
  }

  const plan = await planCobro(env, venta, body.url_resena, referencia, "vendedor:" + vendedor.id, cfg);
  if (plan.error) return plan.error;
  await env.DB.batch(plan.stmts);
  return json({ success: true, id: venta.id, estado: "cobrada", displays_activos: plan.n });
}

// ==========================================
// ENVÍO DE CORREOS: recibo al cliente y comprobante al vendedor (Resend)
// Cron cada minuto: scheduled() llama enviarPendientes().
// ==========================================
const fmtMXN = (n) => new Intl.NumberFormat("es-MX", { style: "currency", currency: "MXN" }).format(Number(n) || 0);

// Logo de Bien Visto (isologo de color, PNG de 400 px) que va adjunto en línea al recibo.
// Los clientes de correo no cargan imágenes externas de forma confiable; así el logo siempre se ve.
const LOGO_CORREO_ID = "logo-bienvisto";
const LOGO_CORREO_B64 = "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";

function fechaLarga(valor) {
  const d = new Date(String(valor || "").replace(" ", "T") + "Z");
  if (isNaN(d.getTime())) return "";
  return new Intl.DateTimeFormat("es-MX", { day: "numeric", month: "long", year: "numeric", timeZone: "America/Mexico_City" }).format(d);
}

function reciboCorreo(venta, folios, vendedor) {
  const primer = String(venta.contacto || "").trim().split(/\s+/)[0] || "";
  const nombreVend = vendedor ? vendedor.nombre : "tu vendedor";
  const transferencia = venta.metodo === "transferencia";
  const pagoTxt = transferencia
    ? "Transferencia a " + nombreVend + (venta.referencia ? " (clave de rastreo " + venta.referencia + ")" : "")
    : "Efectivo, recibido por " + nombreVend;
  const n = folios.length;
  const fecha = fechaLarga(venta.fecha_cobro || venta.created_at);
  const saludo = (primer ? "Hola " + primer + ", tu" : "Tu") + (n > 1 ? " display ya está activo." : " display ya está activo.");

  const lineas = [
    saludo + " Cada vez que alguien lo escanee, llega directo a la página para dejar una reseña en Google.",
    "",
    "Recibo " + venta.id,
    "Total pagado: " + fmtMXN(venta.total) + " (IVA incluido)",
    "Negocio: " + venta.negocio,
    fecha ? "Fecha: " + fecha : null,
    "Forma de pago: " + pagoTxt,
    n ? "Displays activos (" + n + "): " + folios.join(", ") : null,
    "",
    "Soporte y garantía: bienvisto.com.mx/soporte",
    "¿Necesitas factura? Pídela en bienvisto.com.mx/factura con la referencia " + venta.id + ".",
    "",
    "Este recibo no es una factura. Si pagaste una cantidad distinta, responde a este correo y lo revisamos.",
  ].filter((x) => x !== null);
  const texto = lineas.join("\n");

  const fila = (k, v, ultima) =>
    '<tr><td width="150" valign="top" style="padding:12px 0;border-top:1px solid #DDE7E2;' + (ultima ? "border-bottom:1px solid #DDE7E2;" : "") + 'color:#5C7069;">' + esc(k) + '</td>' +
    '<td valign="top" style="padding:12px 0;border-top:1px solid #DDE7E2;' + (ultima ? "border-bottom:1px solid #DDE7E2;" : "") + '">' + v + '</td></tr>';
  const filas = [
    fila("Negocio", esc(venta.negocio), false),
    fecha ? fila("Fecha", esc(fecha), false) : "",
    fila("Forma de pago", transferencia
      ? "Transferencia" + (venta.referencia ? '<br><span style="font-size:13px;color:#5C7069;">Clave de rastreo ' + esc(venta.referencia) + "</span>" : "")
      : "Efectivo", false),
    fila("Atendió", esc(nombreVend), true),
  ].join("");
  const lista = n
    ? '<tr><td bgcolor="#FFFFFF" style="padding:32px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;">' +
      '<p style="margin:0 0 12px 0;font-size:15px;line-height:20px;font-weight:bold;color:#12302B;">Displays activos (' + n + ")</p>" +
      '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">' +
      folios.map((f, i) => '<tr><td style="padding:10px 0;border-top:1px solid #DDE7E2;' + (i === n - 1 ? "border-bottom:1px solid #DDE7E2;" : "") + "font-family:'Courier New',Courier,monospace;font-size:15px;color:#12302B;\">" + esc(f) + "</td></tr>").join("") +
      "</table></td></tr>"
    : "";

  const html =
    '<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Recibo de Bien Visto</title></head>' +
    '<body style="margin:0;padding:0;background:#F3F1EC;">' +
    '<div style="display:none;max-height:0;overflow:hidden;color:#F3F1EC;mso-hide:all;">Recibo ' + esc(venta.id) + " por " + esc(fmtMXN(venta.total)) + ". Tu display ya está activo.</div>" +
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#F3F1EC" style="background:#F3F1EC;"><tr><td align="center" style="padding:24px 12px;">' +
    '<table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" bgcolor="#FFFFFF" style="width:600px;max-width:600px;background:#FFFFFF;">' +
    '<tr><td bgcolor="#FFFFFF" style="padding:28px 32px 24px 32px;border-bottom:1px solid #DDE7E2;font-family:Arial,Helvetica,sans-serif;">' +
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr>' +
    '<td valign="middle" align="left"><img src="cid:' + LOGO_CORREO_ID + '" width="200" height="44" alt="Bien Visto" style="display:block;border:0;outline:none;text-decoration:none;width:200px;height:44px;"></td>' +
    '<td valign="middle" align="right" style="font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:18px;color:#5C7069;">Recibo<br><span style="font-size:15px;font-weight:bold;color:#12302B;">' + esc(venta.id) + "</span></td>" +
    "</tr></table></td></tr>" +
    '<tr><td bgcolor="#FFFFFF" style="padding:32px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;">' +
    '<p style="margin:0;font-size:13px;line-height:18px;color:#5C7069;">Total pagado</p>' +
    '<p style="margin:6px 0 0 0;font-size:40px;line-height:44px;font-weight:bold;color:#12302B;">' + esc(fmtMXN(venta.total)) + "</p>" +
    '<p style="margin:6px 0 0 0;font-size:13px;line-height:18px;color:#5C7069;">IVA incluido</p></td></tr>' +
    '<tr><td bgcolor="#FFFFFF" style="padding:24px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:24px;color:#12302B;"><p style="margin:0;">' +
    esc(saludo) + " Cada vez que alguien lo escanee, llega directo a la página para dejar una reseña en Google.</p></td></tr>" +
    '<tr><td bgcolor="#FFFFFF" style="padding:28px 32px 0 32px;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:22px;color:#12302B;">' +
    filas + "</table></td></tr>" +
    lista +
    '<tr><td bgcolor="#FFFFFF" style="padding:32px;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:22px;color:#12302B;">' +
    '<p style="margin:0;">¿Necesitas factura? Pídela en <a href="https://bienvisto.com.mx/factura" style="color:#0E6B5C;font-weight:bold;text-decoration:underline;">bienvisto.com.mx/factura</a> con la referencia ' + esc(venta.id) + ".</p>" +
    '<p style="margin:8px 0 0 0;">Soporte y garantía: <a href="https://bienvisto.com.mx/soporte" style="color:#0E6B5C;text-decoration:underline;">bienvisto.com.mx/soporte</a></p></td></tr>' +
    '<tr><td bgcolor="#0E6B5C" style="padding:24px 32px;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#FBF6EC;">' +
    '<p style="margin:0;color:#FBF6EC;">Este recibo no es una factura. Si pagaste una cantidad distinta, responde a este correo y lo revisamos.</p>' +
    '<p style="margin:8px 0 0 0;color:#FBF6EC;"><a href="https://bienvisto.com.mx/privacidad" style="color:#FBF6EC;text-decoration:underline;">Aviso de privacidad</a> &nbsp;|&nbsp; <a href="https://bienvisto.com.mx/terminos-clientes" style="color:#FBF6EC;text-decoration:underline;">Términos</a></p>' +
    '<p style="margin:8px 0 0 0;color:#E7F0EC;">Bien Visto · bienvisto.com.mx</p></td></tr>' +
    '<tr><td bgcolor="#F2A71B" style="font-size:0;line-height:4px;height:4px;">&nbsp;</td></tr>' +
    "</table></td></tr></table></body></html>";
  return {
    asunto: "Tu recibo de Bien Visto · " + venta.id,
    texto,
    html,
    adjuntos: [{ filename: "logo-bienvisto.png", content: LOGO_CORREO_B64, content_type: "image/png", content_id: LOGO_CORREO_ID }],
  };
}

function comprobanteCorreo(venta, folios, vendedor) {
  const comision = Number(venta.total) - Number(venta.a_entregar);
  const n = folios.length;
  const primer = String((vendedor && vendedor.nombre) || "").trim().split(/\s+/)[0] || "";
  const fecha = fechaLarga(venta.entregada_at || venta.updated_at);
  const saludo = (primer ? "Hola " + primer + ", Bien" : "Bien") + " Visto confirmó tu entrega.";
  const displays = n + (n === 1 ? " display" : " displays");

  const lineas = [
    saludo,
    "",
    "Venta " + venta.id + " · " + venta.negocio + " · " + displays,
    "Cobrado por ti: " + fmtMXN(venta.total),
    "Tu comisión retenida: " + fmtMXN(comision),
    "Entregado: " + fmtMXN(venta.entregado),
    fecha ? "Fecha de confirmación: " + fecha : null,
    "",
    "Es un comprobante interno de entrega. No es una factura.",
  ].filter((x) => x !== null);
  const texto = lineas.join("\n");

  const fila = (k, v, ultima) =>
    '<tr><td width="170" valign="top" style="padding:12px 0;border-top:1px solid #DDE7E2;' + (ultima ? "border-bottom:1px solid #DDE7E2;" : "") + 'color:#5C7069;">' + esc(k) + '</td>' +
    '<td valign="top" style="padding:12px 0;border-top:1px solid #DDE7E2;' + (ultima ? "border-bottom:1px solid #DDE7E2;" : "") + '">' + v + '</td></tr>';
  const filas = [
    fila("Negocio", esc(venta.negocio), false),
    fila("Displays", esc(displays), false),
    fila("Cobrado por ti", esc(fmtMXN(venta.total)), false),
    fila("Tu comisión retenida", esc(fmtMXN(comision)), !fecha),
    fecha ? fila("Fecha de confirmación", esc(fecha), true) : "",
  ].join("");

  const html =
    '<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Comprobante de entrega</title></head>' +
    '<body style="margin:0;padding:0;background:#F3F1EC;">' +
    '<div style="display:none;max-height:0;overflow:hidden;color:#F3F1EC;mso-hide:all;">Bien Visto confirmó tu entrega de ' + esc(fmtMXN(venta.entregado)) + " de la venta " + esc(venta.id) + ".</div>" +
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#F3F1EC" style="background:#F3F1EC;"><tr><td align="center" style="padding:24px 12px;">' +
    '<table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" bgcolor="#FFFFFF" style="width:600px;max-width:600px;background:#FFFFFF;">' +
    '<tr><td bgcolor="#FFFFFF" style="padding:28px 32px 24px 32px;border-bottom:1px solid #DDE7E2;font-family:Arial,Helvetica,sans-serif;">' +
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr>' +
    '<td valign="middle" align="left"><img src="cid:' + LOGO_CORREO_ID + '" width="200" height="44" alt="Bien Visto" style="display:block;border:0;outline:none;text-decoration:none;width:200px;height:44px;"></td>' +
    '<td valign="middle" align="right" style="font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:18px;color:#5C7069;">Comprobante de entrega<br><span style="font-size:15px;font-weight:bold;color:#12302B;">' + esc(venta.id) + "</span></td>" +
    "</tr></table></td></tr>" +
    '<tr><td bgcolor="#FFFFFF" style="padding:32px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;">' +
    '<table role="presentation" cellspacing="0" cellpadding="0" border="0"><tr><td bgcolor="#E7F0EC" style="background:#E7F0EC;border-radius:14px;padding:5px 12px;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:18px;font-weight:bold;color:#0E6B5C;">Entrega confirmada</td></tr></table>' +
    '<p style="margin:16px 0 0 0;font-size:13px;line-height:18px;color:#5C7069;">Entregado</p>' +
    '<p style="margin:6px 0 0 0;font-size:40px;line-height:44px;font-weight:bold;color:#12302B;">' + esc(fmtMXN(venta.entregado)) + "</p></td></tr>" +
    '<tr><td bgcolor="#FFFFFF" style="padding:24px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:24px;color:#12302B;"><p style="margin:0;">' + esc(saludo) + "</p></td></tr>" +
    '<tr><td bgcolor="#FFFFFF" style="padding:28px 32px 32px 32px;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:22px;color:#12302B;">' +
    filas + "</table></td></tr>" +
    '<tr><td bgcolor="#0E6B5C" style="padding:24px 32px;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#FBF6EC;">' +
    '<p style="margin:0;color:#FBF6EC;">Es un comprobante interno de entrega. No es una factura.</p>' +
    '<p style="margin:8px 0 0 0;color:#FBF6EC;"><a href="https://bienvisto.com.mx/privacidad" style="color:#FBF6EC;text-decoration:underline;">Aviso de privacidad</a> &nbsp;|&nbsp; <a href="https://bienvisto.com.mx/terminos-clientes" style="color:#FBF6EC;text-decoration:underline;">Términos</a></p>' +
    '<p style="margin:8px 0 0 0;color:#E7F0EC;">Bien Visto · bienvisto.com.mx</p></td></tr>' +
    '<tr><td bgcolor="#F2A71B" style="font-size:0;line-height:4px;height:4px;">&nbsp;</td></tr>' +
    "</table></td></tr></table></body></html>";
  return {
    asunto: "Comprobante de entrega · " + venta.id,
    texto,
    html,
    adjuntos: [{ filename: "logo-bienvisto.png", content: LOGO_CORREO_B64, content_type: "image/png", content_id: LOGO_CORREO_ID }],
  };
}

async function enviarEnvio(env, e) {
  const venta = await env.DB.prepare("SELECT * FROM ventas WHERE id = ?").bind(e.venta_id).first();
  if (!venta) return { estado: "error", error: "venta no encontrada" };
  // Si la venta se anuló o rechazó después de programar el correo, ya no se envía (sus folios ya no existen).
  if (venta.estado === "anulada" || venta.estado === "rechazada") return { estado: "omitido", error: "venta " + venta.estado };
  const vendedor = await env.DB.prepare("SELECT nombre, correo FROM vendedores WHERE id = ?").bind(venta.vendedor_id).first();
  const destino = e.destinatario === "cliente" ? venta.correo : (vendedor && vendedor.correo);
  if (!destino) return { estado: "sin_correo", error: "sin correo de destino" };
  const { results: fs } = await env.DB.prepare("SELECT folio FROM venta_folios WHERE venta_id = ? ORDER BY folio").bind(venta.id).all();
  const folios = fs.map((x) => x.folio);
  const msg = e.tipo === "recibo" ? reciboCorreo(venta, folios, vendedor) : comprobanteCorreo(venta, folios, vendedor);
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: "Bien Visto <vendedores@bienvisto.com.mx>", to: [destino], subject: msg.asunto, text: msg.texto, html: msg.html, ...(msg.adjuntos ? { attachments: msg.adjuntos } : {}) }),
    signal: AbortSignal.timeout(10000),
  });
  if (res.ok) return { estado: "enviado" };
  const detalle = await res.text().catch(() => "");
  return { estado: "error", error: "Resend " + res.status + ": " + detalle.slice(0, 200) };
}

async function enviarPendientes(env) {
  const { results } = await env.DB.prepare(
    "SELECT id, venta_id, tipo, destinatario, intentos FROM envios WHERE estado = 'pendiente' AND intentos < 5 AND programado_para <= CURRENT_TIMESTAMP ORDER BY programado_para ASC, id ASC LIMIT 25"
  ).all();
  for (const e of results) {
    let r;
    try {
      r = await enviarEnvio(env, e);
    } catch (err) {
      r = { estado: "error", error: "excepción: " + String(err).slice(0, 200) };
    }
    if (r.estado === "enviado") {
      await env.DB.prepare("UPDATE envios SET estado = 'enviado', enviado_at = CURRENT_TIMESTAMP, intentos = intentos + 1, error = NULL WHERE id = ?").bind(e.id).run();
    } else if (r.estado === "sin_correo" || r.estado === "omitido") {
      await env.DB.prepare("UPDATE envios SET estado = ?, error = ? WHERE id = ?").bind(r.estado, r.error, e.id).run();
    } else {
      const intentos = e.intentos + 1;
      await env.DB.prepare("UPDATE envios SET intentos = ?, estado = ?, error = ? WHERE id = ?")
        .bind(intentos, intentos >= 5 ? "error" : "pendiente", r.error, e.id).run();
    }
  }
}

// Búsqueda de negocios en Google Places (API New). La clave vive en env.GOOGLE_PLACES_KEY, nunca en el navegador.
// Landing de un display libre (ir.bienvisto.com.mx/FOLIO). Estilo: brandbook v1.2.
function paginaLibre(folio) {
  const f = esc(folio);
  return `<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Bien Visto</title>
<style>
@font-face{font-family:"Bricolage Grotesque";src:url(data:font/woff2;base64,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) format("woff2");font-weight:200 800;font-display:swap}
@font-face{font-family:"Figtree";src:url(data:font/woff2;base64,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) format("woff2");font-weight:300 900;font-display:swap}
:root{--verde:#0E6B5C;--verde-h:#0A5246;--ambar:#F2A71B;--tinta:#12302B;--crema:#FBF6EC;--menta:#E7F0EC;--borde:#CFDDD6;--tinta-suave:#3F5A53}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{background:var(--crema);color:var(--tinta);font:400 16px/1.5 Figtree,system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;padding:16px 18px}
.tarjeta{width:100%;max-width:380px;background:var(--verde);color:var(--crema);border-radius:26px;padding:24px 20px 20px;text-align:center}
.iso{display:block;width:100%;max-width:220px;height:auto;margin:0 auto 14px}
h1{font:600 26px/1.1 "Bricolage Grotesque",system-ui,sans-serif;letter-spacing:-.015em;margin:0 0 8px;text-wrap:balance}
.lead{margin:0 auto 16px;max-width:30ch;font-size:15px;line-height:1.5;opacity:.94}
.ejemplo{background:var(--menta);color:var(--tinta);border-radius:20px;padding:16px 14px 14px;text-align:left;margin:0}
.ejemplo .nota{font-size:12.5px;line-height:1.4;color:var(--tinta-suave);margin:10px 0 0;text-align:center}
.cab{display:flex;align-items:center;gap:12px;margin:0}
.av{width:36px;height:36px;border-radius:50%;background:var(--verde);color:var(--crema);display:grid;place-items:center;font:600 14px/1 "Bricolage Grotesque",system-ui,sans-serif;flex:none}
.cab b{display:block;font:600 17px/1.2 "Bricolage Grotesque",system-ui,sans-serif}
.cab small{display:block;font-size:14px;line-height:1.3;color:var(--tinta-suave)}
.ejemplo .pregunta{font:600 19px/1.15 "Bricolage Grotesque",system-ui,sans-serif;margin:14px 0 6px;text-align:center}
.ejemplo .estrellas{color:var(--ambar);font-size:26px;letter-spacing:5px;margin:0 0 12px;line-height:1;text-align:center}
.ejemplo .pide{display:block;font:600 13px/1.2 Figtree,system-ui,sans-serif;color:var(--tinta-suave);margin:0 0 8px}
.resena{background:#fff;border:2px solid var(--borde);border-radius:12px;padding:10px 12px 12px;font-size:15px;line-height:1.45;color:var(--tinta);margin:0}
.btn{display:block;width:100%;margin:0;text-align:center;text-decoration:none;font:600 18px/1.2 Figtree,system-ui,sans-serif;padding:15px 20px;border-radius:999px;background:var(--ambar);color:var(--tinta)}
.btn:hover{background:#E59A10}
.btn:focus-visible,.enlace:focus-visible,.pie a:focus-visible{outline:3px solid var(--verde);outline-offset:3px}
.fuera{width:100%;max-width:380px;display:flex;flex-direction:column;align-items:center;gap:12px;text-align:center}
.enlaces{display:flex;justify-content:center;gap:24px;flex-wrap:wrap}
.enlace{color:var(--verde);font-weight:600;font-size:15px;text-decoration:underline;text-underline-offset:4px;text-decoration-thickness:2px}
.pie{font-size:14px;color:var(--tinta);opacity:.75;margin:0}
.pie a{color:var(--tinta)}
@media (prefers-reduced-motion:no-preference){.ejemplo .estrellas{animation:llena .6s ease-out both}@keyframes llena{from{opacity:0;letter-spacing:14px}to{opacity:1;letter-spacing:6px}}}
</style></head>
<body>
<main class="tarjeta">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 711.85 156.25" role="img" aria-labelledby="t"><title id="t">Bien Visto isologo color</title><rect width="711.85" height="156.25" rx="78.12" fill="#0E6B5C"/><g transform="translate(22.49 4.52) scale(0.52)"><path fill="#FBF6EC" d="M62 163 L62 78 A16 16 0 0 0 30 78 L30 163 A16 16 0 0 0 62 163 Z"/><path fill="#FBF6EC" fill-rule="evenodd" d="M30 163 A59 59 0 1 1 148 163 A59 59 0 1 1 30 163 Z M62 163 A27 27 0 1 0 116 163 A27 27 0 1 0 62 163 Z"/><path fill="#F2A71B" d="M159.53 150 L197.35 215.5 A15 15 0 0 0 223.33 215.5 L298.96 84.5 A15 15 0 0 0 272.98 69.5 L210.34 178 L185.51 135 A15 15 0 0 0 159.53 150 Z"/></g><g transform="translate(212.08 118.25) scale(0.5)"><path fill="#FBF6EC" transform="translate(0 0)" d="M0 -59V-148.68C0 -155.86 5.82 -161.68 13 -161.68C20.18 -161.68 26 -155.86 26 -148.68V-108.97C35.91 -115.92 47.98 -120 61 -120C94.69 -120 122 -92.69 122 -59C122 -25.31 94.69 2 61 2C27.31 2 0 -25.31 0 -59ZM26.78 -59C26.78 -40.1 42.1 -24.78 61 -24.78C79.9 -24.78 95.22 -40.1 95.22 -59C95.22 -77.9 79.9 -93.22 61 -93.22C42.1 -93.22 26.78 -77.9 26.78 -59Z"/><path fill="#FBF6EC" transform="translate(137.84 0)" d="M26 -11.8C26 -4.62 20.18 1.2 13 1.2C5.82 1.2 0 -4.62 0 -11.8V-106.2C0 -113.38 5.82 -119.2 13 -119.2C20.18 -119.2 26 -113.38 26 -106.2ZM-2.08 -146.5C-2.08 -154.83 4.67 -161.58 13 -161.58C21.33 -161.58 28.08 -154.83 28.08 -146.5C28.08 -138.17 21.33 -131.42 13 -131.42C4.67 -131.42 -2.08 -138.17 -2.08 -146.5Z"/><path fill="#FBF6EC" transform="translate(179.69 0)" d="M121.11 -69.39C122.39 -61.99 122.29 -54.41 120.82 -47.04H28.94C30.71 -42.28 33.57 -37.86 37.44 -34.18C48.76 -23.44 65.9 -21.72 79.13 -29.98C85.4 -33.9 93.66 -32 97.58 -25.73C101.51 -19.45 99.6 -11.19 93.33 -7.27C69.75 7.47 39.19 4.39 19.01 -14.75C-1.16 -33.89 -5.83 -64.25 7.65 -88.57C21.13 -112.89 49.35 -125.02 76.27 -118.06C99.78 -111.98 117.1 -92.69 121.11 -69.39ZM93.07 -70.96C89.24 -81.2 80.63 -89.27 69.57 -92.13C54.47 -96.04 38.64 -89.24 31.07 -75.6C30.24 -74.09 29.52 -72.54 28.93 -70.96H93.07Z"/><path fill="#FBF6EC" transform="translate(312.49 0)" d="M26 -11.8C26 -4.62 20.18 1.2 13 1.2C5.82 1.2 0 -4.62 0 -11.8V-106.2C0 -113.38 5.82 -119.2 13 -119.2C17.76 -119.2 21.92 -116.64 24.19 -112.83C31.72 -117.38 40.55 -120 50 -120C77.61 -120 100 -97.61 100 -70V-11.8C100 -4.62 94.18 1.2 87 1.2C79.82 1.2 74 -4.62 74 -11.8V-70C74 -83.25 63.25 -94 50 -94C36.75 -94 26 -83.25 26 -70Z"/><path fill="#FBF6EC" transform="translate(456.15 0)" d="M1.45 -101.05 52.49 -5.05C54.63 -1.02 58.83 1.5 63.4 1.5C67.96 1.5 72.16 -1.02 74.3 -5.05L125.34 -101.05C128.54 -107.07 126.26 -114.55 120.24 -117.75C114.21 -120.96 106.73 -118.67 103.53 -112.65L63.39 -37.16L23.25 -112.65C19.97 -118.51 12.6 -120.67 6.68 -117.51C0.75 -114.36 -1.57 -107.05 1.45 -101.05Z"/><path fill="#FBF6EC" transform="translate(593.63 0)" d="M26 -11.8C26 -4.62 20.18 1.2 13 1.2C5.82 1.2 0 -4.62 0 -11.8V-106.2C0 -113.38 5.82 -119.2 13 -119.2C20.18 -119.2 26 -113.38 26 -106.2ZM-2.08 -146.5C-2.08 -154.83 4.67 -161.58 13 -161.58C21.33 -161.58 28.08 -154.83 28.08 -146.5C28.08 -138.17 21.33 -131.42 13 -131.42C4.67 -131.42 -2.08 -138.17 -2.08 -146.5Z"/><path fill="#FBF6EC" transform="translate(633.81 0)" d="M67.33 -104.48C71.15 -98.82 69.66 -91.15 64 -87.33C58.34 -83.51 50.67 -85 46.85 -90.66C44.05 -94.82 38.7 -96.43 34.07 -94.5C29.44 -92.57 26.82 -87.64 27.81 -82.72C28.79 -77.81 33.11 -74.27 38.12 -74.27L38.13 -74.27C56.63 -74.27 72.47 -60.98 75.68 -42.76C78.89 -24.54 68.56 -6.64 51.17 -0.31C33.79 6.02 14.36 -1.05 5.11 -17.07C1.76 -22.97 3.8 -30.47 9.68 -33.86C15.55 -37.25 23.06 -35.27 26.5 -29.42C29.76 -23.78 36.6 -21.29 42.72 -23.52C48.85 -25.75 52.49 -32.06 51.35 -38.47C50.22 -44.89 44.65 -49.57 38.13 -49.57C21.35 -49.57 6.89 -61.41 3.59 -77.87C0.3 -94.33 9.07 -110.82 24.56 -117.29C40.05 -123.76 57.95 -118.4 67.33 -104.48Z"/><path fill="#FBF6EC" transform="translate(721.98 0)" d="M2 -95.28C-4.61 -95.28 -9.96 -100.63 -9.96 -107.24C-9.96 -113.85 -4.61 -119.2 2 -119.2H16.22C17.35 -125.23 22.64 -129.8 29 -129.8C35.36 -129.8 40.65 -125.23 41.78 -119.2H63C69.61 -119.2 74.96 -113.85 74.96 -107.24C74.96 -100.63 69.61 -95.28 63 -95.28H42V-43.8C42 -33.31 50.51 -24.8 61 -24.8C68.18 -24.8 74 -18.98 74 -11.8C74 -4.62 68.18 1.2 61 1.2C36.15 1.2 16 -18.95 16 -43.8V-95.28Z"/><path fill="#FBF6EC" transform="translate(793.55 0)" d="M0 -59C0 -92.69 27.31 -120 61 -120C94.69 -120 122 -92.69 122 -59C122 -25.31 94.69 2 61 2C27.31 2 0 -25.31 0 -59ZM26.78 -59C26.78 -40.1 42.1 -24.78 61 -24.78C79.9 -24.78 95.22 -40.1 95.22 -59C95.22 -77.9 79.9 -93.22 61 -93.22C42.1 -93.22 26.78 -77.9 26.78 -59Z"/></g></svg>
<h1>Así funciona este display</h1>
<p class="lead">Acerca tu celular y podrás dejar una reseña de este negocio en Google.</p>
<div class="ejemplo" role="img" aria-label="Ejemplo ilustrativo de una petición de reseña. No es una página de Google.">
  <div class="cab"><span class="av">BV</span><div><b>Tu negocio</b><small>Petición de reseña</small></div></div>
  <p class="pregunta">¿Qué tal te atendimos?</p>
  <p class="estrellas" aria-hidden="true">★★★★★</p>
  <span class="pide">Tu reseña</span>
  <p class="resena">Llegué sin cita y me atendieron rápido. Café caliente y muy buen trato.</p>
  <p class="nota">Solo un ejemplo.</p>
</div>
</main>
<div class="fuera">
  <a class="btn" href="https://vendedores.bienvisto.com.mx/#/vender/${f}">Activar este display</a>
  <div class="enlaces">
    <a class="enlace" href="https://bienvisto.com.mx/vendedores">Quiero vender</a>
    <a class="enlace" href="https://bienvisto.com.mx/como-funciona">Quiero conocer más</a>
  </div>
  <p class="pie"><a href="https://bienvisto.com.mx/">bienvisto.com.mx</a></p>
</div>
</body></html>`;
}

async function buscarNegocioGoogle(env, consulta, sesgo = null) {
  if (!env.GOOGLE_PLACES_KEY) return json({ error: "La búsqueda de negocios no está disponible por ahora" }, 503);
  let res;
  try {
    res = await fetch("https://places.googleapis.com/v1/places:searchText", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": env.GOOGLE_PLACES_KEY,
        "X-Goog-FieldMask": "places.id,places.displayName,places.formattedAddress",
      },
      body: JSON.stringify({
        textQuery: consulta,
        maxResultCount: 5,
        languageCode: "es",
        regionCode: "MX",
        ...(sesgo ? { locationBias: { circle: { center: { latitude: sesgo.lat, longitude: sesgo.lng }, radius: 30000 } } } : {}),
      }),
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    return json({ error: "No pudimos buscar el negocio. Intenta de nuevo." }, 502);
  }
  if (!res.ok) return json({ error: "No pudimos buscar el negocio. Intenta de nuevo." }, 502);
  const datos = await res.json().catch(() => ({}));
  const resultados = (datos.places || []).slice(0, 5).map((p) => ({
    place_id: p.id,
    nombre: p.displayName && p.displayName.text ? p.displayName.text : "",
    direccion: p.formattedAddress || "",
    enlace_resena: "https://search.google.com/local/writereview?placeid=" + encodeURIComponent(p.id),
  })).filter((r) => r.place_id && r.nombre);
  return json({ resultados });
}

// Negocios cercanos (Nearby Search, API New). Tipos fijos en el servidor: el vendedor no elige nada.
const TIPOS_CERCANOS = [
  "restaurant", "cafe", "bakery", "meal_takeaway", "supermarket", "grocery_store", "convenience_store",
  "pharmacy", "hardware_store", "beauty_salon", "barber_shop", "spa", "gym",
  "clothing_store", "shoe_store", "florist", "veterinary_care", "laundry", "car_repair",
];

async function buscarCercanosGoogle(env, lat, lng) {
  if (!env.GOOGLE_PLACES_KEY) return json({ error: "La búsqueda de negocios no está disponible por ahora" }, 503);
  let res;
  try {
    res = await fetch("https://places.googleapis.com/v1/places:searchNearby", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": env.GOOGLE_PLACES_KEY,
        "X-Goog-FieldMask": "places.id,places.displayName,places.formattedAddress",
      },
      body: JSON.stringify({
        includedTypes: TIPOS_CERCANOS,
        maxResultCount: 10,
        rankPreference: "DISTANCE",
        locationRestriction: { circle: { center: { latitude: lat, longitude: lng }, radius: 500 } },
        languageCode: "es",
        regionCode: "MX",
      }),
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    return json({ error: "No pudimos buscar negocios cercanos. Intenta de nuevo." }, 502);
  }
  if (!res.ok) {
    // Motivo de Google para diagnosticar (no incluye la clave).
    const cuerpoError = await res.json().catch(() => ({}));
    const detalle = "Google " + res.status + ": " + ((cuerpoError.error && cuerpoError.error.message) || "sin detalle");
    return json({ error: "No pudimos buscar negocios cercanos. Intenta de nuevo.", detalle }, 502);
  }
  const datos = await res.json().catch(() => ({}));
  const resultados = (datos.places || []).slice(0, 10).map((p) => ({
    place_id: p.id,
    nombre: p.displayName && p.displayName.text ? p.displayName.text : "",
    direccion: p.formattedAddress || "",
    enlace_resena: "https://search.google.com/local/writereview?placeid=" + encodeURIComponent(p.id),
  })).filter((r) => r.place_id && r.nombre);
  return json({ resultados });
}

// ---------- Pruebas (vendedor): 30 min como máximo, sin cobro ----------
const PRUEBAS_SIMULTANEAS = 2;
const PRUEBAS_DIA = { nuevo: 15, confianza: 50 };

async function enVentaPendiente(env, folio) {
  return env.DB.prepare(
    "SELECT 1 AS x FROM venta_folios vf JOIN ventas v ON v.id = vf.venta_id WHERE vf.folio = ? AND v.estado IN ('pendiente','rev') LIMIT 1"
  ).bind(folio).first();
}

async function iniciarPrueba(request, env, vendedor) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);
  const folio = String(body.folio || "").trim().toUpperCase();
  if (!FOLIO_RE.test(folio)) return json({ error: "Folio inválido" }, 400);
  const negocio = limpiarTexto(body.negocio, 120);
  if (!negocio) return json({ error: "Elige el negocio para la prueba" }, 400);
  if (!esUrlResena(body.url_resena)) return json({ error: "El enlace de reseña debe ser de Google (https)" }, 400);

  const cfg = await leerConfig(env);
  await aplicarVencimientos(env, "sistema", null, cfg.prueba_minutos);

  const v = await env.DB.prepare("SELECT nivel FROM vendedores WHERE id = ? AND estado = 'activo'").bind(vendedor.id).first();
  if (!v) return json({ error: "Vendedor no válido o inactivo" }, 400);
  const adeudo = await env.DB.prepare("SELECT 1 AS x FROM ventas WHERE vendedor_id = ? AND impago = 1 AND estado <> 'anulada' LIMIT 1").bind(vendedor.id).first();
  if (adeudo) return json({ error: "Tienes un adeudo por impago; no puedes hacer pruebas" }, 409);

  const d = await env.DB.prepare("SELECT estado, vendedor_id FROM folios WHERE folio = ?").bind(folio).first();
  if (!d) return json({ error: "El folio no existe" }, 404);
  if (d.vendedor_id !== vendedor.id) return json({ error: "Ese display no está asignado a ti" }, 409);
  if (d.estado !== "libre") return json({ error: "Solo puedes probar un display libre" }, 409);
  if (await enVentaPendiente(env, folio)) return json({ error: "Ese display ya está en una venta pendiente" }, 409);

  const activas = await env.DB.prepare("SELECT COUNT(*) AS n FROM folios WHERE vendedor_id = ? AND estado = 'prueba'").bind(vendedor.id).first();
  if (Number(activas.n) >= PRUEBAS_SIMULTANEAS) {
    return json({ error: `Ya tienes ${PRUEBAS_SIMULTANEAS} pruebas activas. Termina una para empezar otra.` }, 409);
  }
  const limite = PRUEBAS_DIA[v.nivel === "confianza" ? "confianza" : "nuevo"];
  const hoy = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM auditoria_estados WHERE cambiado_por = ? AND estado_nuevo = 'prueba' AND date(fecha, '-6 hours') = date('now', '-6 hours')"
  ).bind("vendedor:" + vendedor.id).first();
  if (Number(hoy.n) >= limite) return json({ error: `Ya usaste tus ${limite} pruebas de hoy. Se renuevan mañana.` }, 409);

  const up = await env.DB.prepare(
    "UPDATE folios SET estado = 'prueba', prueba_inicio = CURRENT_TIMESTAMP, url_destino = ?, negocio_asignado = ?, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'libre' AND vendedor_id = ?"
  ).bind(body.url_resena, negocio, folio, vendedor.id).run();
  if (!up.meta || up.meta.changes !== 1) return json({ error: "El display ya no está libre" }, 409);
  await env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'libre', 'prueba', ?)")
    .bind(folio, "vendedor:" + vendedor.id).run();
  return json({ success: true, folio, minutos: cfg.prueba_minutos });
}

async function terminarPrueba(env, vendedor, folio) {
  await aplicarVencimientos(env, "sistema", folio, (await leerConfig(env)).prueba_minutos);
  const d = await env.DB.prepare("SELECT estado, vendedor_id FROM folios WHERE folio = ?").bind(folio).first();
  if (!d || d.vendedor_id !== vendedor.id) return json({ error: "Display no encontrado" }, 404);
  if (d.estado !== "prueba") return json({ error: "Ese display ya no está en prueba" }, 409);
  if (await enVentaPendiente(env, folio)) return json({ error: "Tiene una venta pendiente; cóbrala o anúlala antes" }, 409);
  const up = await env.DB.prepare(
    "UPDATE folios SET estado = 'libre', prueba_inicio = NULL, negocio_asignado = NULL, url_destino = NULL, updated_at = CURRENT_TIMESTAMP WHERE folio = ? AND estado = 'prueba' AND vendedor_id = ?"
  ).bind(folio, vendedor.id).run();
  if (!up.meta || up.meta.changes !== 1) return json({ error: "No se pudo terminar la prueba" }, 409);
  await env.DB.prepare("INSERT INTO auditoria_estados (folio, estado_anterior, estado_nuevo, cambiado_por) VALUES (?, 'prueba', 'libre', ?)")
    .bind(folio, "vendedor:" + vendedor.id).run();
  return json({ success: true, folio });
}

async function vendedorDisplays(env, vendedor) {
  const cfg = await leerConfig(env);
  await aplicarVencimientos(env, "sistema", null, cfg.prueba_minutos);
  const { results } = await env.DB.prepare(
    "SELECT folio, estado, negocio_asignado, prueba_inicio, url_destino, direccion, (SELECT COUNT(*) FROM escaneos e WHERE e.folio = folios.folio AND e.contado = 1 AND e.created_at >= datetime('now', '-7 days')) AS escaneos_7d, (SELECT v.id FROM venta_folios vf JOIN ventas v ON v.id = vf.venta_id WHERE vf.folio = folios.folio AND v.estado NOT IN ('anulada', 'rechazada') ORDER BY v.created_at DESC LIMIT 1) AS venta_id, (SELECT v.estado FROM venta_folios vf JOIN ventas v ON v.id = vf.venta_id WHERE vf.folio = folios.folio AND v.estado NOT IN ('anulada', 'rechazada') ORDER BY v.created_at DESC LIMIT 1) AS venta_estado FROM folios WHERE vendedor_id = ? ORDER BY folio"
  ).bind(vendedor.id).all();
  const ahora = Date.now();
  const displays = results.map((d) => {
    let minutos = null;
    if (d.estado === "prueba" && d.prueba_inicio) {
      const inicio = Date.parse(d.prueba_inicio.replace(" ", "T") + "Z");
      minutos = Math.max(0, Math.ceil(cfg.prueba_minutos - (ahora - inicio) / 60000));
    }
    return {
      folio: d.folio,
      estado: d.estado,
      negocio_asignado: d.negocio_asignado,
      prueba_min_restantes: minutos,
      url_destino: d.url_destino || null,
      direccion: d.direccion || null,
      escaneos_7d: Number(d.escaneos_7d) || 0,
      venta_id: d.venta_id || null,
      venta_estado: d.venta_estado || null,
    };
  });
  return json({ displays });
}

async function vendedorDesempeno(env, vendedor) {
  const cfg = await leerConfig(env);
  const entregados = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM venta_folios vf JOIN ventas v ON v.id = vf.venta_id WHERE v.vendedor_id = ? AND v.estado = 'entregada' AND v.entregada_at >= ?"
  ).bind(vendedor.id, inicioMesMX()).first();
  const sinEntregar = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM venta_folios vf JOIN ventas v ON v.id = vf.venta_id WHERE v.vendedor_id = ? AND v.estado IN ('pendiente','rev','cobrada')"
  ).bind(vendedor.id).first();
  const escaneos = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM escaneos e JOIN folios f ON f.folio = e.folio WHERE f.vendedor_id = ? AND e.contado = 1 AND e.created_at >= datetime('now', '-7 days')"
  ).bind(vendedor.id).first();
  const conteo = await env.DB.prepare(
    "SELECT SUM(CASE WHEN estado = 'activo' THEN 1 ELSE 0 END) AS activos, SUM(CASE WHEN estado = 'libre' THEN 1 ELSE 0 END) AS libres FROM folios WHERE vendedor_id = ?"
  ).bind(vendedor.id).first();
  return json({
    entregados_mes: Number(entregados.n) || 0,
    sin_entregar: Number(sinEntregar.n) || 0,
    escaneos_7d: Number(escaneos.n) || 0,
    activos: Number(conteo.activos) || 0,
    libres: Number(conteo.libres) || 0,
    comision_display: cfg.comision_display,
  });
}

async function vendedorSolicitudes(env, vendedor) {
  const { results } = await env.DB.prepare(
    "SELECT id, tipo, folio, venta_id, estado, nuevo_negocio, motivo_rechazo, created_at, resolved_at, (resuelto_por = 'directo') AS directo FROM solicitudes WHERE vendedor_id = ? ORDER BY created_at DESC LIMIT 200"
  ).bind(vendedor.id).all();
  return json({ solicitudes: results });
}

// Rating y número de reseñas del negocio en Google (Places API). Cachea 24 h con la Cache API.
// Devuelve null si no hay place_id, si falla Google o si no hay clave; el panel simplemente no muestra la fila.
async function ratingGoogle(env, urlDestino) {
  let placeId = null;
  try { placeId = new URL(urlDestino || "").searchParams.get("placeid"); } catch (_) { return null; }
  return ratingPorPlaceId(env, placeId);
}

async function ratingPorPlaceId(env, placeId) {
  if (!placeId || !/^[A-Za-z0-9_-]{5,200}$/.test(placeId) || !env.GOOGLE_PLACES_KEY) return null;
  const clave = new Request("https://cache.interno/places3/" + encodeURIComponent(placeId)); // v53: clave nueva; descarta fichas guardadas con foto nula por el límite de 300 caracteres
  try {
    const hit = await caches.default.match(clave);
    if (hit) return await hit.json();
  } catch (_) {}
  try {
    const res = await fetch("https://places.googleapis.com/v1/places/" + encodeURIComponent(placeId), {
      headers: { "X-Goog-Api-Key": env.GOOGLE_PLACES_KEY, "X-Goog-FieldMask": "rating,userRatingCount,photos.name" },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    const datos = await res.json().catch(() => null);
    if (!datos || typeof datos.rating !== "number") return null;
    const foto = Array.isArray(datos.photos) && datos.photos[0] && typeof datos.photos[0].name === "string" ? datos.photos[0].name : null;
    const dato = { rating: datos.rating, total_resenas: Number(datos.userRatingCount) || 0, foto: foto && /^places\/[A-Za-z0-9_-]{5,200}\/photos\/[A-Za-z0-9_-]{5,2000}$/.test(foto) ? foto : null };
    try {
      await caches.default.put(clave, new Response(JSON.stringify(dato), { headers: { "Content-Type": "application/json", "Cache-Control": "max-age=86400" } }));
    } catch (_) {}
    return dato;
  } catch (_) {
    return null;
  }
}

// Foto del negocio (Places API, Place Photos). Se pide una vez y se cachea 24 h; el panel la muestra en miniatura.
// La clave nunca sale del Worker: el navegador solo recibe la imagen.
async function fotoGoogle(env, ref) {
  if (!/^places\/[A-Za-z0-9_-]{5,200}\/photos\/[A-Za-z0-9_-]{5,2000}$/.test(ref) || !env.GOOGLE_PLACES_KEY) return json({ error: "Foto no disponible" }, 404);
  const clave = new Request("https://cache.interno/foto/" + encodeURIComponent(ref));
  try {
    const hit = await caches.default.match(clave);
    if (hit) return hit;
  } catch (_) {}
  try {
    const res = await fetch("https://places.googleapis.com/v1/" + ref + "/media?maxWidthPx=160&maxHeightPx=160", {
      headers: { "X-Goog-Api-Key": env.GOOGLE_PLACES_KEY },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok || !(res.headers.get("Content-Type") || "").startsWith("image/")) return json({ error: "Foto no disponible" }, 404);
    const r = new Response(res.body, { headers: { "Content-Type": res.headers.get("Content-Type"), "Cache-Control": "private, max-age=86400" } });
    try { await caches.default.put(clave, r.clone()); } catch (_) {}
    return r;
  } catch (_) {
    return json({ error: "Foto no disponible" }, 404);
  }
}

// Datos de Bien Visto para transferir. Viven en la tabla datos_pago como TEXTO (una CLABE no es un número:
// como número pierde el cero inicial). El banco sale de los 3 primeros dígitos de la CLABE.
async function leerDatosPago(env) {
  try {
    const { results } = await env.DB.prepare("SELECT clave, valor, updated_by, updated_at FROM datos_pago").all();
    const m = Object.fromEntries(results.map((r) => [r.clave, r]));
    return {
      titular: m.titular ? m.titular.valor : null,
      clabe: m.clabe ? m.clabe.valor : null,
      cuenta: m.cuenta ? m.cuenta.valor : null,
      actualizado_por: m.clabe ? m.clabe.updated_by : null,
      actualizado: m.clabe ? m.clabe.updated_at : null,
    };
  } catch (err) {
    console.error("datos_pago no disponible", err);
    return { titular: null, clabe: null, cuenta: null, actualizado_por: null, actualizado: null };
  }
}

async function vendedorDatosPago(env) {
  const d = await leerDatosPago(env);
  if (!d.titular || !d.clabe || !BANCOS_CLABE[d.clabe.slice(0, 3)]) {
    return json({ error: "Los datos para transferir no están configurados. Pídelos a Bien Visto." }, 404);
  }
  return json({ titular: d.titular, banco: BANCOS_CLABE[d.clabe.slice(0, 3)], clabe: d.clabe, cuenta: d.cuenta || null });
}

async function leerDatosPagoAdmin(env) {
  const d = await leerDatosPago(env);
  return json({ ...d, banco: d.clabe ? BANCOS_CLABE[d.clabe.slice(0, 3)] || null : null, clabe_valida: !!d.clabe && /^\d{18}$/.test(d.clabe) && digitoClabe(d.clabe) === Number(d.clabe[17]) });
}

async function guardarDatosPago(request, env, usuario) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);
  const titular = limpiarTexto(body.titular, 120);
  if (!titular || titular.length < 5) return json({ error: "Escribe el nombre del titular, tal como aparece en el banco." }, 400);
  const clabe = String(body.clabe || "").replace(/[\s-]/g, "");
  if (!/^\d{18}$/.test(clabe)) return json({ error: "La CLABE son 18 dígitos, incluidos los ceros del inicio." }, 400);
  if (!BANCOS_CLABE[clabe.slice(0, 3)]) return json({ error: "Los primeros 3 dígitos no son de un banco reconocido." }, 400);
  if (digitoClabe(clabe) !== Number(clabe[17])) return json({ error: "El último dígito no coincide: revisa la CLABE contra tu app del banco." }, 400);
  const cuenta = String(body.cuenta || "").replace(/\s/g, "");
  if (cuenta && !/^\d{8,11}$/.test(cuenta)) return json({ error: "El número de cuenta debe tener entre 8 y 11 dígitos." }, 400);
  const guardar = (k, v) =>
    env.DB.prepare("INSERT INTO datos_pago (clave, valor, updated_by, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP").bind(k, v, usuario);
  const stmts = [guardar("titular", titular), guardar("clabe", clabe)];
  stmts.push(cuenta ? guardar("cuenta", cuenta) : env.DB.prepare("DELETE FROM datos_pago WHERE clave = 'cuenta'"));
  stmts.push(env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Actualizó los datos de pago de Bien Visto (CLABE terminación ${clabe.slice(-4)})`));
  await env.DB.batch(stmts);
  return leerDatosPagoAdmin(env);
}

async function vendedorHistorial(env, vendedor, folio) {
  const propio = await env.DB.prepare("SELECT folio, url_destino FROM folios WHERE folio = ? AND vendedor_id = ?").bind(folio, vendedor.id).first();
  if (!propio) return json({ error: "No encontramos ese display en tu inventario." }, 404);
  const { results: estados } = await env.DB.prepare(
    "SELECT fecha, estado_anterior, estado_nuevo FROM auditoria_estados WHERE folio = ? AND estado_anterior IS NOT NULL ORDER BY fecha DESC LIMIT 100"
  ).bind(folio).all();
  const { results: solicitudes } = await env.DB.prepare(
    "SELECT tipo, estado, created_at, resolved_at, motivo_rechazo FROM solicitudes WHERE folio = ? AND vendedor_id = ? ORDER BY created_at DESC LIMIT 50"
  ).bind(folio, vendedor.id).all();
  // Escaneos de los últimos 7 días (hora de México, UTC-6), con 0 en los días sin escaneos.
  const hoyMx = new Date(Date.now() - 6 * 3600 * 1000);
  const dias = [];
  for (let i = 6; i >= 0; i--) dias.push(new Date(hoyMx.getTime() - i * 86400000).toISOString().slice(0, 10));
  const { results: porDia } = await env.DB.prepare(
    "SELECT date(created_at, '-6 hours') AS dia, COUNT(*) AS n FROM escaneos WHERE folio = ? AND contado = 1 AND created_at >= datetime('now', '-8 days') GROUP BY dia"
  ).bind(folio).all();
  const mapa = Object.fromEntries(porDia.map((r) => [r.dia, Number(r.n) || 0]));
  const escaneos_por_dia = dias.map((dia) => ({ dia, n: mapa[dia] || 0 }));
  const google = await ratingGoogle(env, propio.url_destino);
  return json({ estados, solicitudes, escaneos_por_dia, google });
}

async function vendedorSaldo(env, vendedor) {
  const cfg = await leerConfig(env);
  // Custodia = saldo por entregar (ventas cobradas). Lo que está en revisión se informa aparte y cuenta para el tope.
  const custodia = await saldoVendedor(env, vendedor.id);
  const exposicion = await exposicionVendedor(env, vendedor.id);
  const plazo = await env.DB.prepare(
    "SELECT MIN(COALESCE(fecha_cobro, created_at)) AS mas_antigua FROM ventas WHERE vendedor_id = ? AND estado IN ('cobrada','entregada') AND a_entregar - COALESCE(entregado, 0) > 0.001"
  ).bind(vendedor.id).first();
  const impago = await env.DB.prepare(
    "SELECT 1 AS x FROM ventas WHERE vendedor_id = ? AND impago = 1 AND estado <> 'anulada' LIMIT 1"
  ).bind(vendedor.id).first();
  let horasRestantes = null;
  let vencido = false;
  if (plazo && plazo.mas_antigua) {
    const transcurridas = (Date.now() - Date.parse(plazo.mas_antigua.replace(" ", "T") + "Z")) / 3600000;
    vencido = transcurridas >= cfg.horas;
    horasRestantes = Math.max(0, Math.floor(cfg.horas - transcurridas));
  }
  const tope = await topeVendedor(env, vendedor.id, cfg);
  return json({
    custodia,
    en_revision: Math.round((exposicion - custodia) * 100) / 100,
    tope,
    horas_restantes: horasRestantes,
    plazo_vencido: vencido,
    impago: !!impago,
  });
}

async function vendedorClientes(env, vendedor) {
  // Clientes previos del vendedor, tomados de sus ventas. Solo nombre y negocio: nunca WhatsApp ni correo.
  const { results } = await env.DB.prepare(
    "SELECT contacto AS nombre, negocio AS empresa, MAX(created_at) AS ultima FROM ventas WHERE vendedor_id = ? AND estado <> 'anulada' AND contacto IS NOT NULL AND TRIM(contacto) <> '' GROUP BY contacto, negocio ORDER BY ultima DESC LIMIT 200"
  ).bind(vendedor.id).all();
  return json({ clientes: results.map((c) => ({ nombre: c.nombre, empresa: c.empresa })) });
}

async function vendedorVentas(env, vendedor) {
  const { results } = await env.DB.prepare(
    "SELECT v.id, v.negocio, v.direccion, v.contacto, v.whatsapp, v.correo, v.total, v.a_entregar, v.entregado, v.estado, v.impago, v.created_at, v.fecha_cobro, (SELECT COUNT(*) FROM venta_folios vf WHERE vf.venta_id = v.id) AS displays, (SELECT f.url_destino FROM venta_folios vf JOIN folios f ON f.folio = vf.folio WHERE vf.venta_id = v.id AND f.url_destino IS NOT NULL LIMIT 1) AS url_destino FROM ventas v WHERE v.vendedor_id = ? ORDER BY v.created_at DESC LIMIT 100"
  ).bind(vendedor.id).all();
  return json({ ventas: results });
}

// ---------- Avisos de entrega (vendedor -> Bien Visto) ----------
// El vendedor avisa que entregó. No cambia el saldo: Bien Visto lo confirma y crea el corte.
// Tabla requerida (migración): avisos_entrega (ver SQL en la nota de despliegue).
const AVISO_COMPROBANTE_TIPOS = ["image/jpeg", "image/png", "image/webp", "application/pdf"];

// Saldo por entregar: lo que el vendedor ya cobró (venta cobrada, o entregada con resto) y aún no entrega.
// Es la única definición de saldo: la usan Mi saldo, los avisos, los cortes y el panel.
async function saldoVendedor(env, vendedor) {
  const fila = await env.DB.prepare(
    "SELECT COALESCE(SUM(a_entregar - COALESCE(entregado, 0)), 0) AS monto FROM ventas WHERE vendedor_id = ? AND estado IN ('cobrada','entregada') AND a_entregar - COALESCE(entregado, 0) > 0.001"
  ).bind(vendedor).first();
  return Math.round((Number(fila && fila.monto) || 0) * 100) / 100;
}

// Exposición para el tope: el saldo más las ventas en revisión (el vendedor avisó que ya cobró).
// "excluir" deja fuera una venta, para sumarla aparte al revisar su propio cobro.
async function exposicionVendedor(env, vendedor, excluir = null) {
  const saldo = await saldoVendedor(env, vendedor);
  const rev = await env.DB.prepare(
    "SELECT COALESCE(SUM(a_entregar), 0) AS monto FROM ventas WHERE vendedor_id = ? AND estado = 'rev' AND id <> ?"
  ).bind(vendedor, excluir || "").first();
  return Math.round((saldo + (Number(rev && rev.monto) || 0)) * 100) / 100;
}

async function topeVendedor(env, vendedor, cfg) {
  const r = await env.DB.prepare("SELECT nivel FROM vendedores WHERE id = ?").bind(vendedor).first();
  return r && r.nivel === "confianza" ? Number(cfg.tope_confianza) : Number(cfg.tope_nuevo);
}

// Lo que el vendedor ve de sus avisos: el pendiente y los últimos resueltos (con el mensaje de Bien Visto si lo rechazó).
async function listarAvisosVendedor(env, vendedor) {
  const { results } = await env.DB.prepare(
    "SELECT id, monto, metodo, referencia, estado, motivo, created_at, resuelto_at FROM avisos_entrega WHERE vendedor_id = ? ORDER BY created_at DESC LIMIT 10"
  ).bind(vendedor.id).all();
  return json({ avisos: results });
}

async function crearAvisoEntrega(request, env, vendedor) {
  const body = await leerJson(request);
  if (body === null) return json({ error: "JSON inválido" }, 400);

  const monto = Math.round(Number(body.monto) * 100) / 100;
  if (!Number.isFinite(monto) || monto <= 0) return json({ error: "El monto debe ser mayor que cero" }, 400);
  if (!METODOS.includes(body.metodo)) return json({ error: "metodo no válido" }, 400);
  const referencia = body.metodo === "transferencia" ? (limpiarTexto(body.referencia, 100) || "").toUpperCase().replace(/\s/g, "") || null : null;
  if (body.metodo === "transferencia" && !referencia) return json({ error: "Escribe la clave de rastreo de la transferencia" }, 400);

  const saldo = await saldoVendedor(env, vendedor.id);

  // Lo que ya está en revisión no se puede volver a avisar; solo lo que queda sin avisar.
  const enRevision = await env.DB.prepare("SELECT COALESCE(SUM(monto), 0) AS monto FROM avisos_entrega WHERE vendedor_id = ? AND estado IN ('pendiente','confirmando')").bind(vendedor.id).first();
  const disponible = Math.round((saldo - (Number(enRevision && enRevision.monto) || 0)) * 100) / 100;
  if (disponible <= 0.001) return json({ error: "Ya avisaste todo lo que debes entregar. Espera la revisión de Bien Visto." }, 409);
  if (monto > disponible + 0.001) return json({ error: "Solo te quedan " + fmtMXN(disponible) + " por avisar." }, 409);

  const id = "AE-" + crypto.randomUUID().replace(/-/g, "").slice(0, 8);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO avisos_entrega (id, vendedor_id, monto, metodo, referencia, estado) VALUES (?, ?, ?, ?, ?, 'pendiente')").bind(id, vendedor.id, monto, body.metodo, referencia),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind("vendedor:" + vendedor.id, "Aviso de entrega " + id + " por " + monto + " (" + body.metodo + ")"),
  ]);
  return json({ success: true, id, monto, metodo: body.metodo }, 201);
}

async function subirComprobanteAviso(request, env, vendedor, id) {
  if (!env.COMPROBANTES) return json({ error: "Almacenamiento de comprobantes no configurado" }, 503);
  const aviso = await env.DB.prepare("SELECT id, estado, comprobante_key FROM avisos_entrega WHERE id = ? AND vendedor_id = ?").bind(id, vendedor.id).first();
  if (!aviso) return json({ error: "Aviso no encontrado" }, 404);
  if (aviso.estado !== "pendiente") return json({ error: "El aviso ya no está pendiente" }, 409);

  const tipo = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  if (!AVISO_COMPROBANTE_TIPOS.includes(tipo)) return json({ error: "Tipo de archivo no permitido (jpg, png, webp o pdf)" }, 415);
  const bytes = await request.arrayBuffer();
  if (bytes.byteLength === 0) return json({ error: "Archivo vacío" }, 400);
  if (bytes.byteLength > COMPROBANTE_MAX) return json({ error: "El archivo supera 5 MB" }, 413);

  const key = `avisos/${id}/${crypto.randomUUID()}`;
  await env.COMPROBANTES.put(key, bytes, { httpMetadata: { contentType: tipo } });
  await env.DB.prepare("UPDATE avisos_entrega SET comprobante_key = ? WHERE id = ?").bind(key, id).run();
  if (aviso.comprobante_key) {
    try { await env.COMPROBANTES.delete(aviso.comprobante_key); } catch (err) { console.error("no se pudo borrar comprobante anterior", err); }
  }
  return json({ success: true, id, comprobante_key: key }, 201);
}

// ---------- Avisos de entrega: revisión en admin ----------
async function listarAvisosEntrega(env) {
  const { results } = await env.DB.prepare(
    `SELECT a.id, a.vendedor_id, v.nombre AS vendedor, a.monto, a.metodo, a.referencia, a.estado,
            a.comprobante_key IS NOT NULL AS tiene_comprobante, a.created_at
     FROM avisos_entrega a JOIN vendedores v ON v.id = a.vendedor_id
     ORDER BY CASE a.estado WHEN 'pendiente' THEN 0 ELSE 1 END, a.created_at DESC LIMIT 100`
  ).all();
  return json({ avisos: results });
}

async function leerComprobanteAviso(env, id) {
  if (!env.COMPROBANTES) return json({ error: "Almacenamiento de comprobantes no configurado" }, 503);
  const aviso = await env.DB.prepare("SELECT comprobante_key FROM avisos_entrega WHERE id = ?").bind(id).first();
  if (!aviso) return json({ error: "Aviso no encontrado" }, 404);
  if (!aviso.comprobante_key) return json({ error: "El aviso no tiene comprobante" }, 404);
  const obj = await env.COMPROBANTES.get(aviso.comprobante_key);
  if (!obj) return json({ error: "Comprobante no encontrado" }, 404);
  return new Response(obj.body, {
    headers: {
      "content-type": obj.httpMetadata?.contentType || "application/octet-stream",
      "cache-control": "private, no-store",
    },
  });
}

// Confirmar = crear el corte con los datos del aviso y marcarlo confirmado, en un solo batch.
// Primero se aparta el aviso (pendiente -> confirmando): un doble clic o dos personas a la vez no crean dos cortes.
async function confirmarAviso(env, id, usuario) {
  const aviso = await env.DB.prepare("SELECT id, vendedor_id, monto, metodo, referencia, estado FROM avisos_entrega WHERE id = ?").bind(id).first();
  if (!aviso) return json({ error: "Aviso no encontrado" }, 404);
  if (aviso.estado !== "pendiente") return json({ error: "El aviso ya no está pendiente" }, 409);

  const apartado = await env.DB.prepare("UPDATE avisos_entrega SET estado = 'confirmando' WHERE id = ? AND estado = 'pendiente'").bind(id).run();
  if (!apartado.meta || apartado.meta.changes !== 1) return json({ error: "El aviso ya no está pendiente" }, 409);
  const regresar = () => env.DB.prepare("UPDATE avisos_entrega SET estado = 'pendiente' WHERE id = ? AND estado = 'confirmando'").bind(id).run();

  let plan;
  try {
    plan = await planCorte(env, { vendedor_id: aviso.vendedor_id, monto: aviso.monto, ajuste: 0, metodo: aviso.metodo, referencia: aviso.referencia }, usuario);
  } catch (err) {
    await regresar();
    throw err;
  }
  if (plan.error) {
    await regresar();
    return plan.error;
  }
  try {
    await env.DB.batch([
      ...plan.stmts,
      env.DB.prepare("UPDATE avisos_entrega SET estado = 'confirmado', resuelto_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'confirmando'").bind(id),
      env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Aviso ${id} confirmado como corte ${plan.id}`),
    ]);
  } catch (err) {
    await regresar();
    throw err;
  }
  return json({ success: true, id, corte_id: plan.id, saldo_restante: plan.saldo_restante, subio_nivel: plan.subio }, 201);
}

async function rechazarAviso(request, env, id, usuario) {
  const body = (await leerJson(request)) || {};
  const motivo = limpiarTexto(body.motivo, 300);
  if (!motivo) return json({ error: "Escribe el motivo del rechazo" }, 400);
  const aviso = await env.DB.prepare("SELECT estado FROM avisos_entrega WHERE id = ?").bind(id).first();
  if (!aviso) return json({ error: "Aviso no encontrado" }, 404);
  if (aviso.estado !== "pendiente") return json({ error: "El aviso ya no está pendiente" }, 409);
  await env.DB.batch([
    env.DB.prepare("UPDATE avisos_entrega SET estado = 'rechazado', motivo = ?, resuelto_at = CURRENT_TIMESTAMP WHERE id = ? AND estado = 'pendiente'").bind(motivo, id),
    env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)").bind(usuario, `Aviso ${id} rechazado: ${motivo}`),
  ]);
  return json({ success: true, id });
}

// HTML de la app de vendedores tal como se publica. Solo lo pide el panel de admin (ruta protegida por Access).
const APP_VENDEDOR_URL = "https://vendedores.bienvisto.com.mx/";

async function appVendedorPublicada() {
  let r;
  try {
    r = await fetch(APP_VENDEDOR_URL, { headers: { Accept: "text/html" }, cf: { cacheTtl: 120, cacheEverything: true } });
  } catch (e) {
    return json({ error: "No se pudo contactar la app de vendedores" }, 502);
  }
  if (!r.ok) return json({ error: "La app de vendedores respondió " + r.status }, 502);
  const html = await r.text();
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(html)));
  const huella = Array.from(digest.slice(0, 6), (b) => b.toString(16).padStart(2, "0")).join("");
  return json({ html, huella, obtenida: new Date().toISOString() });
}

// Vista previa de admin: la ruta /api/admin/vista/:id/vendedor/* ejecuta la API del vendedor como si fuera ese vendedor.
// Solo la ruta admin crea estas peticiones internas; una petición pública no puede estar en este mapa.
const VISTA_INTERNA = new WeakMap();

async function vistaVendedor(request, env, url, usuario) {
  const m = url.pathname.match(/^\/api\/admin\/vista\/([^/]+)\/vendedor(\/.*)?$/);
  if (!m) return json({ error: "No encontrado" }, 404);
  const id = decodeURIComponent(m[1]);
  const existe = await env.DB.prepare("SELECT id FROM vendedores WHERE id = ?").bind(id).first();
  if (!existe) return json({ error: "Vendedor no encontrado" }, 404);
  const ruta = m[2] || "";
  if (ruta === "/yo") {
    await env.DB.prepare("INSERT INTO auditoria (usuario, accion, folio_afectado) VALUES (?, ?, NULL)")
      .bind(usuario, `Vista previa del vendedor ${id} abierta`).run();
  }
  const destino = new URL(url.toString());
  destino.hostname = VENDOR_HOST;
  destino.pathname = "/api/vendedor" + ruta;
  const interna = new Request(destino.toString(), { method: "GET" });
  VISTA_INTERNA.set(interna, { id });
  return handleVendedorApi(interna, env, destino);
}

async function sesionVendedor(request, env) {
  const vista = VISTA_INTERNA.get(request);
  if (vista) {
    const v = await env.DB.prepare("SELECT id, nombre FROM vendedores WHERE id = ?").bind(vista.id).first();
    return v ? { id: v.id, nombre: v.nombre } : null;
  }
  const token = leerCookie(request, COOKIE_SESION);
  if (!token) return null;
  const s = await env.DB.prepare(
    "SELECT s.vendedor_id AS id, s.expira_at, v.nombre FROM sesiones s JOIN vendedores v ON v.id = s.vendedor_id WHERE s.token_hash = ? AND v.estado = 'activo'"
  ).bind(await sha256(token)).first();
  if (!s || Date.parse(s.expira_at) <= Date.now()) return null;
  return { id: s.id, nombre: s.nombre };
}

async function enviarCodigo(env, correo, nombre, codigo) {
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "Bien Visto <vendedores@bienvisto.com.mx>",
        to: [correo],
        subject: `Tu código de acceso: ${codigo}`,
        text: `Hola ${nombre}, tu código de acceso es ${codigo}. Vence en ${CODIGO_VIGENCIA_MIN} minutos. Si no lo pediste, ignora este correo.`,
        html: `<p>Hola ${esc(nombre)},</p><p>Tu código de acceso es:</p><p style="font-size:24px;font-weight:bold;letter-spacing:4px">${esc(codigo)}</p><p>Vence en ${CODIGO_VIGENCIA_MIN} minutos. Si no lo pediste, ignora este correo.</p>`,
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

function normalizarCorreo(valor) {
  return typeof valor === "string" ? valor.trim().toLowerCase() : "";
}

function codigoAleatorio() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(n).padStart(6, "0");
}

function tokenAleatorio() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(texto) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(texto));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function leerCookie(request, nombre) {
  const cabecera = request.headers.get("Cookie") || "";
  for (const parte of cabecera.split(";")) {
    const [clave, ...resto] = parte.trim().split("=");
    if (clave === nombre) return resto.join("=") || null;
  }
  return null;
}

// ==========================================
// FORMULARIOS PÚBLICOS DEL SITIO (bienvisto.com.mx)
// ==========================================
// El sitio envía el formulario a este worker; aquí se valida y se manda por correo a contacto@.
// No se guarda en la base: el correo es el registro.
const CORREO_CONTACTO = "contacto@bienvisto.com.mx";
const REMITENTE_SITIO = "Sitio Bien Visto <sitio@bienvisto.com.mx>";
const ORIGENES_SITIO = ["https://bienvisto.com.mx", "https://www.bienvisto.com.mx"];
const MAX_FORMULARIO = 6 * 1024 * 1024;
const MAX_ARCHIVO = 5 * 1024 * 1024;
const TIPOS_ARCHIVO = { "application/pdf": "pdf", "image/png": "png", "image/jpeg": "jpg" };
const RFC_RE = /^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/;

// Campos aceptados por formulario: [nombre, etiqueta, obligatorio, máximo, validador opcional]
const FORMULARIOS = {
  factura: {
    asunto: (d) => `Solicitud de factura · ${d.rfc} · ${d.folio}`,
    responderA: (d) => d.correo,
    campos: [
      ["nombre", "Nombre o razón social", true, 200],
      ["rfc", "RFC", true, 13, (v) => RFC_RE.test(v) || "El RFC no tiene el formato correcto."],
      ["cp", "Código postal fiscal", true, 5, (v) => /^\d{5}$/.test(v) || "El código postal son 5 dígitos."],
      ["uso", "Uso del CFDI", true, 80],
      ["regimen", "Régimen fiscal", true, 120],
      ["folio", "Folio del display o número de recibo", true, 40],
      ["fecha", "Fecha de compra", false, 10],
      ["correo", "Correo para recibir la factura", true, 160, (v) => CORREO_RE.test(v) || "El correo no se ve bien."],
    ],
    archivo: ["constancia", "Constancia de situación fiscal", true],
  },
  queja: {
    asunto: (d) => `Queja · ${d.tema} · ${d.nombre}`,
    responderA: (d) => (CORREO_RE.test(d.contacto) ? d.contacto : null),
    campos: [
      ["nombre", "Nombre", true, 120],
      ["contacto", "Teléfono o correo", true, 160],
      ["tema", "Tema", true, 80],
      ["folio", "Folio del display", false, 40],
      ["fecha", "Cuándo pasó", false, 10],
      ["detalle", "Qué pasó", true, 4000, (v) => v.length >= 20 || "Cuéntanos con al menos 20 caracteres."],
    ],
  },
  vendedor: {
    asunto: (d) => `Solicitud de vendedor · ${d.nombre} · ${d.zona}`,
    responderA: (d) => d.correo,
    campos: [
      ["nombre", "Nombre completo", true, 120],
      ["whatsapp", "WhatsApp", true, 20, (v) => /^\d{10}$/.test(v.replace(/\D/g, "")) || "El WhatsApp son 10 dígitos."],
      ["correo", "Correo de su cuenta de Google", true, 160, (v) => CORREO_RE.test(v) || "El correo no se ve bien."],
      ["zona", "Ciudad o zona", true, 120],
      ["invito", "¿Quién lo invitó?", false, 120],
      ["acepta", "Aceptó aviso de privacidad y términos para vendedores", true, 2, (v) => v === "si" || "Falta aceptar el aviso de privacidad y los términos."],
    ],
  },
};

function corsSitio(request) {
  const origen = request.headers.get("Origin") || "";
  const h = { Vary: "Origin", "Cache-Control": "no-store", "X-Robots-Tag": "noindex" };
  if (ORIGENES_SITIO.includes(origen)) {
    h["Access-Control-Allow-Origin"] = origen;
    h["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    h["Access-Control-Allow-Headers"] = "Accept";
    h["Access-Control-Max-Age"] = "86400";
  }
  return h;
}

function jsonSitio(request, data, status = 200) {
  return Response.json(data, { status, headers: corsSitio(request) });
}

function base64DeBytes(bytes) {
  let bin = "";
  const paso = 0x8000;
  for (let i = 0; i < bytes.length; i += paso) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + paso));
  return btoa(bin);
}

// Acuse para quien pidió ser vendedor: mismo marco que los recibos.
function solicitudRecibidaCorreo(d) {
  const primer = String(d.nombre || "").trim().split(/\s+/)[0] || "";
  const saludo = (primer ? "Hola " + primer + ", recibimos" : "Recibimos") + " tu solicitud para vender con Bien Visto.";
  const cuerpo = "Está en revisión. Te escribiremos lo antes posible.";
  const texto = [saludo, cuerpo, "", d.nombre ? "Nombre: " + d.nombre : null, d.zona ? "Zona: " + d.zona : null, d.whatsapp ? "WhatsApp: " + d.whatsapp : null, "", "Si algún dato está mal, responde a este correo.", "Bien Visto · bienvisto.com.mx"].filter((x) => x !== null).join("\n");
  const fila = (k, v, ultima) =>
    '<tr><td width="140" valign="top" style="padding:12px 0;border-top:1px solid #DDE7E2;' + (ultima ? "border-bottom:1px solid #DDE7E2;" : "") + 'color:#5C7069;">' + esc(k) + '</td>' +
    '<td valign="top" style="padding:12px 0;border-top:1px solid #DDE7E2;' + (ultima ? "border-bottom:1px solid #DDE7E2;" : "") + '">' + esc(v) + '</td></tr>';
  const datos = [["Nombre", d.nombre], ["Zona", d.zona], ["WhatsApp", d.whatsapp]].filter(([, v]) => v);
  const filas = datos.map(([k, v], i) => fila(k, v, i === datos.length - 1)).join("");
  const html =
    '<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Solicitud recibida</title></head>' +
    '<body style="margin:0;padding:0;background:#F3F1EC;">' +
    '<div style="display:none;max-height:0;overflow:hidden;color:#F3F1EC;mso-hide:all;">Recibimos tu solicitud. Está en revisión y te escribiremos lo antes posible.</div>' +
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#F3F1EC" style="background:#F3F1EC;"><tr><td align="center" style="padding:24px 12px;">' +
    '<table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" bgcolor="#FFFFFF" style="width:600px;max-width:600px;background:#FFFFFF;">' +
    '<tr><td bgcolor="#FFFFFF" style="padding:28px 32px 24px 32px;border-bottom:1px solid #DDE7E2;font-family:Arial,Helvetica,sans-serif;">' +
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr>' +
    '<td valign="middle" align="left"><img src="cid:' + LOGO_CORREO_ID + '" width="200" height="44" alt="Bien Visto" style="display:block;border:0;outline:none;text-decoration:none;width:200px;height:44px;"></td>' +
    '<td valign="middle" align="right" style="font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:18px;color:#5C7069;">Solicitud de vendedor<br><span style="font-size:15px;font-weight:bold;color:#12302B;">Bien Visto</span></td>' +
    "</tr></table></td></tr>" +
    '<tr><td bgcolor="#FFFFFF" style="padding:32px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;">' +
    '<table role="presentation" cellspacing="0" cellpadding="0" border="0"><tr><td bgcolor="#E7F0EC" style="background:#E7F0EC;border-radius:14px;padding:5px 12px;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:18px;font-weight:bold;color:#0E6B5C;">En revisión</td></tr></table>' +
    '<p style="margin:16px 0 0 0;font-size:30px;line-height:36px;font-weight:bold;color:#12302B;">Recibimos tu solicitud</p></td></tr>' +
    '<tr><td bgcolor="#FFFFFF" style="padding:20px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:24px;color:#12302B;"><p style="margin:0;">' + esc(saludo) + '</p><p style="margin:12px 0 0 0;">Está en revisión y te escribiremos <b>lo antes posible</b>.</p></td></tr>' +
    (filas ? '<tr><td bgcolor="#FFFFFF" style="padding:28px 32px 0 32px;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:22px;color:#12302B;">' + filas + "</table></td></tr>" : "") +
    '<tr><td bgcolor="#FFFFFF" style="padding:20px 32px 32px 32px;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:21px;color:#5C7069;">Si algún dato está mal, responde a este correo.</td></tr>' +
    '<tr><td bgcolor="#0E6B5C" style="padding:24px 32px;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#FBF6EC;">' +
    '<p style="margin:0;color:#FBF6EC;"><a href="https://bienvisto.com.mx/privacidad" style="color:#FBF6EC;text-decoration:underline;">Aviso de privacidad</a> &nbsp;|&nbsp; <a href="https://bienvisto.com.mx/terminos-clientes" style="color:#FBF6EC;text-decoration:underline;">Términos</a></p>' +
    '<p style="margin:8px 0 0 0;color:#E7F0EC;">Bien Visto · bienvisto.com.mx</p></td></tr>' +
    '<tr><td bgcolor="#F2A71B" style="font-size:0;line-height:4px;height:4px;">&nbsp;</td></tr>' +
    "</table></td></tr></table></body></html>";
  return {
    asunto: "Recibimos tu solicitud · Bien Visto",
    texto,
    html,
    adjuntos: [{ filename: "logo-bienvisto.png", content: LOGO_CORREO_B64, content_type: "image/png", content_id: LOGO_CORREO_ID }],
  };
}

async function handleFormulario(request, env, url) {
  const tipo = url.pathname.slice("/api/formularios/".length);
  const def = Object.prototype.hasOwnProperty.call(FORMULARIOS, tipo) ? FORMULARIOS[tipo] : null;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsSitio(request) });
  if (!def) return jsonSitio(request, { error: "No encontrado" }, 404);
  if (request.method !== "POST") return jsonSitio(request, { error: "Método no permitido" }, 405);
  if (!ORIGENES_SITIO.includes(request.headers.get("Origin") || "")) {
    return jsonSitio(request, { error: "Origen no permitido" }, 403);
  }
  const largo = Number(request.headers.get("Content-Length") || 0);
  if (largo > MAX_FORMULARIO) return jsonSitio(request, { error: "El envío es demasiado grande. El archivo debe pesar máximo 5 MB." }, 413);

  let fd;
  try { fd = await request.formData(); } catch { return jsonSitio(request, { error: "No pudimos leer el formulario." }, 400); }

  // Trampa para robots: campo oculto que una persona deja vacío.
  if (String(fd.get("sitio_web") || "").trim()) return jsonSitio(request, { ok: true });

  const datos = {};
  for (const [campo, etiqueta, obligatorio, max, validar] of def.campos) {
    let v = fd.get(campo);
    v = typeof v === "string" ? v.trim().replace(/\r\n/g, "\n") : "";
    if (campo === "rfc") v = v.toUpperCase().replace(/\s+/g, "");
    if (campo === "correo") v = v.toLowerCase();
    if (!v) {
      if (obligatorio) return jsonSitio(request, { error: `Falta: ${etiqueta}.` }, 400);
      continue;
    }
    if (v.length > max) return jsonSitio(request, { error: `${etiqueta}: el texto es demasiado largo.` }, 400);
    if (validar) {
      const r = validar(v);
      if (r !== true) return jsonSitio(request, { error: r }, 400);
    }
    datos[campo] = v;
  }

  const adjuntos = [];
  if (def.archivo) {
    const [campo, etiqueta, obligatorio] = def.archivo;
    const f = fd.get(campo);
    if (!f || typeof f === "string" || !f.size) {
      if (obligatorio) return jsonSitio(request, { error: `Falta: ${etiqueta}.` }, 400);
    } else {
      const ext = TIPOS_ARCHIVO[f.type];
      if (!ext) return jsonSitio(request, { error: "Sube la constancia en PDF, PNG o JPG." }, 400);
      if (f.size > MAX_ARCHIVO) return jsonSitio(request, { error: "La constancia debe pesar máximo 5 MB." }, 413);
      const bytes = new Uint8Array(await f.arrayBuffer());
      const base = (datos.rfc || "constancia").replace(/[^A-Z0-9Ñ&]/gi, "");
      adjuntos.push({ filename: `constancia-${base}.${ext}`, content: base64DeBytes(bytes) });
    }
  }

  let alta = null;
  if (tipo === "vendedor") {
    alta = await registrarAltaVendedor(env, datos);
    // Ese correo ya tiene una solicitud pendiente: no se repite el aviso.
    if (alta && alta.repetida) return jsonSitio(request, { ok: true });
  }

  const filas = def.campos.filter(([c]) => datos[c]).map(([c, etiqueta]) => [etiqueta, datos[c]]);
  const cuando = new Date().toLocaleString("es-MX", { timeZone: "America/Mexico_City" });
  const texto = filas.map(([e, v]) => `${e}: ${v}`).join("\n") + `\n\nEnviado desde bienvisto.com.mx el ${cuando}.` + (adjuntos.length ? "\nLa constancia va adjunta." : "");
  const html = `<table style="border-collapse:collapse;font:15px/1.5 Arial,sans-serif">${filas.map(([e, v]) => `<tr><td style="padding:6px 12px 6px 0;color:#3F544E;vertical-align:top;white-space:nowrap"><b>${esc(e)}</b></td><td style="padding:6px 0;white-space:pre-wrap">${esc(v)}</td></tr>`).join("")}</table><p style="font:13px Arial,sans-serif;color:#6B897E">Enviado desde bienvisto.com.mx el ${esc(cuando)}.${adjuntos.length ? " La constancia va adjunta." : ""}</p>`;

  let textoCorreo = texto;
  let htmlCorreo = html;
  if (alta) {
    const panel = "https://" + ADMIN_HOST;
    const tel = String(datos.whatsapp || "").replace(/\D/g, "");
    const wa = tel.length === 10 ? "https://wa.me/52" + tel : "";
    textoCorreo = texto + `\n\nRevísala y apruébala en el panel: ${panel}` + (wa ? `\nEscribirle por WhatsApp: ${wa}` : "");
    htmlCorreo = html + `<p style="font:15px Arial,sans-serif;margin-top:16px"><a href="${esc(panel)}" style="background:#0E6B5C;color:#fff;padding:10px 18px;border-radius:999px;text-decoration:none;font-weight:bold">Revisar en el panel</a>` + (wa ? ` &nbsp; <a href="${esc(wa)}" style="color:#0E6B5C;font-weight:bold">Escribirle por WhatsApp</a>` : "") + `</p>`;
  }

  const correo = {
    from: REMITENTE_SITIO,
    to: [CORREO_CONTACTO],
    subject: def.asunto(datos).slice(0, 180),
    text: textoCorreo,
    html: htmlCorreo,
  };
  const responder = def.responderA(datos);
  if (responder) correo.reply_to = responder;
  if (adjuntos.length) correo.attachments = adjuntos;

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(correo),
    });
    if (!res.ok) {
      console.log("formulario: Resend respondió " + res.status + " " + (await res.text()).slice(0, 300));
      return jsonSitio(request, { error: "No pudimos enviarlo en este momento. Escríbenos por WhatsApp." }, 502);
    }
  } catch (e) {
    console.log("formulario: error al enviar " + (e && e.message));
    return jsonSitio(request, { error: "No pudimos enviarlo en este momento. Escríbenos por WhatsApp." }, 502);
  }
  // Acuse al candidato. Si falla, solo se registra: la solicitud ya llegó.
  if (tipo === "vendedor" && datos.correo) {
    try {
      const a = solicitudRecibidaCorreo(datos);
      const r2 = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({ from: "Bien Visto <vendedores@bienvisto.com.mx>", to: [datos.correo], reply_to: CORREO_CONTACTO, subject: a.asunto, text: a.texto, html: a.html, attachments: a.adjuntos }),
        signal: AbortSignal.timeout(8000),
      });
      if (!r2.ok) console.log("formulario: acuse Resend " + r2.status + " " + (await r2.text().catch(() => "")).slice(0, 200));
    } catch (e) {
      console.log("formulario: error en acuse " + (e && e.message));
    }
  }
  return jsonSitio(request, { ok: true });
}

// Valores de Ajustes que se pueden mostrar al público. Sin datos internos ni de pago.
const CLAVES_PUBLICAS = ["precio_display", "comision_display", "promo_n", "promo_precio", "prueba_minutos", "recibo_min", "horas", "tope_nuevo", "tope_confianza", "lim_rep"];

async function configPublica(request, env) {
  const h = { "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=60", "X-Robots-Tag": "noindex" };
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...h, "Access-Control-Allow-Methods": "GET" } });
  if (request.method !== "GET" && request.method !== "HEAD") return Response.json({ error: "Método no permitido" }, { status: 405, headers: h });
  try {
    const c = await leerConfig(env);
    const out = {};
    for (const k of CLAVES_PUBLICAS) out[k] = Number(c[k]);
    return Response.json(out, { headers: h });
  } catch (e) {
    return Response.json({ error: "Configuración no disponible" }, { status: 503, headers: { ...h, "Cache-Control": "no-store" } });
  }
}
