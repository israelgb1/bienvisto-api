-- Migración 6: guarda las solicitudes de alta de vendedor que llegan del formulario de bienvisto.com.mx/vendedores.
-- Solo agrega una tabla y un índice; no toca datos existentes.
CREATE TABLE IF NOT EXISTS altas_vendedor (
  id TEXT PRIMARY KEY,
  nombre TEXT NOT NULL,
  whatsapp TEXT,
  correo TEXT NOT NULL,
  zona TEXT,
  invito TEXT,
  estado TEXT NOT NULL DEFAULT 'pendiente',
  vendedor_id TEXT,
  motivo_rechazo TEXT,
  resuelto_por TEXT,
  resolved_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS altas_vendedor_estado ON altas_vendedor (estado, created_at);
