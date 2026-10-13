-- Migración 8: seguimiento de 90 días con un resumen cada 15 días (6 envíos por venta).
-- Solo agrega tablas; no toca datos existentes. Las ventas anteriores no tienen seguimiento.
CREATE TABLE IF NOT EXISTS seguimientos (
  venta_id TEXT PRIMARY KEY REFERENCES ventas(id),
  estado TEXT NOT NULL DEFAULT 'activo' CHECK (estado IN ('activo','baja','cancelado','terminado')),
  inicio TEXT NOT NULL,            -- día (hora de México) en que se activó la venta
  consentimiento_at TEXT,          -- cuándo aceptó recibir los resúmenes; sin esto no se envía nada
  saludo_at TEXT,                  -- cuándo se mandó el saludo inicial
  respondio_at TEXT,               -- cuándo respondió SÍ al saludo
  baja_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS seguimiento_envios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  venta_id TEXT NOT NULL REFERENCES ventas(id),
  numero INTEGER NOT NULL CHECK (numero BETWEEN 1 AND 6),   -- 6 es el resumen de cierre (día 90)
  programado_para TEXT NOT NULL,   -- día (hora de México) en que toca mandarlo
  estado TEXT NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente','enviado','omitido')),
  enviado_at TEXT,
  nivel TEXT,                      -- bajo, medio o alto, según los escaneos de esa quincena
  datos TEXT,                      -- JSON con las cifras que llevó el resumen
  UNIQUE (venta_id, numero)
);
CREATE INDEX IF NOT EXISTS idx_seg_envios_pendientes ON seguimiento_envios (estado, programado_para);
