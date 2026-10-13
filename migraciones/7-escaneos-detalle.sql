-- Migración 7: el contador de escaneos deja de contar todo y guarda el detalle de cada visita.
-- Solo agrega columnas con valor por defecto; no borra ni cambia filas existentes.
-- Las filas anteriores quedan con contado = 0 (eran pruebas y no distinguían robots ni repeticiones).
ALTER TABLE escaneos ADD COLUMN dia_mx TEXT;          -- día en hora de México (UTC-6), AAAA-MM-DD
ALTER TABLE escaneos ADD COLUMN huella TEXT;          -- hash diario de IP + navegador; no es reversible a la IP
ALTER TABLE escaneos ADD COLUMN origen TEXT;          -- 'qr' si la URL trae ?q=1; si no, 'nfc' (o enlace directo)
ALTER TABLE escaneos ADD COLUMN dispositivo TEXT;     -- ios, android, escritorio, otro
ALTER TABLE escaneos ADD COLUMN pais TEXT;
ALTER TABLE escaneos ADD COLUMN region TEXT;
ALTER TABLE escaneos ADD COLUMN ciudad TEXT;
ALTER TABLE escaneos ADD COLUMN estado_display TEXT;  -- estado del display al momento del escaneo
ALTER TABLE escaneos ADD COLUMN es_bot INTEGER NOT NULL DEFAULT 0;
ALTER TABLE escaneos ADD COLUMN contado INTEGER NOT NULL DEFAULT 0;
ALTER TABLE escaneos ADD COLUMN motivo_no TEXT;       -- por qué no se contó: bot, prueba, no_activo, repetido
CREATE INDEX IF NOT EXISTS idx_escaneos_contado ON escaneos (folio, contado, created_at);
CREATE INDEX IF NOT EXISTS idx_escaneos_huella ON escaneos (folio, dia_mx, huella);
-- Desde cuándo cuentan los números de un display: su activación o su último cambio de negocio.
ALTER TABLE folios ADD COLUMN conteo_desde TEXT;
UPDATE folios SET conteo_desde = updated_at WHERE estado = 'activo' AND conteo_desde IS NULL;
