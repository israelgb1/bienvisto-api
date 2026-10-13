-- Migración 10: guarda cuándo el cliente aceptó el seguimiento de 90 días al comprar.
-- Solo agrega una columna; las ventas anteriores quedan sin consentimiento (NULL).
ALTER TABLE ventas ADD COLUMN consent_seguimiento_at TEXT;
