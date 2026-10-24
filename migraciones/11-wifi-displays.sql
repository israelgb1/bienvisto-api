-- Migración 11: datos de red de los displays de tipo "Wi-Fi".
-- Tabla nueva y aditiva; no toca ninguna existente. Un folio de lote "Wi-Fi" muestra esta red al escanearlo.
-- La contraseña se guarda en claro porque el display la muestra a los clientes del negocio.
CREATE TABLE IF NOT EXISTS wifi_displays (
  folio TEXT PRIMARY KEY,
  ssid TEXT NOT NULL,
  password TEXT,
  seguridad TEXT NOT NULL DEFAULT 'WPA' CHECK (seguridad IN ('WPA','WEP','nopass')),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
