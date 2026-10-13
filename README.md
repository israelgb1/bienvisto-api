# bienvisto-api

Worker de Bien Visto: API del panel de administración, API de la app de vendedores, formularios del sitio y envío de correos (cron cada 5 minutos).

- `src/index.js`: código del worker.
- `wrangler.jsonc`: bindings (D1 `bienvisto-db`, R2 `bienvisto-comprobantes`, cron).
- Secretos (`RESEND_API_KEY`, `GOOGLE_PLACES_KEY`) y `GOOGLE_CLIENT_ID` se configuran en Cloudflare, no en el repo.

Despliegue: al fusionar en `main`, Cloudflare Workers Builds despliega el worker.
