import { pathToFileURL } from 'node:url';
import express from 'express';
import pino from 'pino';
import { httpRedactor } from 'flare-redact/http';
import { pinoRedact } from 'flare-redact/pino';

export function createApp(logger = pino(pinoRedact())) {
  const app = express();
  app.use(express.json());
  app.use(httpRedactor());
  app.use((request, _response, next) => {
    logger.info(request.redacted(), 'safe request snapshot');
    next();
  });
  app.post('/checkout', (_request, response) => response.json({ ok: true }));
  return app;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  createApp().listen(3000, () => {
    console.log('Express example listening at http://127.0.0.1:3000');
  });
}
