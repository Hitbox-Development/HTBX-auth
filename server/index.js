import express from 'express';
import http from 'http';
import { readdirSync } from 'fs';
import { WebSocketServer } from 'ws';
import logger from './modules/logger.js';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config({ quiet: true });

const PORT = process.env.PORT || 3001;

const app = express();
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
}));
const server = http.createServer(app);

const wss = new WebSocketServer({ noServer: true });

const routeHandlers = {};

const routeFiles = readdirSync('./routes').filter(file => file.endsWith('.js'));

for (const file of routeFiles) {
  const routePath = '/' + file.replace('.js', '');
  const module = await import(`./routes/${file}`);
  app.get(routePath + '/init', module.init);
  routeHandlers[routePath] = module.wsHandler;
  logger.info(`🧩 Loaded route ${routePath}`);
}

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const route = url.pathname;

  const handler = routeHandlers[route];
  if (handler) {
    wss.handleUpgrade(req, socket, head, (ws) => {
      handler(ws, req);
    });
  } else {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
  }
});

server.listen(PORT, () => {
  console.log(`🚀 Auth server running at http://localhost:${PORT}`);
});
