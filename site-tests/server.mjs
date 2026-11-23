import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'docs');
const types = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.txt': 'text/plain', '.xml': 'application/xml',
};

// Serves docs/ under /saas-governance-kit/ so paths match GitHub Pages.
const base = '/saas-governance-kit';
createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (!url.pathname.startsWith(base)) { res.writeHead(404); res.end(); return; }
  let rel = normalize(url.pathname.slice(base.length)).replace(/^(\.\.[/\\])+/, '');
  if (rel === '/' || rel === '.' || rel === '') rel = '/index.html';
  try {
    const body = await readFile(join(root, rel));
    res.writeHead(200, { 'content-type': types[extname(rel)] || 'application/octet-stream' });
    res.end(body);
  } catch {
    try {
      const body = await readFile(join(root, '404.html'));
      res.writeHead(404, { 'content-type': types['.html'] });
      res.end(body);
    } catch { res.writeHead(404); res.end(); }
  }
}).listen(4173, '127.0.0.1');
