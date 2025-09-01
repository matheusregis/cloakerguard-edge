// src/index.ts
import "dotenv/config";
import express, { Request } from "express";
import compression from "compression";
import morgan from "morgan";
import { LRUCache } from "lru-cache";
import type { Options } from "http-proxy-middleware";
import {
  createProxyMiddleware,
  responseInterceptor,
} from "http-proxy-middleware";

const PORT = Number(process.env.PORT || 8080);
const API_BASE = process.env.API_BASE ?? "";
const EDGE_TOKEN = process.env.EDGE_TOKEN || "";
const CACHE_TTL = Number(process.env.CACHE_TTL || 30) * 1000;
const DEFAULT_ORIGIN = process.env.DEFAULT_ORIGIN || "https://example.com";

if (!API_BASE) {
  console.error("Missing env: API_BASE (ex: https://api.cloakerguard.com.br)");
  process.exit(1);
}

type DomainCfg = {
  host: string;
  whiteOrigin?: string;
  blackOrigin?: string;
  rules?: { uaBlock?: string };
  status?: string;
};

const fetchFn: typeof fetch = globalThis.fetch.bind(globalThis);
const cache = new LRUCache<string, DomainCfg>({ max: 5000, ttl: CACHE_TTL });

// pega host do cliente (X-Forwarded-Host > Host)
function getClientHost(req: express.Request): string {
  const xfwd = String(req.headers["x-forwarded-host"] || "")
    .split(",")[0]
    .trim();
  const h = (xfwd || String(req.headers.host || "")).trim().toLowerCase();
  return h.replace(/:\d+$/, "").replace(/^\[([^[\]]+)\](:\d+)?$/, "[$1]");
}

async function resolveHost(host: string): Promise<DomainCfg | null> {
  const key = host.toLowerCase();
  const hit = cache.get(key);
  if (hit) return hit;

  const url = `${API_BASE}/domains/resolve?host=${encodeURIComponent(key)}`;
  const r = await fetchFn(url, {
    headers: EDGE_TOKEN ? { Authorization: `Bearer ${EDGE_TOKEN}` } : undefined,
  });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`resolve ${r.status}`);
  const cfg = (await r.json()) as DomainCfg;
  cache.set(key, cfg);
  return cfg;
}

function isWhite(req: Request, cfg: DomainCfg) {
  const ua = String(req.headers["user-agent"] || "");
  const re = cfg?.rules?.uaBlock
    ? new RegExp(cfg.rules.uaBlock, "i")
    : /(bot|crawler|spider|facebookexternalhit|headlesschrome)/i;
  return re.test(ua);
}

const app = express();
app.use(morgan("combined"));
app.use(compression());

// 1) /api -> proxy direto pra API (sem pré-check)
app.use(
  "/api",
  createProxyMiddleware({
    target: API_BASE,
    changeOrigin: true,
    xfwd: true,
    pathRewrite: (p: string) => p.replace(/^\/api/, ""),
  })
);

// 2) health (sem pré-check)
app.get("/__edge-check", (req, res) => {
  res.json({ ok: true, host: getClientHost(req) });
});

// 3) pré-check pros demais caminhos
app.use(async (req, res, next) => {
  const host = getClientHost(req);
  try {
    const cfg = await resolveHost(host);
    if (!cfg) {
      res.status(404).set("Cache-Control", "no-store")
        .send(`<!doctype html><html><body>
          <h1>Domain not configured</h1>
          <p>${host} não está configurado no CloakerGuard.</p>
        </body></html>`);
      return;
    }
    (req as any)._edgeHost = host; // host do cliente
    (req as any)._edgeCfg = cfg; // config resolvida
    next();
  } catch (e: any) {
    console.error("resolveHost error:", e?.message || e);
    res.status(502).send("Edge resolve error");
  }
});

// 4) proxy principal (white/black) + headers de debug
const mainProxyOptions: Options = {
  router: (req: any) => {
    const clientHost = req._edgeHost || getClientHost(req);
    const cfg: DomainCfg | undefined = req._edgeCfg;

    if (!cfg) {
      req._edgeRoute = "fallback";
      req._edgeTarget = DEFAULT_ORIGIN;
      return DEFAULT_ORIGIN;
    }

    const white = isWhite(req as Request, cfg);
    const target = white ? cfg.whiteOrigin : cfg.blackOrigin;
    req._edgeRoute = white ? "white" : "black";
    req._edgeTarget = target || DEFAULT_ORIGIN;

    try {
      if (target) {
        const t = new URL(target);
        // evita loop: destino não pode ser o mesmo host do cliente
        if (t.host.toLowerCase() === clientHost) {
          req._edgeRoute = "loop-fallback";
          req._edgeTarget = DEFAULT_ORIGIN;
          return DEFAULT_ORIGIN;
        }
        return target;
      }
    } catch {
      // cai no fallback
    }
    req._edgeRoute = "no-target-fallback";
    req._edgeTarget = DEFAULT_ORIGIN;
    return DEFAULT_ORIGIN;
  },
  changeOrigin: true,
  xfwd: true,
  selfHandleResponse: true,
  on: {
    proxyReq(proxyReq, req: any) {
      // Host do origin (Vercel/Globo)
      const destHost = (proxyReq as any).getHeader?.("host") as
        | string
        | undefined;
      if (destHost) (proxyReq as any).setHeader("Host", destHost);

      // Preserve o host do cliente para sua API/origins
      (proxyReq as any).setHeader(
        "X-Forwarded-Host",
        req._edgeHost || getClientHost(req)
      );
      (proxyReq as any).setHeader("X-Forwarded-Proto", "https");
    },
    proxyRes: responseInterceptor(async (buf, _proxyRes, req: any, res) => {
      res.setHeader("x-edge-route", req._edgeRoute || "unknown");
      res.setHeader("x-edge-target", req._edgeTarget || "none");
      res.setHeader("x-edge-host", req._edgeHost || getClientHost(req));
      return buf as Buffer;
    }),
  },
};

app.use("/", createProxyMiddleware(mainProxyOptions));

app.listen(PORT, () => console.log(`EDGE on :${PORT}`));
