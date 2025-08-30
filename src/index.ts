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

async function resolveHost(host: string): Promise<DomainCfg | null> {
  const key = host.toLowerCase();
  const hit = cache.get(key);
  if (hit) return hit;
  const url = `${API_BASE}/domains/resolve?host=${encodeURIComponent(key)}`;
  const r = await fetchFn(url, {
    headers: { Authorization: `Bearer ${EDGE_TOKEN}` },
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
    : /(bot|crawler|spider|HeadlessChrome)/i;
  return re.test(ua);
}

const app = express();
app.use(morgan("combined"));
app.use(compression());

// /api -> proxy direto para API_BASE (sem pré-check)
app.use(
  "/api",
  createProxyMiddleware({
    target: API_BASE,
    changeOrigin: true,
    xfwd: true,
    pathRewrite: (p: string) => p.replace(/^\/api/, ""),
  })
);

// health
app.get("/__edge-check", (req, res) => {
  res.json({ ok: true, host: req.headers.host });
});

// pré-check apenas para o resto
app.use(async (req, res, next) => {
  const host = String(req.headers.host || "").toLowerCase();
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
    (req as any)._edgeCfg = cfg;
    next();
  } catch (e: any) {
    console.error("resolveHost error:", e?.message || e);
    res.status(502).send("Edge resolve error");
  }
});

// proxy principal (white/black) + headers de debug
const mainProxyOptions: Options = {
  router: (req: any) => {
    const host = String(req.headers.host || "").toLowerCase();
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
        if (t.host.toLowerCase() === host) {
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
      const destHost = (proxyReq as any).getHeader?.("host") as
        | string
        | undefined;
      const clientHost = String(req.headers.host || "").toLowerCase();
      if (destHost) (proxyReq as any).setHeader("Host", destHost);
      (proxyReq as any).setHeader("X-Forwarded-Host", clientHost);
      (proxyReq as any).setHeader("X-Forwarded-Proto", "https");
    },
    proxyRes: responseInterceptor(async (buf, _proxyRes, req: any, res) => {
      res.setHeader("x-edge-route", req._edgeRoute || "unknown");
      res.setHeader("x-edge-target", req._edgeTarget || "none");
      return buf as Buffer;
    }),
  },
};

app.use("/", createProxyMiddleware(mainProxyOptions));

app.listen(PORT, () => console.log(`EDGE on :${PORT}`));
