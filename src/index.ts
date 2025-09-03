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
import { IncomingMessage, ServerResponse } from "http";
import type { ClientRequest } from "http";
import type { Socket } from "net";

const PORT = Number(process.env.PORT || 8080);
const API_BASE = process.env.API_BASE ?? "";
const EDGE_TOKEN = process.env.EDGE_TOKEN || "";
const CACHE_TTL = Number(process.env.CACHE_TTL || 30) * 1000;
const DEFAULT_ORIGIN = process.env.DEFAULT_ORIGIN || "https://example.com";
const DEBUG = true; // força debug sempre

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

type EdgeReq = Request & {
  _edgeHost?: string;
  _edgeCfg?: DomainCfg;
  _edgeRoute?: string;
  _edgeTarget?: string;
};

const fetchFn: typeof fetch = globalThis.fetch.bind(globalThis);
const cache = new LRUCache<string, DomainCfg>({ max: 5000, ttl: CACHE_TTL });

// Prioriza X-Original-Host (CF Transform), depois X-Forwarded-Host, por fim Host
function getClientHost(req: Request): string {
  const xoh =
    (req.headers["x-original-host"] as string) ||
    (req.headers["x-forwarded-host"] as string)?.split(",")[0]?.trim() ||
    (req.headers.host as string) ||
    "";
  return xoh.toLowerCase().trim().replace(/:\d+$/, "");
}

async function resolveHost(host: string): Promise<DomainCfg | null> {
  const key = host.toLowerCase();
  console.log(`[RESOLVE] start host=${key}`);
  const hit = cache.get(key);
  if (hit) {
    console.log(`[RESOLVE cache] ${key} ->`, hit);
    return hit;
  }

  const url = `${API_BASE}/domains/resolve?host=${encodeURIComponent(key)}`;
  console.log(`[RESOLVE fetch] GET ${url}`);
  const r = await fetchFn(url, {
    headers: EDGE_TOKEN ? { Authorization: `Bearer ${EDGE_TOKEN}` } : undefined,
  });

  if (r.status === 404) {
    console.log(`[RESOLVE] 404 for host=${key}`);
    return null;
  }
  if (!r.ok) {
    console.log(`[RESOLVE] error status=${r.status}`);
    throw new Error(`resolve ${r.status}`);
  }
  const cfg = (await r.json()) as DomainCfg;
  cache.set(key, cfg);
  console.log(`[RESOLVE ok] ${key} ->`, cfg);
  return cfg;
}

function isWhite(req: Request, cfg: DomainCfg) {
  const ua = String(req.headers["user-agent"] || "");
  const re = cfg?.rules?.uaBlock
    ? new RegExp(cfg.rules.uaBlock, "i")
    : /(bot|crawler|spider|facebookexternalhit|headlesschrome)/i;
  const matched = re.test(ua);
  console.log(`[UA CHECK] ua="${ua}" -> white=${matched}`);
  return matched;
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", true);

// morgan com host/ua
morgan.token("edge-host", (req) => getClientHost(req as any));
morgan.token("ua", (req) => String(req.headers["user-agent"] || ""));
app.use(
  morgan(
    ':method :url :status :res[content-length] - :response-time ms h=:edge-host ua=":ua"'
  )
);
app.use(compression());

// log de entrada
app.use((req, _res, next) => {
  console.log(
    `[EDGE] Incoming: host=${getClientHost(req)}, url=${req.url}, ua="${
      req.headers["user-agent"]
    }"`
  );
  next();
});

app.all("/.well-known/acme-challenge/:token", async (req, res) => {
  const host = getClientHost(req);
  const token = req.params.token;
  console.log(`[ACME] host=${host}, token=${token}`);
  try {
    const url = `${API_BASE}/acme/http-token?host=${encodeURIComponent(
      host
    )}&token=${encodeURIComponent(token)}`;
    const r = await fetchFn(url, {
      headers: EDGE_TOKEN
        ? { Authorization: `Bearer ${EDGE_TOKEN}` }
        : undefined,
    });
    if (r.status === 404) {
      console.log(`[ACME] 404 token not found`);
      return res.status(404).end();
    }
    if (!r.ok) {
      console.log(`[ACME] error status=${r.status}`);
      return res.status(502).end();
    }
    const body = await r.text();
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    if (req.method === "HEAD") return res.status(200).end();
    return res.status(200).send(body);
  } catch (e: any) {
    console.error(`[ACME] error`, e);
    return res.status(500).end();
  }
});

// Rota de debug
app.get("/__echo", (req, res) => {
  res.json({
    ok: true,
    hostDetectado: getClientHost(req),
    method: req.method,
    url: req.url,
    headers: req.headers,
  });
});

// pré-check de domínios
app.use(async (req, res, next) => {
  const host = getClientHost(req);
  try {
    const cfg = await resolveHost(host);
    if (!cfg) {
      console.log(`[PRECHECK] host=${host} NOT CONFIGURED`);
      res
        .status(404)
        .set("Cache-Control", "no-store")
        .send(`<h1>Domain not configured</h1><p>${host}</p>`);
      return;
    }
    (req as EdgeReq)._edgeHost = host;
    (req as EdgeReq)._edgeCfg = cfg;
    console.log(`[PRECHECK] host=${host} cfg ok`);
    next();
  } catch (e: any) {
    console.error("[PRECHECK] resolve error:", e?.message || e);
    res.status(502).send("Edge resolve error");
  }
});

type HpmOptions = Options & {
  timeout?: number;
  proxyTimeout?: number;
};

const mainProxyOptions: HpmOptions = {
  router: (req: any) => {
    const r = req as EdgeReq;
    const clientHost = r._edgeHost || getClientHost(r);
    const cfg: DomainCfg | undefined = r._edgeCfg;

    if (!cfg) {
      r._edgeRoute = "fallback";
      r._edgeTarget = DEFAULT_ORIGIN;
      console.log(`[ROUTER] ${clientHost} -> FALLBACK ${DEFAULT_ORIGIN}`);
      return DEFAULT_ORIGIN;
    }

    const white = isWhite(r, cfg);
    const target = white ? cfg.whiteOrigin : cfg.blackOrigin;
    r._edgeRoute = white ? "white" : "black";
    r._edgeTarget = target || DEFAULT_ORIGIN;

    try {
      if (target) {
        const t = new URL(target);
        if (!/^https?:$/.test(t.protocol)) throw new Error("bad scheme");
        if (t.host.toLowerCase() === clientHost) {
          r._edgeRoute = "loop-fallback";
          r._edgeTarget = DEFAULT_ORIGIN;
          console.log(
            `[ROUTER] ${clientHost} LOOP -> FALLBACK ${DEFAULT_ORIGIN}`
          );
          return DEFAULT_ORIGIN;
        }
        console.log(
          `[ROUTER] ${clientHost} uaRoute=${r._edgeRoute} -> ${target}`
        );
        return target;
      }
    } catch (e) {
      console.log(`[ROUTER] ${clientHost} bad target: ${e}`);
    }

    r._edgeRoute = "no-target-fallback";
    r._edgeTarget = DEFAULT_ORIGIN;
    console.log(`[ROUTER] ${clientHost} -> NO-TARGET ${DEFAULT_ORIGIN}`);
    return DEFAULT_ORIGIN;
  },
  changeOrigin: true,
  xfwd: true,
  selfHandleResponse: true,
  timeout: 25_000,
  proxyTimeout: 25_000,
  ws: true,
  on: {
    error: (err: Error, req: IncomingMessage, res: ServerResponse | Socket) => {
      console.error(
        `[PROXY ERROR] host=${getClientHost(req as any)} err=${err.message}`
      );
      if (res instanceof ServerResponse) {
        res.writeHead(502, { "Content-Type": "text/plain" });
        res.end("Edge upstream error");
      }
    },
    proxyReq: (proxyReq: ClientRequest, req: IncomingMessage) => {
      const r = req as EdgeReq;
      const target = r._edgeTarget || DEFAULT_ORIGIN;
      let destHost = "";
      try {
        destHost = new URL(target).host;
      } catch {
        destHost = "";
      }
      if (destHost) proxyReq.setHeader("Host", destHost);

      const clientHost = r._edgeHost || getClientHost(r as any);
      proxyReq.setHeader("X-Original-Host", clientHost);
      proxyReq.setHeader("X-Forwarded-Host", clientHost);
      proxyReq.setHeader(
        "X-Forwarded-Proto",
        (req as any).secure ? "https" : "http"
      );

      console.log(`[PROXY REQ] ${clientHost} -> ${target} (Host=${destHost})`);
    },
    proxyRes: responseInterceptor(
      async (buf, _proxyRes, req: IncomingMessage, res: ServerResponse) => {
        const r = req as EdgeReq;
        res.setHeader("x-edge-route", r._edgeRoute || "unknown");
        res.setHeader("x-edge-target", r._edgeTarget || "none");
        res.setHeader("x-edge-host", r._edgeHost || getClientHost(r as any));
        console.log(
          `[PROXY RES] host=${r._edgeHost} route=${r._edgeRoute} target=${r._edgeTarget}`
        );
        return buf as Buffer;
      }
    ),
  },
};

app.use("/", createProxyMiddleware(mainProxyOptions));

app.listen(PORT, () => console.log(`EDGE listening on :${PORT}`));
