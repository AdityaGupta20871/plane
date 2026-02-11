import http from "node:http";
import path from "node:path";
import * as dotenv from "@dotenvx/dotenvx";
import { reactRouter } from "@react-router/dev/vite";
import { defineConfig, type Plugin } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";
import { joinUrlPath } from "@plane/utils";

function keycloakProxy(): Plugin {
  return {
    name: "keycloak-proxy",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url?.startsWith("/realms") || req.url?.startsWith("/resources")) {
          const proxyReq = http.request(
            {
              hostname: "127.0.0.1",
              port: 8080,
              path: req.url,
              method: req.method,
              headers: { ...req.headers, host: "127.0.0.1:8080" },
            },
            (proxyRes) => {
              res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
              proxyRes.pipe(res);
            }
          );
          proxyReq.on("error", (err) => {
            console.error("Keycloak proxy error:", err.message);
            res.statusCode = 502;
            res.end("Bad Gateway");
          });
          req.pipe(proxyReq);
        } else {
          next();
        }
      });
    },
  };
}

dotenv.config({ path: path.resolve(__dirname, ".env") });

// Expose only vars starting with VITE_
const viteEnv = Object.keys(process.env)
  .filter((k) => k.startsWith("VITE_"))
  .reduce<Record<string, string>>((a, k) => {
    a[k] = process.env[k] ?? "";
    return a;
  }, {});

const basePath = joinUrlPath(process.env.VITE_ADMIN_BASE_PATH ?? "", "/") ?? "/";

export default defineConfig(() => ({
  base: basePath,
  define: {
    "process.env": JSON.stringify(viteEnv),
  },
  build: {
    assetsInlineLimit: 0,
  },
  plugins: [keycloakProxy(), reactRouter(), tsconfigPaths({ projects: [path.resolve(__dirname, "tsconfig.json")] })],
  resolve: {
    alias: {
      // Next.js compatibility shims used within admin
      "next/link": path.resolve(__dirname, "app/compat/next/link.tsx"),
      "next/navigation": path.resolve(__dirname, "app/compat/next/navigation.ts"),
    },
    dedupe: ["react", "react-dom"],
  },
  server: {
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
      },
      "/auth": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
      },
    },
  },
  // No SSR-specific overrides needed; alias resolves to ESM build
}));
