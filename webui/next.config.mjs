import { fileURLToPath } from "node:url";

// Static export: `NEXT_EXPORT=1 next build` produces a pure static directory at web/out,
// ready to drop into an nginx web root. Dev (next dev) leaves the variable unset, keeping the /api reverse proxy and hot reload.
const isExport = process.env.NEXT_EXPORT === "1";
// Vercel demo: the whole site runs on mock, no backend, no /api reverse proxy needed.
const isMock = process.env.NEXT_PUBLIC_MOCK === "1";
// Go backend (ARGUS). Override with AUTOPENTEST_API when it runs elsewhere.
const backend = process.env.AUTOPENTEST_API ?? "http://127.0.0.1:8787";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Prevent a parent directory's lockfile from affecting root inference and asset path generation.
  turbopack: { root: fileURLToPath(new URL(".", import.meta.url)) },
  reactCompiler: true,
  // Allow accessing dev resources (HMR) from LAN IPs; add or remove as needed.
  // In dev, allow any IPv4 origin to access /_next/* and HMR (unaffected by LAN IP changes).
  // Note: Next forbids a bare "*" for security; use segmented wildcards — "*.*.*.*" matches any IPv4.
  allowedDevOrigins: ["*.*.*.*"],
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  images: { unoptimized: true },
  ...(isExport
    ? {
        // Pure static export: no Node runtime, no rewrites.
        output: "export",
        trailingSlash: true,
      }
    : {
        async rewrites() {
          return [
            // ARTEX 原生 API 契约（mock 模式下由 lib/mock 拦截，不会真的打到这里）
            { source: "/api/:path*", destination: `${backend}/api/:path*` },
            // ARGUS 真实后端：前端用 /argus/* 访问我们自己的安全内核 API，避免 CORS
            { source: "/argus/:path*", destination: `${backend}/api/:path*` },
          ];
        },
      }),
  // isMock only disables nothing today; kept so mock builds stay explicit in logs.
  env: isMock ? { NEXT_PUBLIC_MOCK: "1" } : undefined,
};

export default nextConfig;
