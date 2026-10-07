import type { NextConfig } from "next";

// Server-side deployment setting. Never put credentials in this URL.
const backendOrigin = process.env.BACKEND_ORIGIN;
if (backendOrigin) {
  const parsed = new URL(backendOrigin);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password ||
      parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("BACKEND_ORIGIN must be an HTTPS origin without credentials, path or query.");
  }
}

const nextConfig: NextConfig = {
  async rewrites() {
    return backendOrigin ? [{
      source: "/backend/:path*",
      destination: `${new URL(backendOrigin).origin}/:path*`,
    }] : [];
  },
};

export default nextConfig;
