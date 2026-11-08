/** @type {import('next').NextConfig} */
// BACKEND_URL build time par bake hota hai (rewrites). Deploy se PEHLE set karein.
const BACKEND = (process.env.BACKEND_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

module.exports = {
  reactStrictMode: true,
  poweredByHeader: false,
  output: "standalone",
  async redirects() {
    // Backend ke /privacy aur /terms pages ke nav mein /account link hai; naye UI mein wo /settings hai.
    return [{ source: "/account", destination: "/settings", permanent: false }];
  },
  async rewrites() {
    // Browser sirf frontend domain se baat karta hai => cookies same-site, CSRF/Origin check pass.
    return [
      { source: "/api/:path*", destination: `${BACKEND}/api/:path*` },
      { source: "/health", destination: `${BACKEND}/health` },
      { source: "/health/:path*", destination: `${BACKEND}/health/:path*` },
      { source: "/privacy", destination: `${BACKEND}/privacy` },
      { source: "/terms", destination: `${BACKEND}/terms` },
      { source: "/static/:path*", destination: `${BACKEND}/static/:path*` },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          // script-src bewajah nahi lagaya (Next inline scripts nonce ke baghair toot jate); baqi directives safe hain
          { key: "Content-Security-Policy", value: "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'" },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};
