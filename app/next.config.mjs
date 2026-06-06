/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The verifier/sandbox API routes shell out to `forge` and use the Node runtime.
  // Mark the heavy server-only deps as external so the bundler doesn't choke on them.
  serverExternalPackages: ["@anthropic-ai/sdk"],
};

export default nextConfig;
