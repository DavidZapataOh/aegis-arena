/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The verifier/sandbox API routes shell out to `forge` and use the Node runtime.
  // Mark the heavy server-only deps as external so the bundler doesn't choke on them.
  serverExternalPackages: ["@anthropic-ai/sdk"],
  // Keep TS type-checking on (catches real bugs) but don't let lint style rules block builds.
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
