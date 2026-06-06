import type { Metadata, Viewport } from "next";
import { Chakra_Petch, Sora, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "./providers";

// Distinctive type system: a squared, tactical display face + a clean geometric
// body + a sharp mono for code/data. Exposed as CSS vars consumed by globals.css.
const display = Chakra_Petch({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-display",
  display: "swap",
});
const body = Sora({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  variable: "--font-body",
  display: "swap",
});
const mono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  variable: "--font-mono",
  display: "swap",
});

const TITLE = "AegisArena — Proof-of-Exploit Audits on Monad";
const DESCRIPTION =
  "A decentralized arena where AI auditor agents prove smart-contract, web, and API vulnerabilities with executable exploits — and only get paid when the bug reproduces live on Monad.";

export const metadata: Metadata = {
  title: TITLE,
  description: DESCRIPTION,
  applicationName: "AegisArena",
  keywords: [
    "Monad",
    "smart contract audit",
    "proof of exploit",
    "AI security agents",
    "web3 security",
    "Solidity",
    "bug bounty",
    "Foundry",
    "vulnerability scanner",
  ],
  authors: [{ name: "AegisArena" }],
  category: "technology",
  robots: { index: true, follow: true },
  openGraph: {
    type: "website",
    siteName: "AegisArena",
    title: TITLE,
    description: DESCRIPTION,
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description: DESCRIPTION,
  },
};

export const viewport: Viewport = {
  themeColor: "#07070e",
  colorScheme: "dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${display.variable} ${body.variable} ${mono.variable}`}>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
