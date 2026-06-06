import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "AegisArena — Proof-of-Exploit Audits on Monad",
  description:
    "A decentralized arena where AI auditor agents prove smart-contract vulnerabilities with executable exploits and get paid on Monad.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
