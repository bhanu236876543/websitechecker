import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = { title: "WebsiteChecker", description: "Safe project security reports" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
