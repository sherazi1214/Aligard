import type { Metadata, Viewport } from "next";
import "@fontsource/sora/400.css";
import "@fontsource/sora/500.css";
import "@fontsource/sora/600.css";
import "@fontsource/sora/700.css";
import "@fontsource/sora/800.css";
import "@fontsource/fira-code/400.css";
import "@fontsource/fira-code/500.css";
import "./globals.css";
import Backdrop from "@/components/Backdrop";
import Boot from "@/components/Boot";
import PointerLight from "@/components/PointerLight";
import { ToastProvider } from "@/lib/toast";

export const metadata: Metadata = {
  title: { default: "AliGuard - phishing defence for your inbox", template: "%s | AliGuard" },
  description: "AI anti-phishing platform. Four detection layers, automatic quarantine, explainable verdicts.",
  robots: { index: false, follow: false },
};
export const viewport: Viewport = { themeColor: "#07031a", colorScheme: "dark" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Backdrop />
        <PointerLight />
        <Boot />
        <ToastProvider>
          <div className="stage">{children}</div>
        </ToastProvider>
      </body>
    </html>
  );
}
