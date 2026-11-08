"use client";
import type { ReactNode } from "react";
import type { Tone } from "@/lib/types";

export interface Blip { angle: number; r: number; tone: Tone; fresh?: boolean }

const TONE: Record<Tone, string> = {
  idle: "#a98bff", safe: "#4de3d1", warn: "#ffb020", danger: "#ff4d8d",
};

/** Signature element: ghoomta radar-reactor. value = arc (0-100), blips = recent scans, scanning = tez sweep. */
export default function ThreatCore({
  value, tone, scanning = false, size = 280, blips = [], children,
}: { value: number; tone: Tone; scanning?: boolean; size?: number; blips?: Blip[]; children?: ReactNode }) {
  const R = 70, C = 2 * Math.PI * R;
  const off = C * (1 - Math.max(0, Math.min(100, value)) / 100);
  const col = TONE[tone];
  const ticks = Array.from({ length: 72 }, (_, i) => {
    const a = (i / 72) * Math.PI * 2, long = i % 6 === 0;
    const r1 = long ? 88 : 91, r2 = 96;
    return { x1: 100 + Math.cos(a) * r1, y1: 100 + Math.sin(a) * r1, x2: 100 + Math.cos(a) * r2, y2: 100 + Math.sin(a) * r2, long };
  });

  return (
    <div className={`core ${scanning ? "core--scan" : ""}`} style={{ width: size, height: size, ["--tone" as string]: col }}>
      <div className="core__sweep" />
      <svg viewBox="0 0 200 200" className="core__svg" aria-hidden="true">
        <g className="core__spin">
          {ticks.map((t, i) => (
            <line key={i} x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} stroke={t.long ? col : "rgba(190,205,240,.35)"} strokeWidth={t.long ? 1.4 : 0.8} strokeOpacity={t.long ? 0.9 : 1} />
          ))}
        </g>
        <circle className="core__dash" cx="100" cy="100" r="82" fill="none" stroke="rgba(190,205,240,.22)" strokeWidth="1" strokeDasharray="2 7" />
        <circle cx="100" cy="100" r={R} fill="none" stroke="rgba(255,255,255,.07)" strokeWidth="7" />
        <circle
          cx="100" cy="100" r={R} fill="none" stroke={col} strokeWidth="7" strokeLinecap="round"
          strokeDasharray={C} strokeDashoffset={off} transform="rotate(-90 100 100)" className="core__arc"
        />
        <circle cx="100" cy="100" r="56" fill="rgba(4,6,12,.55)" stroke="rgba(255,255,255,.06)" />
        <path d="M100 40v8M100 152v8M40 100h8M152 100h8" stroke="rgba(190,205,240,.35)" strokeWidth="1" />
      </svg>
      {blips.map((b, i) => {
        const rad = (b.angle * Math.PI) / 180;
        const rr = 0.6 + b.r * 0.34;
        return (
          <span
            key={i}
            className={`blip blip--${b.tone} ${b.fresh ? "blip--fresh" : ""}`}
            style={{ left: `${50 + Math.cos(rad) * rr * 50}%`, top: `${50 + Math.sin(rad) * rr * 50}%` }}
          />
        );
      })}
      <div className="core__center">{children}</div>
    </div>
  );
}
