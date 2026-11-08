"use client";
import { useEffect, useRef } from "react";

interface N { x: number; y: number; vx: number; vy: number; r: number; hot: boolean }

/** Violet network field: dheere behte nodes, links, mouse ke qareeb jagmagate hain. Neeche CSS: glow orbs + dot grid. */
export default function Backdrop() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let w = 0, h = 0, raf = 0, nodes: N[] = [];
    const mouse = { x: -9999, y: -9999 };

    const resize = () => {
      w = window.innerWidth; h = window.innerHeight;
      c.width = w * dpr; c.height = h * dpr;
      c.style.width = `${w}px`; c.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.round(Math.min(90, Math.max(28, (w * h) / 22000)));
      nodes = Array.from({ length: count }, () => ({
        x: Math.random() * w, y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25,
        r: Math.random() * 1.4 + 0.6, hot: Math.random() < 0.18,
      }));
    };

    const LINK = 160;
    const draw = () => {
      ctx.clearRect(0, 0, w, h);
      for (const n of nodes) {
        if (reduce) continue;
        n.x += n.vx; n.y += n.vy;
        if (n.x < -10) n.x = w + 10; else if (n.x > w + 10) n.x = -10;
        if (n.y < -10) n.y = h + 10; else if (n.y > h + 10) n.y = -10;
      }
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
          if (d2 > LINK * LINK) continue;
          const k = 1 - Math.sqrt(d2) / LINK;
          const mx = (a.x + b.x) / 2 - mouse.x, my = (a.y + b.y) / 2 - mouse.y;
          const near = mx * mx + my * my < 200 * 200;
          ctx.strokeStyle = near ? `rgba(255,120,245,${k * 0.6})` : `rgba(160,130,255,${k * 0.2})`;
          ctx.lineWidth = near ? 1.1 : 0.7;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
      for (const n of nodes) {
        const mx = n.x - mouse.x, my = n.y - mouse.y;
        const near = mx * mx + my * my < 150 * 150;
        ctx.fillStyle = near ? "rgba(255,150,246,1)" : n.hot ? "rgba(255,61,240,.8)" : "rgba(190,170,255,.65)";
        ctx.shadowColor = n.hot || near ? "#ff3df0" : "#8b5cff"; ctx.shadowBlur = near ? 14 : 6;
        ctx.beginPath(); ctx.arc(n.x, n.y, near ? n.r + 1 : n.r, 0, Math.PI * 2); ctx.fill();
        ctx.shadowBlur = 0;
      }
      if (!reduce) raf = requestAnimationFrame(draw);
    };

    const onMove = (e: PointerEvent) => { mouse.x = e.clientX; mouse.y = e.clientY; };
    const onLeave = () => { mouse.x = -9999; mouse.y = -9999; };
    const onVis = () => { if (reduce) return; cancelAnimationFrame(raf); if (!document.hidden) raf = requestAnimationFrame(draw); };

    resize();
    raf = requestAnimationFrame(draw);
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onMove, { passive: true });
    document.addEventListener("pointerleave", onLeave);
    document.addEventListener("visibilitychange", onVis);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerleave", onLeave);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, []);

  return (
    <>
      <div className="lights" aria-hidden="true"><i className="lights__g" /><i className="lights__r" /><i className="lights__g2" /></div>
      <div className="dotgrid" aria-hidden="true" />
      <canvas ref={ref} className="backdrop" aria-hidden="true" />
      <div className="backdrop-vignette" aria-hidden="true" />
    </>
  );
}
