"use client";
import { useEffect, useRef, type ReactNode } from "react";

/** Scroll par section smoothly ubharta hai. Jo pehle se screen par hai usay chhupata nahi (flash nahi). */
export default function Reveal({ children, className = "", delay = 0 }: { children: ReactNode; className?: string; delay?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const r = el.getBoundingClientRect();
    if (r.top < window.innerHeight * 0.92) return;
    el.classList.add("rv-hide");
    const io = new IntersectionObserver((es) => {
      es.forEach((e) => {
        if (e.isIntersecting) {
          window.setTimeout(() => { el.classList.remove("rv-hide"); el.classList.add("rv-in"); }, delay);
          io.disconnect();
        }
      });
    }, { threshold: 0.12 });
    io.observe(el);
    return () => io.disconnect();
  }, [delay]);
  return <div ref={ref} className={`rv ${className}`}>{children}</div>;
}
