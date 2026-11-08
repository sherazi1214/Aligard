export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" aria-hidden="true" className="logo-mark">
      <defs>
        <linearGradient id="lg1" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
          <stop stopColor="#a98bff" /><stop offset="1" stopColor="#ff3df0" />
        </linearGradient>
        <clipPath id="lgclip"><path d="M24 4 41 10v13c0 10-7 17-17 21C14 40 7 33 7 23V10L24 4Z" /></clipPath>
      </defs>
      <path d="M24 4 41 10v13c0 10-7 17-17 21C14 40 7 33 7 23V10L24 4Z" fill="rgba(139,92,255,.08)" stroke="url(#lg1)" strokeWidth="2" strokeLinejoin="round" />
      <g clipPath="url(#lgclip)"><rect className="logo-scan" x="4" y="0" width="40" height="3" fill="#ff3df0" opacity=".9" /></g>
      <path d="m16 24 6 6 11-12" stroke="#a98bff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="wordmark">
      <Logo size={28} />
      <span className="wordmark__t">Ali<b>Guard</b></span>
    </span>
  );
}
