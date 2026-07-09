import React from 'react';

export interface SealGlyphProps {
  /** Any string to derive the glyph from — a safety number, a public key,
   * a device fingerprint. The same value always produces the same glyph. */
  value: string;
  size?: number;
  tone?: 'neutral' | 'verified' | 'alert';
  title?: string;
  className?: string;
}

const TONE_COLORS: Record<NonNullable<SealGlyphProps['tone']>, { fill: string; stroke: string }> = {
  neutral: { fill: 'rgba(148, 155, 171, 0.16)', stroke: 'var(--text-secondary)' },
  verified: { fill: 'var(--verified-tint)', stroke: 'var(--verified)' },
  alert: { fill: 'var(--alert-tint)', stroke: 'var(--alert)' },
};

const POINT_COUNT = 9;

/**
 * FNV-1a — cheap, stable, non-cryptographic. The glyph is a *visual*
 * fingerprint aid, not a security boundary: the safety number underneath
 * it is what actually gets compared. This just needs to spread visually
 * distinct inputs (including similar-looking hex strings) into visibly
 * different shapes.
 */
function fnv1a(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function amplitudesFor(value: string, count: number, minR: number, maxR: number): number[] {
  const amps: number[] = [];
  for (let i = 0; i < count; i++) {
    const h = fnv1a(`${value}:${i}`);
    const t = (h % 10000) / 10000; // 0..1
    amps.push(minR + t * (maxR - minR));
  }
  return amps;
}

/** Smooth closed path through polar points via quadratic curves through
 * successive midpoints — gives the rosette an organic, seal-pressed edge
 * rather than a jagged polygon. */
function rosettePath(amps: number[], cx: number, cy: number): string {
  const n = amps.length;
  const pts = amps.map((r, i) => {
    const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
    return [cx + r * Math.cos(angle), cy + r * Math.sin(angle)] as const;
  });
  const mid = (a: readonly [number, number], b: readonly [number, number]) =>
    [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2] as const;

  const start = mid(pts[n - 1], pts[0]);
  let d = `M ${start[0].toFixed(2)} ${start[1].toFixed(2)} `;
  for (let i = 0; i < n; i++) {
    const next = pts[i];
    const after = mid(pts[i], pts[(i + 1) % n]);
    d += `Q ${next[0].toFixed(2)} ${next[1].toFixed(2)} ${after[0].toFixed(2)} ${after[1].toFixed(2)} `;
  }
  return d + 'Z';
}

/**
 * A deterministic abstract "seal" derived from a fingerprint value — the
 * same safety number always presses the same shape. Two devices with a
 * matching safety number show a matching seal, so a mismatch is visible
 * as a shape difference before either side reads a single hex digit.
 */
export const SealGlyph: React.FC<SealGlyphProps> = ({
  value,
  size = 48,
  tone = 'neutral',
  title,
  className,
}) => {
  const colors = TONE_COLORS[tone];
  const cx = 50;
  const cy = 50;
  const amps = amplitudesFor(value, POINT_COUNT, 13, 45);
  const path = rosettePath(amps, cx, cy);
  const notchAngle = (fnv1a(`${value}:notch`) % 360) * (Math.PI / 180);
  const notchX = cx + 44 * Math.cos(notchAngle);
  const notchY = cy + 44 * Math.sin(notchAngle);

  // Radial ticks at each petal angle — reads as an engraved dial/seal edge
  // rather than a bare blob, and grows the shape's visual entropy further.
  const ticks = amps.map((_, i) => {
    const angle = (i / amps.length) * Math.PI * 2 - Math.PI / 2;
    const x1 = cx + 45 * Math.cos(angle);
    const y1 = cy + 45 * Math.sin(angle);
    const x2 = cx + 49 * Math.cos(angle);
    const y2 = cy + 49 * Math.sin(angle);
    return { x1, y1, x2, y2 };
  });

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      role="img"
      aria-label={title ?? `Fingerprint seal for ${value}`}
      className={className}
    >
      {title && <title>{title}</title>}
      <circle cx={cx} cy={cy} r={47} fill="none" stroke={colors.stroke} strokeOpacity={0.3} strokeWidth={1} />
      {ticks.map((t, i) => (
        <line key={i} x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} stroke={colors.stroke} strokeOpacity={0.5} strokeWidth={1.5} />
      ))}
      <path d={path} fill={colors.fill} stroke={colors.stroke} strokeWidth={2} strokeLinejoin="round" />
      <circle cx={cx} cy={cy} r={3} fill={colors.stroke} />
      <circle cx={notchX} cy={notchY} r={2.5} fill={colors.stroke} />
    </svg>
  );
};
