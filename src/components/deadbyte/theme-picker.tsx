import { useEffect, useState } from 'react';
import { Monitor, Moon, Sun } from 'lucide-react';

// ---------- Accent colors ----------
export const THEMES = [
  { id: 'purple', label: 'Purple', color: 'oklch(.64 .23 295)' },
  { id: 'blue', label: 'Blue', color: 'oklch(.64 .2 250)' },
  { id: 'cyan', label: 'Cyan', color: 'oklch(.7 .13 200)' },
  { id: 'green', label: 'Green', color: 'oklch(.7 .17 160)' },
  { id: 'amber', label: 'Amber', color: 'oklch(.76 .15 70)' },
  { id: 'red', label: 'Red', color: 'oklch(.65 .21 20)' },
  { id: 'pink', label: 'Pink', color: 'oklch(.68 .21 345)' },
];

// ---------- Light / Dark / System mode ----------
export type Mode = 'system' | 'light' | 'dark';
const MODES: { id: Mode; label: string; Icon: typeof Sun }[] = [
  { id: 'system', label: 'System', Icon: Monitor },
  { id: 'light', label: 'Light', Icon: Sun },
  { id: 'dark', label: 'Dark', Icon: Moon },
];

const THEME_KEY = 'deadbyte-theme';
const MODE_KEY = 'deadbyte-mode';
const CUSTOM_KEY = 'deadbyte-custom-color';
const DEFAULT_CUSTOM = '#8b5cf6';

export function loadTheme(): string {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    return saved === 'custom' || THEMES.some((t) => t.id === saved) ? (saved as string) : 'purple';
  } catch {
    return 'purple';
  }
}

export function loadMode(): Mode {
  try {
    const saved = localStorage.getItem(MODE_KEY);
    return saved === 'light' || saved === 'dark' || saved === 'system' ? saved : 'system';
  } catch {
    return 'system';
  }
}

export function loadCustom(): string {
  try {
    const saved = localStorage.getItem(CUSTOM_KEY);
    return saved && /^#[0-9a-fA-F]{6}$/.test(saved) ? saved : DEFAULT_CUSTOM;
  } catch {
    return DEFAULT_CUSTOM;
  }
}

// ---------- Custom color helpers ----------
// Works out the color's hue (0-360) so the banner picture can be tinted to match.
function hueOf(hex: string): number {
  const r = parseInt(hex.slice(1, 3), 16) / 255;
  const g = parseInt(hex.slice(3, 5), 16) / 255;
  const b = parseInt(hex.slice(5, 7), 16) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const d = max - min;
  if (d === 0) return 270;
  let h: number;
  if (max === r) h = ((g - b) / d) % 6;
  else if (max === g) h = (b - r) / d + 2;
  else h = (r - g) / d + 4;
  h *= 60;
  return h < 0 ? h + 360 : h;
}

function applyCustom(hex: string) {
  const s = document.documentElement.style;
  s.setProperty('--custom', hex);
  s.setProperty('--banner-rotate', `${Math.round(hueOf(hex) - 270)}deg`);
}

function clearCustom() {
  const s = document.documentElement.style;
  s.removeProperty('--custom');
  s.removeProperty('--banner-rotate');
}

// ---------- Light / dark helpers ----------
function resolveMode(pref: Mode): 'light' | 'dark' {
  if (pref === 'system') {
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  return pref;
}

let listening = false;

export function applyMode(pref: Mode) {
  document.documentElement.setAttribute('data-mode', resolveMode(pref));
  if (!listening) {
    listening = true;
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
      if (loadMode() === 'system') applyMode('system');
    });
  }
}

// workspace.tsx already calls applyTheme(loadTheme()) on startup, so this
// also applies the saved mode and custom color. No other edit needed.
export function applyTheme(id: string) {
  document.documentElement.setAttribute('data-theme', id);
  if (id === 'custom') applyCustom(loadCustom());
  else clearCustom();
  applyMode(loadMode());
}

export function ThemePicker() {
  const [theme, setTheme] = useState('purple');
  const [mode, setMode] = useState<Mode>('system');
  const [custom, setCustom] = useState(DEFAULT_CUSTOM);

  useEffect(() => {
    setTheme(loadTheme());
    setMode(loadMode());
    setCustom(loadCustom());
  }, []);

  function chooseTheme(id: string) {
    setTheme(id);
    try {
      localStorage.setItem(THEME_KEY, id);
    } catch {
      /* storage blocked */
    }
    applyTheme(id);
  }

  function chooseCustom(hex: string) {
    setCustom(hex);
    setTheme('custom');
    try {
      localStorage.setItem(CUSTOM_KEY, hex);
      localStorage.setItem(THEME_KEY, 'custom');
    } catch {
      /* storage blocked */
    }
    document.documentElement.setAttribute('data-theme', 'custom');
    applyCustom(hex);
  }

  function chooseMode(m: Mode) {
    setMode(m);
    try {
      localStorage.setItem(MODE_KEY, m);
    } catch {
      /* storage blocked */
    }
    applyMode(m);
  }

  return (
    <div className="theme-controls">
      <div className="mode-toggle" role="group" aria-label="Color mode">
        {MODES.map(({ id, label, Icon }) => (
          <button
            key={id}
            type="button"
            className="mode-btn"
            aria-pressed={mode === id}
            onClick={() => chooseMode(id)}
          >
            <Icon size={14} />
            {label}
          </button>
        ))}
      </div>
      <div className="theme-swatches" role="group" aria-label="Accent color">
        {THEMES.map((t) => (
          <button
            key={t.id}
            type="button"
            className="theme-swatch"
            style={{ background: t.color }}
            aria-label={t.label}
            title={t.label}
            aria-pressed={theme === t.id}
            onClick={() => chooseTheme(t.id)}
          />
        ))}
        <label
          className={`theme-swatch custom-swatch${theme === 'custom' ? ' is-active' : ''}`}
          style={theme === 'custom' ? { background: custom } : undefined}
          title="Custom color"
        >
          <input
            type="color"
            value={custom}
            aria-label="Custom color"
            onChange={(e) => chooseCustom(e.target.value)}
          />
        </label>
      </div>
    </div>
  );
}
