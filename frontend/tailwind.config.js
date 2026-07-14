/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    // Overriding the base scale (not extend) on purpose: this flattens every
    // rounded-md/lg/xl usage across the app into a tighter, hairline-panel
    // language in one place, instead of touching each of the ~50 pages.
    borderRadius: {
      none: '0px',
      sm: '2px',
      DEFAULT: '3px',
      md: '3px',
      lg: '4px',
      xl: '6px',
      '2xl': '8px',
      '3xl': '10px',
      full: '9999px',
    },
    extend: {
      colors: {
        surface: {
          DEFAULT: 'rgb(var(--surface-0) / <alpha-value>)',
          1: 'rgb(var(--surface-1) / <alpha-value>)',
          2: 'rgb(var(--surface-2) / <alpha-value>)',
          3: 'rgb(var(--surface-3) / <alpha-value>)',
          4: 'rgb(var(--surface-4) / <alpha-value>)',
        },
        border: {
          DEFAULT: 'rgb(var(--border) / <alpha-value>)',
          muted: 'rgb(var(--border-muted) / <alpha-value>)',
        },
        text: {
          primary: 'rgb(var(--text-primary) / <alpha-value>)',
          secondary: 'rgb(var(--text-secondary) / <alpha-value>)',
          muted: 'rgb(var(--text-muted) / <alpha-value>)',
        },
        accent: {
          cyan: 'rgb(var(--accent-cyan) / <alpha-value>)',
          green: 'rgb(var(--accent-green) / <alpha-value>)',
          red: 'rgb(var(--accent-red) / <alpha-value>)',
          orange: 'rgb(var(--accent-orange) / <alpha-value>)',
          yellow: 'rgb(var(--accent-yellow) / <alpha-value>)',
          purple: 'rgb(var(--accent-purple) / <alpha-value>)',
          blue: 'rgb(var(--accent-blue) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'monospace'],
        display: ['"JetBrains Mono"', '"IBM Plex Mono"', 'monospace'],
      },
      boxShadow: {
        xs: '0 1px 2px 0 rgba(18, 21, 28, 0.04)',
        sm: '0 1px 2px 0 rgba(18, 21, 28, 0.05), 0 1px 1px 0 rgba(18, 21, 28, 0.03)',
        card: '0 1px 2px 0 rgba(18, 21, 28, 0.04), 0 1px 8px -2px rgba(18, 21, 28, 0.07)',
        'card-hover': '0 4px 14px -2px rgba(18, 21, 28, 0.10), 0 2px 4px -2px rgba(18, 21, 28, 0.06)',
        popover: '0 14px 34px -6px rgba(18, 21, 28, 0.16), 0 4px 10px -4px rgba(18, 21, 28, 0.08)',
        glow: '0 0 0 1px rgba(138, 75, 10, 0.14), 0 4px 14px -4px rgba(138, 75, 10, 0.22)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-up': 'slideUp 0.2s ease-out',
        shimmer: 'shimmer 2.2s linear infinite',
        scan: 'scan 2.4s linear infinite',
      },
      keyframes: {
        fadeIn: { from: { opacity: '0' }, to: { opacity: '1' } },
        slideUp: { from: { transform: 'translateY(8px)', opacity: '0' }, to: { transform: 'translateY(0)', opacity: '1' } },
        shimmer: { from: { backgroundPosition: '200% 0' }, to: { backgroundPosition: '-200% 0' } },
        scan: { from: { transform: 'translateX(-100%)' }, to: { transform: 'translateX(100%)' } },
      },
    },
  },
  plugins: [],
}
