import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        neon:    '#00ff41',
        alert:   '#ff0055',
        warn:    '#ff6600',
        caution: '#ffff00',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      boxShadow: {
        glow:       '0 0 4px #00ff41, 0 0 8px #00ff41',
        'glow-lg':  '0 0 8px #00ff41, 0 0 16px #00ff41',
        'glow-alert': '0 0 4px #ff0055, 0 0 8px #ff0055',
      },
      keyframes: {
        flicker: {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0.7' },
        },
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0' },
        },
        sweep: {
          from: { transform: 'rotate(0deg)' },
          to:   { transform: 'rotate(360deg)' },
        },
      },
      animation: {
        flicker:     'flicker 0.15s infinite',
        blink:       'blink 1s step-end infinite',
        'pulse-slow': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        sweep:       'sweep 4s linear infinite',
      },
    },
  },
  plugins: [],
} satisfies Config
