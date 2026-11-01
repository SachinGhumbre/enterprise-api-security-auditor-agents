/** @type {import('tailwindcss').Config} */

// tailwind-scrollbar is declared in devDependencies but is not required for the
// app to build. Loading it optionally keeps `npm start` working on a fresh
// clone where only the root package.json has been installed.
const plugins = [];
try {
  plugins.push(require('tailwind-scrollbar'));
} catch (err) {
  // Plugin not installed - custom scrollbar styles in index.css cover it.
}

module.exports = {
  content: ['./src/**/*.{js,jsx,ts,tsx}', './public/index.html'],
  theme: {
    extend: {
      colors: {
        /**
         * Brand = a single validated blue ramp, light -> dark.
         * Steps are the reference sequential blue scale, so any magnitude
         * encoding (progress meters, tints) stays monotonic in lightness.
         */
        brand: {
          50: '#f3f8fe',
          100: '#cde2fb',
          200: '#9ec5f4',
          300: '#6da7ec',
          400: '#3987e5',
          500: '#2a78d6',
          600: '#256abf',
          700: '#1c5cab',
          800: '#184f95',
          900: '#104281',
          950: '#0d366b',
        },

        /** Page and card surfaces. Light blue throughout - no dark planes. */
        surface: {
          page: '#eef4fc',
          raised: '#ffffff',
          sunken: '#f6f9fe',
          header: '#ffffff',
          rail: '#f7fafe',
        },

        /**
         * Status palette - fixed, never themed, never reused as a series color.
         * warning and serious sit below 3:1 on a light surface by design, so
         * every status mark ships with an icon AND a text label; colour never
         * carries the meaning alone.
         */
        status: {
          good: '#0ca30c',
          warning: '#fab219',
          serious: '#ec835a',
          critical: '#d03b3b',
        },

        /** Text tokens. Values and labels wear these, never a status hue. */
        ink: {
          primary: '#0f1b2d',
          secondary: '#44546b',
          muted: '#73839a',
          hairline: '#d7e3f4',
        },
      },
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px rgba(16,66,129,.05), 0 8px 24px -16px rgba(16,66,129,.28)',
        raised: '0 2px 4px rgba(16,66,129,.06), 0 12px 32px -18px rgba(16,66,129,.34)',
        focus: '0 0 0 3px rgba(42,120,214,.22)',
      },
      keyframes: {
        'fade-up': {
          '0%': { opacity: '0', transform: 'translateY(6px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: { '100%': { transform: 'translateX(100%)' } },
      },
      animation: {
        'fade-up': 'fade-up .35s ease-out both',
        shimmer: 'shimmer 1.6s infinite',
      },
    },
  },
  plugins,
};
