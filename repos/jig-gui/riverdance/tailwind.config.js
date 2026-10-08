/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./ui/src/**/*.rs",
    "./web/src/**/*.rs",
    "./desktop/src/**/*.rs",
    "./mobile/src/**/*.rs",
    "./api/src/**/*.rs",
  ],
  theme: {
    extend: {
      colors: {
        gray: {
          50: '#fafafa',
          100: '#f5f5f5',
          150: '#eeeeee',
          200: '#e5e5e5',
          250: '#dedede',
          300: '#d4d4d4',
          350: '#c7c7c7',
          400: '#a3a3a3',
          450: '#8a8a8a',
          500: '#737373',
          550: '#5e5e5e',
          600: '#525252',
          650: '#464646',
          700: '#404040',
          750: '#363636',
          800: '#262626',
          850: '#1f1f1f',
          900: '#171717',
          950: '#0a0a0a',
        },
      },
      fontFamily: {
        sans: ['system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', 'source-code-pro', 'Menlo', 'monospace'],
      },
    },
  },
}