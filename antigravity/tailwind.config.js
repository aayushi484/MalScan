/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'neo-bg-light': '#E0E5EC',
        'neo-bg-dark': '#131419',
        'neo-accent-blue': '#4D77FF',
        'neo-accent-mint': '#00D1B2',
      },
      boxShadow: {
        'neumorph-out': '-9px -9px 16px rgba(255, 255, 255, 0.5), 9px 9px 16px rgba(163, 177, 198, 0.6)',
        'neumorph-in': 'inset -9px -9px 16px rgba(255, 255, 255, 0.5), inset 9px 9px 16px rgba(163, 177, 198, 0.6)',
      }
    },
  },
  plugins: [],
}
