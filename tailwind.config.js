/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0d1117",
        surface: "#161b22",
        border: "#30363d",
        primary: "#3fb950",
        "primary-hover": "#46c957",
        "text-main": "#e6edf3",
        "text-muted": "#8b949e",
        danger: "#f85149",
        "danger-hover": "#ff6a63",
      },
      animation: {
        pulse: "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [],
};
