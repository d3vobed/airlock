# AIRLOCK — Team C Frontend Notes

## Bugs found + fixed
- Missing frontend/postcss.config.mjs → Tailwind wasn't compiling at all → added tailwindcss+autoprefixer config
- app/layout.tsx never imported globals.css → styles never reached the browser → added import

## Bugs found, still open
- Passport panel shows sandbox.ok mismatched vs Decision card for same admission (decision said "clean", passport said "blocked")
