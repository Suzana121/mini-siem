# mini-siem web

React 18 + TypeScript + Vite dashboard for the mini-siem API.

## Dev

    npm ci
    npm run dev        # http://localhost:5173, API paths proxied to http://localhost:8000

Set `VITE_API_TARGET` to proxy to a different backend.

## Build and check

    npm run build      # typecheck + bundle into web/dist (served by FastAPI at /)
    npm run typecheck
    npm test
