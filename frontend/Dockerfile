# --- Build stage: compile the Vite + React app to static assets ---
FROM node:24-slim AS build

RUN corepack enable && corepack prepare pnpm@10.25.0 --activate

WORKDIR /app

# Copy manifests first for dependency layer caching.
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Copy the rest of the frontend source and build
COPY . .
RUN pnpm build

# --- Production stage: Nginx serves static files + proxies API ---
FROM nginx:alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built frontend from build stage
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
