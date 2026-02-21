# ============================================================================
# Vigilant Guardian — Dockerfile Frontend (section 4.3)
# Next.js 14 multi-stage — node:20-alpine
# ============================================================================

# === Stage 1: Build ===
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json pnpm-lock.yaml ./

RUN corepack enable && pnpm install --frozen-lockfile

COPY . .

RUN pnpm build

# === Stage 2: Runtime ===
FROM node:20-alpine AS runtime

WORKDIR /app

RUN addgroup -S appuser && adduser -S appuser -G appuser

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

USER appuser

EXPOSE 3000

CMD ["node", "server.js"]
