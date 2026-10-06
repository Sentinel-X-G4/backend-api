# ============================================
# Dockerfile pour Sentinel-X Backend API
# ============================================

# --- Étape 1: Image de base ---
# Utilise Node.js 20 LTS (version stable à long terme) sur Alpine (léger)
FROM node:20-alpine AS base

# Métadonnées de l'image
LABEL maintainer="Sentinel-X Team"
LABEL description="Backend API pour Sentinel-X - Système de détection d'intrusion"
LABEL version="1.0.0"

# --- Étape 2: Installation des dépendances ---
FROM base AS deps

# Définir le répertoire de travail
WORKDIR /app

# Copier uniquement les fichiers de dépendances (pour optimiser le cache Docker)
COPY package*.json ./

# Installer les dépendances de production uniquement
# --omit=dev exclut les devDependencies
# --legacy-peer-deps évite les conflits de versions
RUN npm ci --omit=dev --legacy-peer-deps && \
    npm cache clean --force

# --- Étape 3: Build (si besoin de compilation TypeScript, etc.) ---
# Pour ce projet en JavaScript pur, cette étape n'est pas nécessaire
# Mais on la garde pour la structure

# --- Étape 4: Image de production ---
FROM base AS production

# Variables d'environnement par défaut
ENV NODE_ENV=production
ENV PORT=3000

# Créer un utilisateur non-root pour la sécurité
# Node.js sur Alpine utilise déjà l'utilisateur 'node' (UID 1000)
# On s'assure que le répertoire lui appartient
RUN addgroup -g 1001 -S sentinel && \
    adduser -S sentinel -u 1001 -G sentinel

WORKDIR /app

# Changer le propriétaire du répertoire de travail
RUN chown -R sentinel:sentinel /app

# Copier les dépendances installées depuis l'étape 'deps'
COPY --from=deps --chown=sentinel:sentinel /app/node_modules ./node_modules

# Copier le code source
COPY --chown=sentinel:sentinel . .

# Passer à l'utilisateur non-root
USER sentinel

# Exposer le port HTTP et WebSocket
EXPOSE 3000

# Health check pour Docker : sur $PORT (forme shell, évaluée à l'exécution), car le
# compose parent lance l'API sur 5678 (port attendu par le reverse proxy)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider "http://localhost:${PORT}/api/health" || exit 1

# Point d'entrée
# Utilise 'node' directement (pas 'npm start' pour éviter un processus shell supplémentaire)
CMD ["node", "server.js"]