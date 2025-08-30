FROM node:20-alpine
WORKDIR /app
COPY package.json yarn.lock* package-lock.json* pnpm-lock.yaml* ./
RUN yarn install
COPY tsconfig.json ./
COPY src ./src
RUN yarn build
RUN yarn install --production --ignore-scripts --prefer-offline
ENV PORT=8080 NODE_ENV=production
EXPOSE 8080
CMD ["node","dist/index.js"]
