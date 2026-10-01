FROM node
WORKDIR /app
ARG STRIPE_SECRET_KEY
COPY . .
RUN npm ci && npm run build
CMD ["npm", "start"]
