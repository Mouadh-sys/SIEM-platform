FROM nginx:1.27-alpine

# Remove default nginx page
RUN rm -rf /usr/share/nginx/html/*

# Copy static site
COPY src/index.html /usr/share/nginx/html/index.html
COPY src/style.css  /usr/share/nginx/html/style.css
COPY src/app.js     /usr/share/nginx/html/app.js

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
