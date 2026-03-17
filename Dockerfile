# Distroless Node image: minimal OS, no shell/pkg manager, actively patched (Debian 13).
# Only Node runtime + your app — dramatically fewer CVEs than full distros.
FROM gcr.io/distroless/nodejs22-debian13
WORKDIR /app
COPY hello.js .
EXPOSE 8000
CMD ["hello.js"]
