FROM node:16-alpine

WORKDIR /app

# Install necessary packages for networking and SSL support
RUN apk add --no-cache iputils openssl netcat-openbsd

# Create directories for keys and received files
RUN mkdir -p /app/keys /app/received-files

# Create package.json
COPY package*.json ./
RUN npm install

# Copy source files
COPY localSharing.js ./
COPY example-run.js ./

# Create a test file to send
RUN echo "This is a test file for LocalSharing with SSL/TLS encryption" > example-file.txt

# Script to verify certificates
RUN echo '#!/bin/sh\n\
if [ -f "$1" ]; then\n\
  openssl x509 -in "$1" -text -noout\n\
else\n\
  echo "Certificate file not found: $1"\n\
fi' > verify-cert.sh && chmod +x verify-cert.sh

# Handle trust endpoint
RUN echo 'const http = require("http");\
const fs = require("fs");\
console.log("Starting trust server...");\
const server = http.createServer((req, res) => {\
  if (req.method === "POST" && req.url === "/trust") {\
    let data = "";\
    req.on("data", chunk => { data += chunk; });\
    req.on("end", () => {\
      try {\
        console.log("Received trust request");\
        const body = JSON.parse(data);\
        if (!body.deviceId || !body.certificate) {\
          res.writeHead(400);\
          res.end(JSON.stringify({error:"Missing required fields"}));\
          return;\
        }\
        const trustFile = `/app/keys/${body.deviceId}_trusted_cert.pem`;\
        fs.writeFileSync(trustFile, body.certificate);\
        console.log(`Certificate for ${body.deviceId} stored at ${trustFile}`);\
        res.writeHead(200);\
        res.end(JSON.stringify({status:"success"}));\
      } catch(e) {\
        console.error("Error processing request:", e);\
        res.writeHead(500);\
        res.end(JSON.stringify({error:e.message}));\
      }\
    });\
  } else {\
    res.writeHead(404);\
    res.end();\
  }\
});\
server.listen(3000, () => console.log("Trust server running on port 3000"));\
' > trust-server.js

# Set a healthcheck
HEALTHCHECK --interval=5s --timeout=5s --retries=3 CMD nc -z localhost ${DEVICE_PORT:-8765} || exit 1

# Expose the HTTP/HTTPS and discovery ports
EXPOSE 8765-8769 8766/udp 3000

# Set the command to run the example
CMD ["sh", "-c", "node trust-server.js & node example-run.js"]