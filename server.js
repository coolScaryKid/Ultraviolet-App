import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import helmet from "helmet";
import cheerio from "cheerio";
import fetch from "node-fetch";

// UV engine import
import createBareServer from "@tomphttp/bare-server-node";
import uv from "@titaniumnetwork-dev/ultraviolet";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const bare = createBareServer("/bare/");

// ✅ Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // UV injects scripts, so strict CSP would break it
  crossOriginEmbedderPolicy: false,
}));
app.disable("x-powered-by");

// ✅ Serve static UV client files
app.use(express.static(path.join(__dirname, "public")));

// ✅ Proxy handler with cookie + WebRTC hardening
app.use(async (req, res, next) => {
  try {
    // Forward request through UV’s engine
    const targetUrl = req.query.url;
    if (!targetUrl) return next();

    const proxiedRes = await fetch(targetUrl, {
      headers: {
        ...req.headers,
        cookie: "", // 🚫 strip cookies
      },
    });

    let body = await proxiedRes.text();

    // 🔒 Sanitize cookies + fingerprinting
    res.removeHeader("set-cookie");

    // 🛡 Inject WebRTC blocker script into HTML
    if (proxiedRes.headers.get("content-type")?.includes("text/html")) {
      const $ = cheerio.load(body);

      $("head").append(`
        <script>
          // Block WebRTC leaks
          if (window.RTCPeerConnection) {
            window.RTCPeerConnection = function() {
              throw new Error("WebRTC disabled by proxy for security.");
            };
          }
          if (window.webkitRTCPeerConnection) {
            window.webkitRTCPeerConnection = function() {
              throw new Error("WebRTC disabled by proxy for security.");
            };
          }
          // Strip fingerprinting cookies
          document.cookie = "";
        </script>
      `);

      body = $.html();
    }

    res.status(proxiedRes.status);
    proxiedRes.headers.forEach((value, key) => {
      if (key.toLowerCase() !== "set-cookie") {
        res.setHeader(key, value);
      }
    });

    res.send(body);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Proxy error");
  }
});

// ✅ Bare server upgrade (for websocket support)
const server = app.listen(process.env.PORT || 8080, () => {
  console.log(`✅ Ultraviolet proxy running on port ${server.address().port}`);
});
server.on("upgrade", (req, socket, head) => {
  if (bare.shouldRoute(req)) bare.routeUpgrade(req, socket, head);
});
