"use strict";
require("dotenv").config();
const path = require("path");
const {
  PDS,
  envToCfg,
  envToSecrets,
  readEnv,
  httpLogger,
} = require("@atproto/pds");
const pkg = require("@atproto/pds/package.json");
const OAuthServer = require("@node-oauth/express-oauth-server");
const bodyParser = require("body-parser");
const PDSOAuthStore = require("./pds-oauth-store");

const main = async () => {
  const env = readEnv();
  env.version ||= pkg.version;
  const cfg = envToCfg(env);
  const secrets = envToSecrets(env);
  const pds = await PDS.create(cfg, secrets);
  pds.app.use(bodyParser.json());
  pds.app.use(bodyParser.urlencoded({ extended: false }));

  pds.app.oauth = new OAuthServer({
    model: PDSOAuthStore(pds),
    grants: ["password", "refresh_token", "authorization_code"],
    debug: true,
    continueMiddleware: false,
    requireClientAuthentication: { password: false },
    accessTokenLifetime: 60 * 2, // two hours,
    refreshTokenLifetime: 60 * 24 * 30 * 2, // two months
    allowEmptyState: true,
    allowExtendedTokenAttributes: true,
  });

  pds.app.get("/tls-check", (req, res) => {
    checkHandleRoute(pds, req, res);
  });

  pds.app.get("/client", (req, res) =>
    res.sendFile(path.join(__dirname, "./public/clientAuthenticate.html"))
  );

  pds.app.get("/client/app", (req, res) =>
    res.sendFile(path.join(__dirname, "./public/clientApp.html"))
  );

  pds.app.get("/oauth", (req, res) =>
    res.sendFile(path.join(__dirname, "./public/oauthAuthenticate.html"))
  );

  pds.app.post(
    "/oauth/authorize",
    async (req, res, next) => {
      const { username, password } = req.body;
      const createSessionRes = await fetch(
        `http://localhost:${pds.ctx.cfg.service.port}/xrpc/com.atproto.server.createSession`,
        {
          method: "POST",
          body: JSON.stringify({
            identifier: username,
            password,
          }),
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      const response = await createSessionRes.json();
      if (response.accessJwt) {
        req.body.access_token = response.accessJwt;
        req.body.user = {
          accessToken: response.accessJwt,
          refreshToken: response.refreshJwt,
        };
        return next();
      }
      const params = [
        // Send params back down
        "client_id",
        "redirect_uri",
        "response_type",
        "grant_type",
        "state",
      ]
        .map((a) => `${a}=${req.body[a]}`)
        .join("&");
      return res.redirect(`/oauth?success=false&${params}`);
    },
    (req, res, next) => {
      return next();
    },
    pds.app.oauth.authorize({
      authenticateHandler: {
        handle: (req) => {
          console.log("Authenticate Handler");
          return req.body.user;
        },
      },
    })
  );

  pds.app.post(
    "/oauth/token",
    pds.app.oauth.token({
      requireClientAuthentication: {},
    })
  );
  pds.app.get("/secure/", pds.app.oauth.authenticate(), (req, res) => {
    res.json({ success: true });
  });

  await pds.start();
  httpLogger.info("pds has started");

  process.on("SIGTERM", async () => {
    httpLogger.info("pds is stopping");
    await pds.destroy();
    httpLogger.info("pds is stopped");
  });
};

async function checkHandleRoute(
  /** @type {PDS} */ pds,
  /** @type {import('express').Request} */ req,
  /** @type {import('express').Response} */ res
) {
  try {
    const { domain } = req.query;
    if (!domain || typeof domain !== "string") {
      return res.status(400).json({
        error: "InvalidRequest",
        message: "bad or missing domain query param",
      });
    }
    if (domain === pds.ctx.cfg.service.hostname) {
      return res.json({ success: true });
    }
    const isHostedHandle = pds.ctx.cfg.identity.serviceHandleDomains.find(
      (avail) => domain.endsWith(avail)
    );
    if (!isHostedHandle) {
      return res.status(400).json({
        error: "InvalidRequest",
        message: "handles are not provided on this domain",
      });
    }
    const account = await pds.ctx.accountManager.getAccount(domain);
    if (!account) {
      return res.status(404).json({
        error: "NotFound",
        message: "handle not found for this domain",
      });
    }
    return res.json({ success: true });
  } catch (err) {
    httpLogger.error({ err }, "check handle failed");
    return res.status(500).json({
      error: "InternalServerError",
      message: "Internal Server Error",
    });
  }
}

main();
