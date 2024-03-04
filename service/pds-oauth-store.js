const crypto = require("crypto");

const PDSOAuthStore = (pds) => {
  const db = {
    // Here is a fast overview of what your db model should look like
    authorizationCode: {
      authorizationCode: "", // A string that contains the code
      expiresAt: new Date(), // A date when the code expires
      redirectUri: "", // A string of where to redirect to with this code
      client: null, // See the client section
      user: null, // Whatever you want... This is where you can be flexible with the protocol
    },
    client: {
      // Application wanting to authenticate with this server
      id: "application", // Unique string representing the client
      secret: "", // Secret of the client; Can be null
      grants: ["authorization_code", "refresh_token"], // Array of grants that the client can use (ie, `authorization_code`)
      redirectUris: ["http://localhost:2583/client/app"], // Array of urls the client is allowed to redirect to
    },
    token: {
      accessToken: "", // Access token that the server created
      accessTokenExpiresAt: new Date(), // Date the token expires
      client: null, // Client associated with this token
      user: null, // User associated with this token
    },
  };
  return {
    generateAccessToken: (client, user, scope) => {
      console.log("'generateAccessToken' was called!");
      return user.accessToken;
    },

    generateRefreshToken: (client, user, scope) => {
      console.log("'generateRefreshToken' was called!");
      return user.refreshToken;
    },

    /**
     * Invoked to retrieve a client using a client id or a client
     * id/client secret combination, depending on the grant type.
     *
     * @param {*} clientId      The client id of the client to retrieve.
     * @param {*} clientSecret  The client secret of the client to retrieve. Can be null.
     */
    getClient: (clientId, clientSecret) => {
      console.log("'getClient' was called!");
      if (clientId !== "application") return;

      return Promise.resolve(db.client);
    },

    /**
     * Invoked to save an access token and optionally a refresh token,
     * depending on the grant type.
     *
     * @param {Object} token The token(s) to be saved.
     * @param {String} token.accessToken The access token to be saved.
     * @param {Date} token.accessTokenExpiresAt The expiry time of the access token.
     * @param {String} token.refreshToken The refresh token to be saved.
     * @param {Date} token.refreshTokenExpiresAt The expiry time of the refresh token.
     * @param {String} token.scope The authorized scope of the token(s).
     * @param {Object} client The client associated with the token(s).
     * @param {Object} user The user associated with the token(s).
     */
    saveToken: (token, client, user) => {
      console.log("'saveToken' was called!");

      db.token = {
        accessToken: token.accessToken,
        accessTokenExpiresAt: token.accessTokenExpiresAt,
        refreshToken: token.refreshToken, // NOTE this is only needed if you need refresh tokens down the line
        refreshTokenExpiresAt: token.refreshTokenExpiresAt,
        client: client,
        user: user,
      };
      return db.token;
    },

    validateScope: (user, client, scope) => {
      // providing a default, unsure if necessary long-term
      return scope || "email";
    },

    /**
     * Invoked to retrieve an existing refresh token previously saved through Model#saveToken().
     *
     * @param {String} refreshToken The access token to retrieve.
     * @returns {Object} An Object representing the refresh token and associated data.
     * See: https://oauth2-server.readthedocs.io/en/latest/model/spec.html#model-getrefreshtoken
     */
    getRefreshToken: async (refreshToken) => {
      console.log("'getRefreshToken' was called!");
      const refreshSessionRes = await fetch(
        `http://localhost:${pds.ctx.cfg.service.port}/xrpc/com.atproto.server.refreshSession`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${refreshToken}`,
          },
        }
      );
      const response = await refreshSessionRes.json();

      return {
        client: {
          id: "application",
        },
        user: {
          accessToken: response.accessJwt,
          refreshToken: response.refreshJwt,
        },
        accessToken: response.accessJwt,
        refreshToken: response.refreshJwt,
      };
    },

    /**
     * Invoked to revoke a refresh token.
     *
     * @param {Object} token The token to be revoked.
     * @param {String} token.refreshToken The refresh token.
     * @param {Date}   token.refreshTokenExpiresAt The expiry time of the refresh token.
     * @param {String} token.scope The authorized scope of the refresh token.
     * @param {Object} token.client The client associated with the refresh token.
     * @param {String} token.client.id A unique string identifying the client.
     * @param {Object} token.user The user associated with the refresh token.
     * @returns {Boolean} Return true if the revocation was successful or false if the refresh token could not be found.
     */
    revokeToken: async (token) => {
      return true;
    },

    /**
     * Invoked to retrieve an existing access token previously saved through Model#saveToken().
     *
     * @param {String} token The access token to retrieve.
     */
    getAccessToken: (token) => {
      console.log("'getAccessToken' was called!");
      if (!token || token === "undefined") return false;
      return Promise.resolve(db.token);
    },

    saveAuthorizationCode: (code, client, user) => {
      console.log("'saveAuthorizationCode' was called!");
      db.authorizationCode = {
        authorizationCode: code.authorizationCode,
        expiresAt: code.expiresAt,
        client: client,
        user: user,
      };
      return Promise.resolve(
        Object.assign(
          {
            redirectUri: `${code.redirectUri}`,
          },
          db.authorizationCode
        )
      );
    },

    getAuthorizationCode: (authorizationCode) => {
      /* this is where we fetch the stored data from the code */
      return Promise.resolve(db.authorizationCode);
    },
    revokeAuthorizationCode: (authorizationCode) => {
      /* This is where we delete codes */
      db.authorizationCode = {
        // DB Delete in this in memory example :)
        authorizationCode: "", // A string that contains the code
        expiresAt: new Date(), // A date when the code expires
        redirectUri: "", // A string of where to redirect to with this code
        client: null, // See the client section
        user: null, // Whatever you want... This is where you can be flexible with the protocol
      };
      const codeWasFoundAndDeleted = true; // Return true if code found and deleted, false otherwise
      return Promise.resolve(codeWasFoundAndDeleted);
    },
  };
};

module.exports = PDSOAuthStore;
