import crypto from "node:crypto";
import express from "express";
import path from "node:path";
import jose from "node-jose";
import JWT from "jsonwebtoken";
import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert";
import { db } from "./db"
import { usersTable, applicationsTable, authorizationCodesTable, refreshTokensTable } from "./db/schema";
import { eq, and, lte } from "drizzle-orm";
import type { JWTClaims } from "./utils/user-token";

const app = express();

const PORT = process.env.PORT ?? 8000;


app.use(express.json());
app.use(express.static(path.resolve("public")));

app.get("/", (req, res) => {
    res.json({ message: "Hello from Auth Server" })
});

app.get("/health", (req, res) => {
    res.json({ message: "Server is healthy", healthy: true })
});

app.get("/admin", (req, res) => {
  res.sendFile(path.resolve("public", "admin.html"));
});

app.post("/admin/application", async (req, res) => {
  const { name, url, redirectUri } = req.body;

  if (!name || !url || !redirectUri) {
    res.status(400).json({ message: "Name, URL, and Redirect URI are required" });
    return;
  }

  const secret = crypto.randomBytes(32).toString("hex");

  const [newApplication] = await db.insert(applicationsTable).values({
    name,
    url,
    redirectUri,
    secret,
  }).returning();

  if (!newApplication) {
    res.status(500).json({ message: "Failed to create application" });
    return;
  }

  res.status(201).json({
    client_id: newApplication.id,
    client_secret: newApplication.secret,
  });
});

app.get("/o/application-info", async (req, res) => {
  const { client_id } = req.query;

  if (!client_id || typeof client_id !== "string") {
    res.status(400).json({ message: "client_id is required" });
    return;
  }

  const [application] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.id, client_id))
    .limit(1);

  if (!application) {
    res.status(404).json({ message: "Application not found" });
    return;
  }

  res.json({
    name: application.name,
    url: application.url,
  });
});

app.get("/.well-known/openid-configuration", (req, res) => {
    const ISSUER = `http://localhost:${PORT}`;
    return res.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/o/authenticate`,
        userinfo_endpoint: `${ISSUER}/o/userinfo`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        token_endpoint: `${ISSUER}/o/tokeninfo`,
    })
});

app.post("/o/tokeninfo", async (req, res) => {
  const { code, client_secret, code_verifier, refresh_token, grant_type } = req.body;

  if (!client_secret) {
    res.status(400).json({ message: "client_secret is required" });
    return;
  }

  
  const [application] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.secret, client_secret))
    .limit(1);

  if (!application) {
    res.status(401).json({ message: "Invalid client_secret" });
    return;
  }

  const ISSUER = `http://localhost:${PORT}`;
  const now = Math.floor(Date.now() / 1000);

  let userId: string;

  if (grant_type === "refresh_token") {
    if (!refresh_token) {
      res.status(400).json({ message: "refresh_token is required" });
      return;
    }

    const refreshTokenHash = crypto.createHash("sha256").update(refresh_token).digest("hex");

    const [tokenRecord] = await db
      .select()
      .from(refreshTokensTable)
      .where(
        and(
          eq(refreshTokensTable.tokenHash, refreshTokenHash),
          eq(refreshTokensTable.applicationId, application.id)
        )
      )
      .limit(1);

    if (!tokenRecord) {
      res.status(400).json({ message: "Invalid refresh token" });
      return;
    }

    
    if (tokenRecord.consumedAt || tokenRecord.revokedAt) {
      
      await db
        .update(refreshTokensTable)
        .set({ revokedAt: new Date() })
        .where(
          and(
            eq(refreshTokensTable.userId, tokenRecord.userId),
            eq(refreshTokensTable.applicationId, application.id)
          )
        );
      res.status(401).json({ message: "Refresh token reuse detected. All sessions revoked." });
      return;
    }

    if (tokenRecord.expiresAt < new Date()) {
      res.status(400).json({ message: "Refresh token expired" });
      return;
    }

    userId = tokenRecord.userId;

    
    const newRefreshToken = crypto.randomBytes(40).toString("hex");
    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");
    
    
    const [newTokenRecord] = await db.insert(refreshTokensTable).values({
      tokenHash: newRefreshTokenHash,
      userId: userId,
      applicationId: application.id,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    }).returning();

    if (!newTokenRecord) {
      res.status(500).json({ message: "Failed to generate new refresh token" });
      return;
    }

    await db.update(refreshTokensTable).set({
      consumedAt: new Date(),
      replacedByTokenId: newTokenRecord.id
    }).where(eq(refreshTokensTable.id, tokenRecord.id));

    const [user] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, userId))
      .limit(1);

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    const claims: JWTClaims = {
      iss: ISSUER,
      sub: user.id,
      email: user.email,
      email_verified: String(user.emailVerified),
      exp: now + 3600,
      given_name: user.firstName ?? "",
      family_name: user.lastName ?? undefined,
      name: [user.firstName, user.lastName].filter(Boolean).join(" "),
      picture: user.profileImageURL ?? undefined,
    };

    const accessToken = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

    res.json({
      access_token: accessToken,
      refresh_token: newRefreshToken,
      token_type: "Bearer",
      expires_in: 3600,
    });
    return;
  } else {
    // Default to authorization_code grant
    if (!code) {
      res.status(400).json({ message: "code is required" });
      return;
    }

    // validate the short code
    const [authCode] = await db
      .select()
      .from(authorizationCodesTable)
      .where(
        and(
          eq(authorizationCodesTable.code, code),
          eq(authorizationCodesTable.applicationId, application.id)
        )
      )
      .limit(1);

    if (!authCode) {
      res.status(400).json({ message: "Invalid or expired code" });
      return;
    }

    if (authCode.expiresAt < new Date()) {
      res.status(400).json({ message: "Code has expired" });
      return;
    }

    
    if (authCode.codeChallenge) {
      if (!code_verifier) {
        res.status(400).json({
          message: "code_verifier is required",
        });
        return;
      }

      let generatedChallenge: string;

      if (
        authCode.codeChallengeMethod === "S256" ||
        !authCode.codeChallengeMethod
      ) {
        generatedChallenge = crypto
          .createHash("sha256")
          .update(code_verifier)
          .digest("base64url");
      } else if (authCode.codeChallengeMethod === "plain") {
        generatedChallenge = code_verifier;
      } else {
        res.status(400).json({
          message: "Unsupported code challenge method",
        });
        return;
      }

      if (generatedChallenge !== authCode.codeChallenge) {
        res.status(400).json({
          message: "Invalid code_verifier",
        });
        return;
      }
    }

    const [user] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, authCode.userId))
      .limit(1);

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    userId = user.id;

    const claims: JWTClaims = {
      iss: ISSUER,
      sub: user.id,
      email: user.email,
      email_verified: String(user.emailVerified),
      exp: now + 3600,
      given_name: user.firstName ?? "",
      family_name: user.lastName ?? undefined,
      name: [user.firstName, user.lastName].filter(Boolean).join(" "),
      picture: user.profileImageURL ?? undefined,
    };

    const accessToken = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });
    const refreshToken = crypto.randomBytes(40).toString("hex");
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    await db.insert(refreshTokensTable).values({
      tokenHash: refreshTokenHash,
      userId: userId,
      applicationId: application.id,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    });

    // Optional: Delete the code after use
    await db.delete(authorizationCodesTable).where(eq(authorizationCodesTable.id, authCode.id));

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: 3600,
    });
  }
});

app.get("/.well-known/jwks.json", async (req, res) => {
    const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
    return res.json({ keys: [key.toJSON()] });
});

app.get("/o/authenticate", (req, res) => {
  const {
    client_id,
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method,
  } = req.query;

  return res.sendFile(path.resolve("public", "authenticate.html"));
});

app.get("/o/signup", (req, res) => {
  return res.sendFile(path.resolve("public", "signup.html"));
});

app.post("/o/authenticate/sign-in", async (req, res) => {
  const { 
    email,
    password,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
   } = req.body;

  if(!email || !password) {
    res.status(400).json({ message: "Email and password are required" });
    return;
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if(!user || !user.password || !user.salt) {
    res.status(401).json({ message: "Invalid email or password" });
    return;
  }

  const hash = crypto
    .createHash("sha256")
    .update(password + user.salt)
    .digest("hex");

  if (hash !== user.password) {
    res.status(401).json({ message: "Invalid email or password" });
    return;
  }

  if (client_id) {
    const [application] = await db
      .select()
      .from(applicationsTable)
      .where(eq(applicationsTable.id, client_id))
      .limit(1);

    if (!application) {
      res.status(400).json({ message: "Invalid client_id" });
      return;
    }

    // Optional: validate redirect_uri matches
    // if (redirect_uri && application.redirectUri !== redirect_uri) {
    //   res.status(400).json({ message: "Invalid redirect_uri" });
    //   return;
    // }

    const code = crypto.randomBytes(16).toString("hex");
    const expiresAt = new Date(Date.now() + 60 * 1000); // 1 minute

    await db.insert(authorizationCodesTable).values({
      code,
      userId: user.id,
      applicationId: application.id,
      expiresAt,
      codeChallenge: code_challenge ?? null,
      codeChallengeMethod: code_challenge_method ?? "S256",
    });

    const redirectUrl = new URL(application.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (req.body.state) redirectUrl.searchParams.set("state", req.body.state);

    res.json({ redirect: redirectUrl.toString() });
    return;
  }

  const ISSUER = `http://localhost:${PORT}`;
  const now = Math.floor(Date.now() / 1000);

  const claims: JWTClaims = {
    iss: ISSUER,
    sub: user.id,
    email: user.email,
    email_verified: String(user.emailVerified),
    exp: now + 3600,
    given_name: user.firstName ?? "",
    family_name: user.lastName ?? undefined,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL ?? undefined,
  };

  const token = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

  res.json({ token });

});


app.post("/o/authenticate/sign-up", async (req, res) => {
  const { 
    firstName,
    lastName,
    email,
    password,
    client_id,
    code_challenge,
    code_challenge_method,
   } = req.body;

  if (!email || !password || !firstName) {
    res
      .status(400)
      .json({ message: "First name, email, and password are required." });
    return;
  }

  const [existing] = await db
    .select({ id: usersTable.id })
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (existing) {
    res
      .status(409)
      .json({ message: "An account with this email already exists." });
    return;
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .createHash("sha256")
    .update(password + salt)
    .digest("hex");

  const [newUser] = await db.insert(usersTable).values({
    firstName,
    lastName: lastName ?? null,
    email,
    password: hash,
    salt,
  }).returning();

  if (client_id && newUser) {
    const [application] = await db
      .select()
      .from(applicationsTable)
      .where(eq(applicationsTable.id, client_id))
      .limit(1);

    if (application) {
        const code = crypto.randomBytes(16).toString("hex");
        const expiresAt = new Date(Date.now() + 60 * 1000); // 1 minute

        await db.insert(authorizationCodesTable).values({
          code,
          userId: newUser.id,
          applicationId: application.id,
          expiresAt,
          codeChallenge: code_challenge ?? null,
          codeChallengeMethod: code_challenge_method ?? "S256",
        });

        const redirectUrl = new URL(application.redirectUri);
        redirectUrl.searchParams.set("code", code);
        if (req.body.state) redirectUrl.searchParams.set("state", req.body.state);

        res.status(201).json({ ok: true, redirect: redirectUrl.toString() });
        return;
    }
  }

  res.status(201).json({ ok: true });
});

app.get("/o/userinfo", async (req, res) => {
    const authHeader = req.headers.authorization;

    if(!authHeader?.startsWith("Bearer ")){
        res.status(401).json({ message: "Missing or invalid Authorization header" });
        return;
    }

    const token = authHeader.slice(7);

    let claims: JWTClaims;
    try{
        claims = JWT.verify(token, PUBLIC_KEY, {
            algorithms: ["RS256"]
        }) as JWTClaims;
    } catch {
        res.status(401).json({ message: "Invalid or expired token" });
        return;
    }

    const [user] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.id, claims.sub))
        .limit(1)

    if(!user) {
        res.status(404).json({ message: "User is not found" })
        return;
    }

    res.json({
        sub: user.id,
        email: user.email,
        email_verified: user.emailVerified,
        given_name: user.firstName,
        family_name: user.lastName,
        name: [user.firstName, user.lastName].filter(Boolean).join(" "),
        picture: user.profileImageURL,
    });
});



app.listen(PORT, () => {
    console.log(`Auth server is running on port ${PORT}`)
})

