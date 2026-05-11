import {
  uuid,
  pgTable,
  varchar,
  text,
  boolean,
  timestamp,
} from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),

  firstName: varchar("first_name", { length: 25 }),
  lastName: varchar("last_name", { length: 25 }),

  profileImageURL: text("profile_image_url"),

  email: varchar("email", { length: 322 }).notNull(),
  emailVerified: boolean("email_verified").default(false).notNull(),

  password: varchar("password", { length: 66 }),
  salt: text("salt"),

  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});

export const applicationsTable = pgTable("applications", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: varchar("name", { length: 255 }).notNull(),
  url: varchar("url", { length: 255 }).notNull(),
  redirectUri: varchar("redirect_uri", { length: 255 }).notNull(),
  secret: varchar("secret", { length: 255 }).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const authorizationCodesTable = pgTable("authorization_codes", {
  id: uuid("id").primaryKey().defaultRandom(),
  code: varchar("code", { length: 255 }).notNull(),
  codeChallenge: text("code_challenge"),
  codeChallengeMethod: varchar("code_challenge_method", { length: 10 }),
  userId: uuid("user_id").references(() => usersTable.id).notNull(),
  applicationId: uuid("application_id").references(() => applicationsTable.id).notNull(),
  expiresAt: timestamp("expires_at").notNull(),
});

export const refreshTokensTable = pgTable("refresh_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  tokenHash: text("token_hash").notNull(),
  userId: uuid("user_id").references(() => usersTable.id).notNull(),
  applicationId: uuid("application_id").references(() => applicationsTable.id).notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  consumedAt: timestamp("consumed_at"),
  replacedByTokenId: uuid("replaced_by_token_id"), // for rotation tracking
  revokedAt: timestamp("revoked_at"),
});