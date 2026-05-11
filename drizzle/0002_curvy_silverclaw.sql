CREATE TABLE "refresh_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"token_hash" text NOT NULL,
	"user_id" uuid NOT NULL,
	"application_id" uuid NOT NULL,
	"expires_at" timestamp NOT NULL,
	"consumed_at" timestamp,
	"replaced_by_token_id" uuid,
	"revoked_at" timestamp
);
--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD COLUMN "code_challenge" text;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD COLUMN "code_challenge_method" varchar(10);--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_application_id_applications_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."applications"("id") ON DELETE no action ON UPDATE no action;