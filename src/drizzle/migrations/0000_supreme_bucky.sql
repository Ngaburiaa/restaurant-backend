CREATE TYPE "public"."userType" AS ENUM('member', 'admin', 'disabled');--> statement-breakpoint
CREATE TYPE "public"."statusType" AS ENUM('pending', 'canceled', 'completed');--> statement-breakpoint
CREATE TABLE "mealTable" (
	"mealId" serial PRIMARY KEY NOT NULL,
	"mealName" varchar,
	"mealUrl" varchar,
	"mealDescription" varchar NOT NULL,
	"mealPrice" numeric NOT NULL,
	"mealBadge" varchar,
	"rating" integer DEFAULT 0,
	"createdAt" timestamp DEFAULT now(),
	"updatedAt" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "orderTable" (
	"orderId" serial PRIMARY KEY NOT NULL,
	"mealId" integer NOT NULL,
	"userId" integer NOT NULL,
	"statusType" "statusType" DEFAULT 'pending',
	"createdAt" timestamp DEFAULT now(),
	"updatedAt" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "userTable" (
	"userId" serial PRIMARY KEY NOT NULL,
	"firstName" varchar,
	"lastName" varchar,
	"profileUrl" varchar DEFAULT 'null',
	"email" varchar NOT NULL,
	"password" varchar NOT NULL,
	"userType" "userType" DEFAULT 'member',
	"createdAt" timestamp DEFAULT now(),
	"updatedAt" timestamp DEFAULT now()
);
--> statement-breakpoint
ALTER TABLE "orderTable" ADD CONSTRAINT "orderTable_mealId_mealTable_mealId_fk" FOREIGN KEY ("mealId") REFERENCES "public"."mealTable"("mealId") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "orderTable" ADD CONSTRAINT "orderTable_userId_userTable_userId_fk" FOREIGN KEY ("userId") REFERENCES "public"."userTable"("userId") ON DELETE cascade ON UPDATE no action;