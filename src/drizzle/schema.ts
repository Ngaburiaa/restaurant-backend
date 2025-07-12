import { relations } from "drizzle-orm";
import { pgTable, serial, decimal, timestamp, integer, varchar, pgEnum } from "drizzle-orm/pg-core";

export const roleEnum = pgEnum("userType", ['member', 'admin', 'disabled']);
export const statusEnum = pgEnum("statusType", ['pending', 'canceled', 'completed'])



// User table 1
export const userTable = pgTable("userTable", {
    userId: serial("userId").primaryKey(),
    firstName: varchar("firstName"),
    lastName: varchar("lastName"),
    profileUrl: varchar("profileUrl").default("null"),
    email: varchar("email").notNull(),
    password: varchar("password").notNull(),
    userType: roleEnum("userType").default('member'),
    createdAt: timestamp('createdAt').defaultNow(),
    updatedAt: timestamp('updatedAt').defaultNow(),
});

// Meal table 2
export const mealTable = pgTable("mealTable", {
    mealId: serial("mealId").primaryKey(),
    mealName: varchar("mealName"),
    mealUrl: varchar("mealUrl"),
    mealDescription: varchar("mealDescription").notNull(),
    mealPrice: decimal("mealPrice").notNull(),
    mealBadge: varchar("mealBadge"),
    rating: integer("rating").default(0),
    createdAt: timestamp('createdAt').defaultNow(),
    updatedAt: timestamp('updatedAt').defaultNow(),
});

//Order table 3
export const orderTable = pgTable("orderTable", {
    orderId: serial("orderId").primaryKey(),
    mealId: integer("mealId").notNull().references(() => mealTable.mealId, { onDelete: 'cascade' }),
    userId: integer("userId").notNull().references(() => userTable.userId, { onDelete: 'cascade' }),
    status: statusEnum("statusType").default('pending'),
    createdAt: timestamp('createdAt').defaultNow(),
    updatedAt: timestamp('updatedAt').defaultNow(),
})



//Infer Types
export type TUserInsert = typeof userTable.$inferInsert;
export type TUserSelect = typeof userTable.$inferSelect;

export type TMealInsert = typeof mealTable.$inferInsert;
export type TMealSelect = typeof mealTable.$inferSelect;

export type TOrderInsert = typeof orderTable.$inferInsert;
export type TOrderSelect = typeof orderTable.$inferSelect;


// one to one rln
//relation btn order(1) --> (1)user & (1)meal
export const orderUserMealRelation = relations(orderTable, ({ one }) => ({
    user: one(userTable, {
        fields: [orderTable.userId],
        references: [userTable.userId]
    }),
    meal: one(mealTable, {
        fields: [orderTable.mealId],
        references: [mealTable.mealId]
    })
}));

// many to one rln
//relation btn user(1) --> (m)order
export const userOrderRelation = relations(userTable, ({ many }) => ({
    orders: many(orderTable)
}))

// many to one rln
//relation btn meal(1) --> (m)order
export const mealOrderRelation = relations(mealTable, ({ many }) => ({
    meals: many(orderTable)
}))





