
import { desc, eq } from "drizzle-orm";
import db from "../drizzle/db";
import { mealTable, TMealInsert, TMealSelect } from "../drizzle/schema";


//CRUD Operations for City entity

//Get all Meal
export const getMealsServices = async (): Promise<TMealSelect[] | null> => {
    return await db.query.mealTable.findMany({
        orderBy:[desc(mealTable.mealId)]
    });
}

//Get meal by ID
export const getMealByIdServices = async (mealId: number): Promise<TMealSelect | undefined> => {
    return await db.query.mealTable.findFirst({
        where: eq(mealTable.mealId, mealId)
    })
}

// Create a new meal
export const createMealServices = async (meal: TMealInsert): Promise<string> => {
    await db.insert(mealTable).values(meal).returning();
    return "meal created successfully 🎉";
}

// Update an existing meal
export const updateMealServices = async (mealId: number, meal: Partial<TMealInsert>): Promise<string> => {
    await db.update(mealTable).set(meal).where(eq(mealTable.mealId, mealId));
    return "meal updated successfully 😎";
}


// Delete a meal

export const deleteMealServices = async (mealId: number): Promise<string> => {
    await db.delete(mealTable).where(eq(mealTable.mealId, mealId));
    return "Meal deleted successfully 🎉"
}