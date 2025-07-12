import { Request, Response } from "express";
import { createMealServices, deleteMealServices, getMealByIdServices, getMealsServices, updateMealServices } from "./meal.service";

//Business logic for cities-related operations

export const getMeals = async (req: Request, res: Response) => {
    try {
        const allMeals = await getMealsServices();
        if (allMeals == null || allMeals.length == 0) {
            res.status(404).json({ message: "No meals found" });
        } else {
            res.status(200).json(allMeals);
        }
    } catch (error: any) {
        res.status(500).json({ message: error.message || "Failed to fetch meals" });
    }
}

export const getMealById = async (req: Request, res: Response) => {
    const mealId = parseInt(req.params.id);
    if (isNaN(mealId)) {
        res.status(400).json({ message: "Invalid meal ID" });
        return; // Prevent further execution
    }
    try {
        const meal = await getMealByIdServices(mealId);
        if (meal == null) {
            res.status(404).json({ message: "meal not found" });
        } else {
            res.status(200).json(meal);
        }
    } catch (error: any) {
        res.status(500).json({ message: error.message || "Failed to fetch meal" });
    }
}

export const createMeal = async (req: Request, res: Response) => {
    const { mealName, mealPrice,mealUrl, mealDescription,mealBadge } = req.body;
    if (!mealName || !mealPrice || !mealUrl || !mealDescription || !mealBadge) {
        res.status(400).json({ error: "All fields are required" });
        return; // Prevent further execution
    }
    try {
        const newMeal = await createMealServices({mealName, mealPrice,mealUrl, mealDescription,mealBadge });
        if (newMeal == null) {
            res.status(500).json({ message: "Failed to create meal" });
        } else {
            res.status(201).json({ message: newMeal });
        }
    } catch (error: any) {
        res.status(500).json({ error: error.message || "Failed to create meal" });
    }
}

export const updateMeal = async (req: Request, res: Response) => {
    const mealId = parseInt(req.params.id);
    if (isNaN(mealId)) {
        res.status(400).json({ error: "Invalid city ID" });
        return; // Prevent further execution
    }
    const { mealName, mealPrice,mealUrl, mealDescription,mealBadge } = req.body;
    if (!mealName || !mealPrice || !mealUrl || !mealDescription || !mealBadge) {
        res.status(400).json({ error: "All fields are required" });
        return; // Prevent further execution
    }
    try {
        const updatedMeal = await updateMealServices(mealId, { mealName, mealPrice });
        if (updatedMeal == null) {
            res.status(404).json({ message: "Meal not found or failed to update" });
        } else {
            res.status(200).json({ message: updatedMeal });
        }
    } catch (error: any) {
        res.status(500).json({ message: error.message || "Failed to update Meal" });
    }
}


export const deleteMeal = async (req: Request, res: Response) => {
    const mealId = parseInt(req.params.id);
    if (isNaN(mealId)) {
        res.status(400).json({ error: "Invalid Meal ID" });
        return; // Prevent further execution
    }
    const existingMeal = await getMealByIdServices(mealId)
    if (!existingMeal) {
        res.status(200).json({ message: "Meal is not found" });
        return;
    }

    try {
        const deleteMeal = await deleteMealServices(mealId);
        if (deleteMeal) {
            res.status(200).json(deleteMeal);
        } else {
            res.status(404).json({ message: "Meal not found" });
        }
    } catch (error: any) {
        res.status(500).json({ message: error.message || "Failed to delete meal" });
    }
}