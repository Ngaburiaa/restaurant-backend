import { Router } from "express";
import { createMeal, deleteMeal, getMealById, getMeals, updateMeal } from "./meal.controller";
import { adminRoleAuth } from "../middleware/bearAuth";

export const mealRouter = Router();

// User routes definition


// Get all users
mealRouter.get('/meals', getMeals);

// Get user by ID
mealRouter.get('/meals/:id', getMealById);

// Create a new user
mealRouter.post('/meals', createMeal);

// Update an existing user
mealRouter.put('/meals/:id',adminRoleAuth,updateMeal);


// Delete an existing user
mealRouter.delete('/meals/:id',adminRoleAuth, deleteMeal);