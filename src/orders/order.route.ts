import { Router } from "express";
import { createOrder, deleteOrder, getAlllOrderForOneUserById, getOrderById, getOrders, updateOrder } from "./order.controller";
import { bothRoleAuth } from "../middleware/bearAuth";

export const orderRouter = Router();

// Order routes definition


// Get all Orders
orderRouter.get('/orders', getOrders);


// Get All Order for One User by ID
orderRouter.get('/orders/user', getAlllOrderForOneUserById);

// Get Order by ID
orderRouter.get('/orders/:id', getOrderById);

// Create a new Order
orderRouter.post('/orders', createOrder);

// Update an existing Order
orderRouter.put('/orders/:id',updateOrder);


// Delete an existing Order
orderRouter.delete('/orders/:id',bothRoleAuth, deleteOrder);