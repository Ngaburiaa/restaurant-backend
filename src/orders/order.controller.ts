import { Request, Response } from "express";
import { createOrderServices, deleteOrderServices, getAllOrdersForOneUserServices, getAllOrdersServices, getOrderByIdServices, updateOrderServices } from "./order.service";

//Business logic for order-related operations

export const getOrders = async (req: Request, res: Response) => {
    try {
        const allOrders = await getAllOrdersServices();
        if (allOrders == null ) {
            res.status(404).json({ message: "No orders found" });
        } else {
            res.status(200).json(allOrders);
        }
    } catch (error: any) {
        res.status(500).json({ message: error.message || "Failed to fetch order" });
    }
}

export const getAlllOrderForOneUserById = async (req: Request, res: Response) => {
    const userIdParam = req.query.userId;
    const userId = typeof userIdParam === "string" ? parseInt(userIdParam, 10) : NaN;
    console.log("🚀 ~ getAlllOrderForOneUserById ~ userId:", userId)
    if (isNaN(userId)) {
        res.status(400).json({ message: "Invalid User ID 😟" });
        return; // Prevent further execution
    }
    try {
        const order = await getAllOrdersForOneUserServices(userId);
        if (order == null) {
            res.status(404).json({ message: "orders not found" });
        } else {
            res.status(200).json(order);
        }
    } catch (error: any) {
        res.status(500).json({ message: error.message || "Failed to fetch orders" });
    }
}

export const getOrderById = async (req: Request, res: Response) => {
    const orderId = parseInt(req.params.id);
    if (isNaN(orderId)) {
        res.status(400).json({ message: "Invalid order ID" });
        return; // Prevent further execution
    }
    try {
        const order = await getOrderByIdServices(orderId);
        if (order == null) {
            res.status(404).json({ message: "order not found" });
        } else {
            res.status(200).json(order);
        }
    } catch (error: any) {
        res.status(500).json({ message: error.message || "Failed to fetch order" });
    }
}

export const createOrder = async (req: Request, res: Response) => {
    const { mealId, userId } = req.body;
    if (!mealId || !userId) {
        res.status(400).json({ error: "All fields are required" });
        return; // Prevent further execution
    }
    try {
        const newOrder = await createOrderServices({ mealId, userId });
        if (newOrder == null) {
            res.status(500).json({ message: "Failed to create order" });
        } else {
            res.status(201).json({ message: newOrder });
        }
    } catch (error: any) {
        res.status(500).json({ error: error.message || "Failed to create order" });
    }
}

export const updateOrder = async (req: Request, res: Response) => {
    const orderId = parseInt(req.params.id);
    if (isNaN(orderId)) {
        res.status(400).json({ error: "Invalid Order ID" });
        return; // Prevent further execution
    }
    const { status } = req.body;
    if (!status) {
        res.status(400).json({ error: "All fields are required" });
        return; // Prevent further execution
    }
    try {
        const existingOrder = await getOrderByIdServices(orderId)
        if (!existingOrder) {
            res.status(200).json({ message: "Order is not found" });
            return;
        }

        const updatedMeal = await updateOrderServices(orderId, { status });
        if (updatedMeal == null) {
            res.status(404).json({ message: "Order not found or failed to update" });
        } else {
            res.status(200).json({ message: updatedMeal });
        }
    } catch (error: any) {
        res.status(500).json({ message: error.message || "Failed to update Order" });
    }
}


export const deleteOrder = async (req: Request, res: Response) => {
    const orderId = parseInt(req.params.id);
    if (isNaN(orderId)) {
        res.status(400).json({ error: "Invalid Order ID" });
        return; // Prevent further execution
    }
    const existingOrder = await getOrderByIdServices(orderId)
    if (!existingOrder) {
        res.status(200).json({ message: "Order is not found" });
        return;
    }

    try {
        const deleteOrder = await deleteOrderServices(orderId);
        if (deleteOrder) {
            res.status(200).json(deleteOrder);
        } else {
            res.status(404).json({ message: "Order not found" });
        }
    } catch (error: any) {
        res.status(500).json({ message: error.message || "Failed to delete order" });
    }
}