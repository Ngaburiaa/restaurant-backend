import { desc, eq } from "drizzle-orm";
import db from "../drizzle/db";
import { orderTable, TOrderInsert, TOrderSelect } from "../drizzle/schema";


//CRUD Operations for Order entity

//Get all order
export const getAllOrdersServices = async (): Promise<TOrderSelect[] | null> => {
    return await db.query.orderTable.findMany({
        with:{
            meal:{
                columns:{
                    mealName:true,
                    mealBadge:true,
                    mealPrice:true,
                    mealUrl:true
                },
            },
            user:{
                columns:{
                    firstName:true,
                    email:true
                }
            }
        },
        orderBy:[desc(orderTable.orderId)]
    });
}

//Get all order for one user by userId
export const getAllOrdersForOneUserServices = async (userId:number): Promise<TOrderSelect[] | null> => {
    return await db.query.orderTable.findMany({
        where:eq(orderTable.userId,userId),
        with:{
            meal:{
                columns:{
                    mealName:true,
                    mealBadge:true,
                    mealPrice:true,
                    mealUrl:true
                }
            }
        },
        orderBy:[desc(orderTable.orderId)]
    });
}


//Get order by ID
export const getOrderByIdServices = async (orderId: number): Promise<TOrderSelect | undefined> => {
    return await db.query.orderTable.findFirst({
        where: eq(orderTable.orderId, orderId),
        with:{
            meal:{
                columns:{
                    mealPrice:true,
                    mealName:true,
                    mealUrl:true
                }
            },
            user:{
                columns:{
                    firstName:true,
                    lastName:true,
                    email:true
                }
            }
        }
    })
}

// Create a new order
export const createOrderServices = async (order: TOrderInsert): Promise<string> => {
    await db.insert(orderTable).values(order).returning();
    return "order created successfully 🎉";
}

// Update an existing order
export const updateOrderServices = async (orderId: number, order: Partial<TOrderInsert>): Promise<string> => {
    await db.update(orderTable).set(order).where(eq(orderTable.orderId, orderId));
    return "order updated successfully 😎";
}


// Delete a order

export const deleteOrderServices = async (orderId: number): Promise<string> => {
    await db.delete(orderTable).where(eq(orderTable.orderId, orderId));
    return "Order deleted successfully 🎉"
}