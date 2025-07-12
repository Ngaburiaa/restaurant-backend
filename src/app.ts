import express, { Application, Response } from "express";

import { logger } from "./middleware/logger";
import { userRouter } from "./users/user.route";
import { mealRouter } from "./meals/meal.route";
import { authRouter } from "./auth/auth.route";
import { rateLimiterMiddleware } from "./middleware/rateLimiter";
import cors from "cors"
import { orderRouter } from "./orders/order.route";

const app:Application = express()




//Basic MIddleware
app.use(cors())
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(logger);
app.use(rateLimiterMiddleware)

//default route
app.get('/',(req,res:Response)=>{
    res.send("Welcome to Express API Backend WIth Drizzle ORM and PostgreSQL")
})


//import routes
app.use('/api',userRouter)
app.use('/api',mealRouter)
app.use('/api',authRouter)
app.use('/api',orderRouter)

export default app;