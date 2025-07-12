import { Request, Response } from "express";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import { createUserServices, getUserByEmailService } from "./auth.service";
import { sendNotificationEmail } from "../middleware/googleMailer";



//Register Login
export const createUser = async (req: Request, res: Response) => {
    const user = req.body;
    try {

        if (!user.firstName || !user.lastName || !user.email || !user.password) {
            res.status(400).json({ error: "All fields are required" });
            return; // Prevent further execution
        }

        
            const existingUser = await getUserByEmailService(user.email);
            if (existingUser) {
                res.status(404).json({ message: "Email already taken😒" });
                return;
            }

            //generate hashed password
            const salt = bcrypt.genSaltSync(10);
            const hashedPassword = bcrypt.hashSync(user.password, salt)
            user.password = hashedPassword

            const newUser = await createUserServices(user)
            // const result = await sendNotificationEmail(user.email, user.fullName,"Acount created Successfully","Welcome to our Food Service")
            res.status(201).json({ message: newUser })
        } catch (error: any) {
            res.status(500).json({ error: error.message || "Failed to create user" });
        }
    }

//Login

export const loginUser = async (req: Request, res: Response) => {
        const user = req.body;

        try {
            const existingUser = await getUserByEmailService(user.email);
            if (!existingUser) {
                res.status(404).json({ message: "User not found" });
                return;
            }else{

            //Compare password
            const isMatch = bcrypt.compareSync(user.password, existingUser.password)
            if (!isMatch) {
                res.status(401).json({ message: "Invalid Credentials" });
                return;
            }

            //Generate Token

            let payload = {
                userId: existingUser.userId,
                email: existingUser.email,
                firstName: existingUser.firstName,
                lastName: existingUser.lastName,
                userType: existingUser.userType,
                exp: Math.floor(Date.now() / 1000) + (60 * 60) /// token expire 1hr
            }

            let secret = process.env.JWT_SECRET as string;

            const token = jwt.sign(payload, secret)

            res.status(200).json({ token, userId: existingUser.userId, email: existingUser.email, firstName: existingUser.firstName,lastName: existingUser.lastName, userType: existingUser.userType })
        }} catch (error: any) {
            res.status(500).json({ message: error.message || "Failed to login" })
        }


    }