import { Request, Response } from "express";
import { createUserServices, deleteUserServices, getUserByIdServices, getUsersServices, updateUserServices } from "./user.service";

//Business logic for user-related operations


export const getUsers = async (req: Request, res: Response) => {
    try {
        const allUsers = await getUsersServices();
        if (allUsers == null || allUsers.length == 0) {
          res.status(404).json({ message: "No users found" });
        }else{
            res.status(200).json(allUsers);             
        }            
    } catch (error:any) {
        res.status(500).json({ error:error.message || "Failed to fetch users" });
    }
}

export const getUserById = async (req: Request, res: Response) => {
    const userId = parseInt(req.params.id);
    if (isNaN(userId)) {
        res.status(400).json({ error: "Invalid user ID" });
         return; // Prevent further execution
    }
    try {
        const user = await getUserByIdServices(userId);
        if (user == undefined) {
            res.status(404).json({ message: "User not found" });
        } else {
            res.status(200).json(user);
        }
    } catch (error:any) {
        res.status(500).json({ error:error.message || "Failed to fetch user" });
    }
}

export const createUser = async (req: Request, res: Response) => {
    const { firstName,lastName,email, password } = req.body;
    if (!firstName || !lastName || !email || !password) {
        res.status(400).json({ error: "All fields are required" });
        return; // Prevent further execution
    }
    try {

        
        const newUser = await createUserServices({ firstName,lastName, email, password });
        if (newUser == null) {
            res.status(500).json({ message: "Failed to create user" });
        } else {
            res.status(201).json({message:newUser});
        }
    } catch (error:any) {
        res.status(500).json({ error:error.message || "Failed to create user" });
    }
}
export const updateUser = async (req: Request, res: Response) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) {
     res.status(400).json({ error: "Invalid user ID" });
     return
  }

  const { firstName, lastName, email, password, userType, status } = req.body;

  // Check if at least one field is provided
  if (!firstName && !lastName && !email && !password && !userType && !status) {
    res.status(400).json({ error: "At least one field must be provided to update" });
    return 
  }

  try {
    const updatedUser = await updateUserServices(userId, {
      ...(firstName && { firstName }),
      ...(lastName && { lastName }),
      ...(email && { email }),
      ...(password && { password }),
      ...(userType && { userType }),
      ...(status && { status }),
    });

    res.status(200).json({ message: updatedUser });
  } catch (error: any) {
    res.status(500).json({ error: error.message || "Failed to update user" });
  }
};



export const deleteUser = async (req: Request, res: Response) => {
    const userId = parseInt(req.params.id);  
    if (isNaN(userId)) {
        res.status(400).json({ error: "Invalid user ID" });
        return; // Prevent further execution
    }
    try {
        const deletedUser = await deleteUserServices(userId);
        if (deletedUser) {
            res.status(200).json({ message: "User deleted successfully" });
        } else {
            res.status(404).json({ message: "User not found" });
        }
    } catch (error:any) {    
        res.status(500).json({ error:error.message || "Failed to delete user" });
    }    
}