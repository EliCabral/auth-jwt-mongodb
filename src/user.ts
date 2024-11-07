import express, { Request, Response } from 'express';
import { authMiddleware } from './middleware/authMiddleware';
import User from './domains/users/models/User';


const userRoutes = express.Router();

userRoutes.get('/profile', authMiddleware, async (req: Request, res: Response) => {
    try {
        const user = await User.findById((req.user as any).id);
        res.json({ message: 'Welcome to your profile', user });
    } catch (error) {
        res.status(500).json({ error: 'User not found' });
    }
});
export default userRoutes;