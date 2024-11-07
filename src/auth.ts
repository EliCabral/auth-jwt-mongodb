import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { initDatabase } from './database';
import dotenv from 'dotenv';
import User from './domains/users/models/User';

dotenv.config();

const authRouters = express.Router();
const SECRET_KEY = process.env.SECRET_KEY as string;

authRouters.post('/registrar', async (req: Request, res: Response) => {
    const { name, cpf, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    // const db = await initDatabase();

    try {
        const newUser = new User({ name, cpf, email, password:hashedPassword });
        await newUser.save();
        res.status(201).json({
            message: 'Usuário registrado comsucesso'
        });
    } catch (error) {
        res.status(400).json({ error: 'Usuário já existe' });
    }
});

authRouters.post('/login', async (req: Request, res: Response) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
        const token = jwt.sign({ id: user._id, email: user.email }, 
            SECRET_KEY, {
                expiresIn: '1h',
        });
        res.json({ token });
    } else {
        res.status(401).json({
            error: 'Credenciais inválidas'
        });
    }
});

export default authRouters;