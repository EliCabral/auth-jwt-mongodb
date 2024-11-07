import express from 'express';
import authRoutes from './auth';
import userRoutes from './user';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
// import { initDatabase } from './database';

dotenv.config();

const app = express();
app.use(express.json());

// Conectando ao MongoDB
mongoose.connect(process.env.MONGO_URI as string).then(() => {
        console.log('Conectado ao MongoDB');
    }).catch((error) => {
        console.error('Erro ao conectar ao MongoDB:', error);
    });
// Rotas
app.use('/auth', authRoutes);
app.use('/user', userRoutes);

// Iniciar o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on <http://localhost>:${PORT}`);
});