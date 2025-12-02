import dotenv from 'dotenv';
dotenv.config();
import express, {Request, Response} from 'express';
import cors from 'cors';
import authRoutes from './src/routes/authRoutes';
import cookieParser from 'cookie-parser';

// configure the server
const app = express();

// middleware for json
app.use(express.json());

// middleware for cookies
app.use(cookieParser());

app.use(
    cors({
        origin: ['http://localhost:5173'],
    })
);

app.use('/auth', authRoutes);

const PORT = process.env.PORT || 8000;
const HOST = process.env.HOST;

app.get('/', (req: Request, res: Response) => {
    res.send('Auth Service is running');
});

app.listen(PORT, () => {
    console.log(`Server is running at http://${HOST}:${PORT}`);
});