import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import emailRoutes from './src/routes/emailRoutes';

dotenv.config();

const app = express();

// middleware
app.use(cors({
  origin: [process.env.CLIENT_URL || 'http://localhost:5173', process.env.AUTH_SERVICE_URL || 'http://localhost:8000'],
  credentials: true,
}));

app.use(express.json());

// routes
app.use('/email', emailRoutes);

app.get('/', (req, res) => {
  res.send('Email Service is running');
});

const PORT = process.env.EMAIL_SERVICE_PORT || 8001;
const HOST = process.env.HOST || 'localhost';

app.listen(PORT, () => {
  console.log(`email service running at http://${HOST}:${PORT}`);
});