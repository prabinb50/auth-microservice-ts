import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import emailRoutes from './src/routes/emailRoutes';
import { sanitizeInput } from './src/middlewares/sanitize';
import { apiRateLimiter } from './src/middlewares/rateLimiter';

dotenv.config();

const app = express();

// trust proxy
app.set('trust proxy', 1);

// enforce https in production
if (process.env.NODE_ENV === 'production') {
    app.use((req: Request, res: Response, next: NextFunction) => {
        if (req.header('x-forwarded-proto') !== 'https') {
            return res.redirect(301, `https://${req.header('host')}${req.url}`);
        }
        next();
    });
}

// security headers with helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    },
    frameguard: {
        action: 'deny',
    },
    noSniff: true,
    xssFilter: true,
}));

// logging middleware
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
} else {
    app.use(morgan('combined'));
}

// compression middleware
app.use(compression());

// json middleware with size limit
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// input sanitization
app.use(sanitizeInput);

// cors configuration
const allowedOrigins = [
    process.env.CLIENT_URL || 'http://localhost:5173', 
    process.env.AUTH_SERVICE_URL || 'http://localhost:8000'
];

if (process.env.ALLOWED_ORIGINS) {
    allowedOrigins.push(...process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()));
}

app.use(cors({
    origin: (origin, callback) => {
        // allow requests with no origin
        if (!origin) {
            return callback(null, true);
        }
        
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        
        const msg = 'the cors policy for this site does not allow access from the specified origin.';
        return callback(new Error(msg), false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 86400,
    preflightContinue: false,
    optionsSuccessStatus: 204,
}));

// disable x-powered-by header
app.disable('x-powered-by');

// rate limiting middleware
app.use(apiRateLimiter);

// routes
app.use('/email', emailRoutes);

app.get('/', (req: Request, res: Response) => {
    res.status(200).json({
        status: 'ok',
        service: 'email-service',
        timestamp: new Date().toISOString(),
    });
});

// 404 handler
app.use((req: Request, res: Response) => {
    res.status(404).json({
        message: 'endpoint not found',
        path: req.originalUrl,
    });
});

// global error handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error('global error:', err);
    
    // don't leak error details in production
    const errorResponse = {
        message: err.message || 'internal server error',
        ...(process.env.NODE_ENV === 'development' && { 
            stack: err.stack,
            error: err 
        }),
    };
    
    res.status(err.status || 500).json(errorResponse);
});

const PORT = process.env.EMAIL_SERVICE_PORT || 8001;
const HOST = process.env.HOST || 'localhost';

app.listen(PORT, () => {
    console.log(`email service running at http://${HOST}:${PORT}`);
    console.log(`environment: ${process.env.NODE_ENV || 'development'}`);
});