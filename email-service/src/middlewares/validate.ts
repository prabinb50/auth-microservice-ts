import { Request, Response, NextFunction } from 'express';
import { ZodSchema } from 'zod';

// validation middleware
export const validate = (schema: ZodSchema) => (req: Request, res: Response, next: NextFunction) => {
    try {
        // parse and sanitize body
        req.body = schema.parse(req.body);
        next();
    } catch (error: any) {
        return res.status(400).json({
            message: 'invalid input data',
            errors: error.errors || [],
        });
    }
};