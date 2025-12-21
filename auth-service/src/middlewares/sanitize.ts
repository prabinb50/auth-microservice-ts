import { Request, Response, NextFunction } from 'express';

const sanitizeString = (str: string): string => {
    if (typeof str !== 'string') return str;
    return str
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<[^>]+>/g, '')
        .replace(/\0/g, '')
        .replace(/[\x00-\x1F\x7F]/g, '')
        .trim();
};

// recursively sanitize object
const sanitizeObject = (obj: any): any => {
    if (obj === null || obj === undefined) {
        return obj;
    }
    
    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeObject(item));
    }
    
    if (typeof obj === 'object' && obj.constructor === Object) {
        const sanitized: any = {};
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                // sanitize key as well
                const sanitizedKey = sanitizeString(key);
                sanitized[sanitizedKey] = sanitizeObject(obj[key]);
            }
        }
        return sanitized;
    }
    
    if (typeof obj === 'string') {
        return sanitizeString(obj);
    }
    
    return obj;
};

// middleware to sanitize all inputs
export const sanitizeInput = (req: Request, res: Response, next: NextFunction) => {
    try {
        // sanitize body
        if (req.body && Object.keys(req.body).length > 0) {
            req.body = sanitizeObject(req.body);
        }
        
        // sanitize query parameters
        if (req.query && Object.keys(req.query).length > 0) {
            req.query = sanitizeObject(req.query);
        }
        
        // sanitize params
        if (req.params && Object.keys(req.params).length > 0) {
            req.params = sanitizeObject(req.params);
        }
        
        next();
    } catch (error) {
        console.error('sanitization error:', error);
        return res.status(400).json({
            message: 'invalid input data',
            error: 'input contains dangerous characters',
        });
    }
};