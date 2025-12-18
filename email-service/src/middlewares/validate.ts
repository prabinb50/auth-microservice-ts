// import { Request, Response, NextFunction } from 'express';
// import { ZodSchema } from 'zod';

// // validation middleware
// export const validate = (schema: ZodSchema) => (req: Request, res: Response, next: NextFunction) => {
//     try {
//         // parse and sanitize body
//         req.body = schema.parse(req.body);
//         next();
//     } catch (error: any) {
//         return res.status(400).json({
//             message: 'invalid input data',
//             errors: error.errors || [],
//         });
//     }
// };

import { Request, Response, NextFunction } from 'express';
import { AnyZodObject, ZodError } from 'zod';

export const validate = (schema: AnyZodObject) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // validate req.body directly
      await schema.parseAsync(req.body);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json({
          message: 'invalid input data',
          errors: error.errors,
        });
      }
      return res.status(500).json({
        message: 'validation error',
        error: error instanceof Error ? error.message : 'unknown error',
      });
    }
  };
};