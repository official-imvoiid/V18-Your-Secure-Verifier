import type { NextFunction, Request, RequestHandler, Response } from 'express';

/**
 * An error that is safe to send to the client as
 * `{"error": "<text>", "code": "<CODE>"}` (protocol section 3).
 * `extra` adds a few more safe fields, for example `reason`.
 */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly extra: Record<string, unknown> = {},
    public readonly headers: Record<string, string> = {}
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export function sendError(res: Response, err: ApiError): void {
  for (const [k, v] of Object.entries(err.headers)) res.setHeader(k, v);
  res.status(err.status).json({ error: err.message, code: err.code, ...err.extra });
}

/** Wraps an async route so thrown errors reach the error handler (Express 4). */
export function route(
  fn: (req: Request, res: Response) => Promise<void> | void
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve()
      .then(() => fn(req, res))
      .catch(next);
  };
}

export const badRequest = (message: string, extra?: Record<string, unknown>) =>
  new ApiError(400, 'BAD_REQUEST', message, extra);
