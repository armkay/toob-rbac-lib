export class UnauthorizedError extends Error {
    statusCode = 401;
    constructor(msg: string) { super(msg); }
}

export class ForbiddenError extends Error {
    statusCode = 403;
    constructor(msg: string) { super(msg); }
}
