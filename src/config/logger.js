import winston from 'winston';
import path from 'path';
import fs from 'fs';
import config from './config.js';

const isProduction = config.server.env === 'production';

// Define a single console transport to be used by all loggers in production
const consoleTransport = new winston.transports.Console({
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({ format: 'HH:mm:ss' }),
        winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
    )
});

// Function to create a logger
const createLogger = (label) => {
    const transports = [consoleTransport];

    // If not in production, add file transports
    if (!isProduction) {
        const logsDir = path.resolve(process.cwd(), 'logs');
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }

        transports.push(new winston.transports.File({
            filename: path.join(logsDir, `${label}.log`),
            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
        }));
    }

    return winston.createLogger({
        level: config.logging.level,
        format: winston.format.combine(winston.format.label({ label })),
        transports: transports,
    });
};

// Create the loggers
const mainLogger = createLogger('app');
const auditLogger = createLogger('audit');
const securityLogger = createLogger('security');
const performanceLogger = createLogger('performance');

// --- Helper Functions ---

export const logAuth = (event, userId, details = {}) => securityLogger.info('Authentication Event', { event, userId, ...details });
export const logAuthorization = (event, userId, resource, action, allowed, details = {}) => securityLogger.info('Authorization Event', { event, userId, resource, action, allowed, ...details });
export const logAudit = (action, userId, resourceType, resourceId, changes = {}, metadata = {}) => auditLogger.info('User Action', { action, userId, resourceType, resourceId, changes, metadata });
export const logPerformance = (endpoint, method, responseTime, statusCode, userId = null) => performanceLogger.info('API Performance', { endpoint, method, responseTime, statusCode, userId });
export const logDatabase = (operation, table, duration, recordsAffected, error = null) => {
    const logData = { operation, table, duration, recordsAffected };
    if (error) mainLogger.error('Database Operation Failed', { ...logData, error: error.message });
    else mainLogger.debug('Database Operation', logData);
};
export const logFileOperation = (operation, filename, userId, size = null, error = null) => {
    const logData = { operation, filename, userId, size };
    if (error) mainLogger.error('File Operation Failed', { ...logData, error: error.message });
    else mainLogger.info('File Operation', logData);
};
export const logSystem = (event, details = {}) => mainLogger.info('System Event', { event, ...details });
export const logSecurityIncident = (incident, severity, userId = null, details = {}) => {
    securityLogger.error('Security Incident', { incident, severity, userId, ...details });
    mainLogger.error('SECURITY INCIDENT', { incident, severity, userId, ...details });
};
export const logError = (error, context = {}) => mainLogger.error('Application Error', { message: error.message, stack: error.stack, ...context });
export const logRequest = (req, res, responseTime) => {
    const logData = { method: req.method, url: req.originalUrl, statusCode: res.statusCode, responseTime, userAgent: req.get('User-Agent'), ip: req.ip, userId: req.user?.id || null };
    if (res.statusCode >= 500) mainLogger.error('HTTP Request Error', logData);
    else if (res.statusCode >= 400) mainLogger.warn('HTTP Request Warning', logData);
    else mainLogger.info('HTTP Request', logData);
};
export const logHealthCheck = (component, status, responseTime, details = {}) => mainLogger.info('Health Check', { component, status, responseTime, ...details });

export const closeLoggers = () => new Promise(resolve => {
    // In production, transports are shared, so we only need to end one.
    if (isProduction) {
        mainLogger.on('finish', resolve);
        mainLogger.end();
    } else {
        // In dev, end all loggers
        let count = 4;
        const onFinish = () => { if (--count === 0) resolve(); };
        mainLogger.on('finish', onFinish).end();
        auditLogger.on('finish', onFinish).end();
        securityLogger.on('finish', onFinish).end();
        performanceLogger.on('finish', onFinish).end();
    }
});

export {
    mainLogger as default,
    auditLogger,
    securityLogger,
    performanceLogger
};