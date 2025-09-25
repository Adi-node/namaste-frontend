import express from 'express';
import { initializeSupabase, checkDatabaseHealth } from './config/database.js';
import { validateConfig } from './config/config.js';
import logger, { logSystem, logError } from './config/logger.js';
import { 
    corsMiddleware, 
    securityHeaders, 
    generalRateLimit,
    trustProxySetup,
    securityLogger,
    suspiciousActivityDetector,
    requestSizeLimit
} from './middleware/security.js';
import { optionalAuth } from './middleware/auth.js';

// Import routes
import authRoutes from './routes/authRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import codeMappingRoutes from './routes/codeMappingRoutes.js';
import patientRoutes from './routes/patientRoutes.js';

// Import configuration
import config from './config/config.js';

// --- Serverless Initialization ---
// Validate configuration and initialize database connection when the function instance starts.
// This will run once on a "cold start" and the connection will be reused for "warm" invocations.
try {
    validateConfig();
    initializeSupabase();
    logSystem('Application initialized for serverless environment.', {
        environment: config.server.env,
        nodeVersion: process.version,
    });
} catch (error) {
    logError(error, { context: 'applicationInitialization' });
    // If initialization fails, the function will be unhealthy.
    // Vercel will likely show a 500 error for any requests.
}
// --- End Serverless Initialization ---

// Create Express app
const app = express();

// Trust proxy setup for production
trustProxySetup(app);

// Global middleware setup
app.use(securityLogger);
app.use(securityHeaders);
app.use(corsMiddleware);
app.use(requestSizeLimit);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security middleware
app.use(suspiciousActivityDetector);
app.use(generalRateLimit);

// Optional authentication for all routes (adds req.user if token is valid)
app.use(optionalAuth);

// Health check endpoint (no auth required)
app.get('/health', async (req, res) => {
    try {
        const dbHealth = await checkDatabaseHealth();
        const serverUptime = process.uptime();
        const memoryUsage = process.memoryUsage();
        
        const healthStatus = {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            server: {
                uptime: `${Math.floor(serverUptime)} seconds (in this execution environment)`,
                memory: {
                    used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)} MB`,
                    total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)} MB`
                },
                environment: config.server.env,
                nodeVersion: process.version
            },
            database: dbHealth
        };

        if (dbHealth.status === 'healthy') {
            res.json(healthStatus);
        } else {
            res.status(503).json({
                ...healthStatus,
                status: 'unhealthy',
                issues: ['Database connection failed']
            });
        }
    } catch (error) {
        logError(error, { context: 'healthCheck' });
        res.status(503).json({
            status: 'unhealthy',
            timestamp: new Date().toISOString(),
            error: 'Health check failed'
        });
    }
});

// API root endpoint
app.get('/api', (req, res) => {
    res.json({
        message: 'NAMASTE FHIR R4 Backend API',
        version: '1.0.0',
        description: 'Secure healthcare terminology microservice with JWT authentication and audit logging',
        endpoints: {
            authentication: '/api/auth',
            admin: '/api/admin (admin only)',
            health: '/health',
            documentation: '/api/docs'
        },
        features: [
            'JWT Authentication',
            'Role-based Access Control',
            'Comprehensive Audit Logging',
            'NAMASTE ↔ ICD-11 Code Mapping',
            'Electronic Health Records',
            'FHIR R4 Compliance'
        ],
        security: {
            rateLimiting: 'Enabled',
            cors: 'Configured',
            helmet: 'Enabled',
            auditLogging: 'Comprehensive'
        }
    });
});

// Mount API routes
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/codes', codeMappingRoutes);
app.use('/api/patients', patientRoutes);

// 404 handler for undefined routes
app.use((req, res, next) => {
    res.status(404).json({
        error: 'Route not found',
        message: `The requested endpoint ${req.originalUrl} does not exist`,
        availableEndpoints: [
            '/api - API information',
            '/health - Health check',
            '/api/auth - Authentication endpoints',
            '/api/admin - Admin endpoints (admin only)'
        ]
    });
});

// Global error handler
app.use((error, req, res, next) => {
    logError(error, {
        context: 'globalErrorHandler',
        url: req.originalUrl,
        method: req.method,
        userId: req.user?.id,
        ip: req.ip
    });

    // CORS error
    if (error.message.includes('CORS policy violation')) {
        return res.status(403).json({
            error: 'CORS violation',
            message: 'Origin not allowed by CORS policy'
        });
    }

    // Validation errors
    if (error.name === 'ValidationError') {
        return res.status(400).json({
            error: 'Validation failed',
            message: error.message
        });
    }

    // JWT errors
    if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: 'Authentication failed',
            message: 'Invalid token'
        });
    }

    // Rate limit errors
    if (error.status === 429) {
        return res.status(429).json({
            error: 'Rate limit exceeded',
            message: 'Too many requests, please try again later'
        });
    }

    // Default error response
    const statusCode = error.statusCode || error.status || 500;
    const message = config.server.env === 'production' 
        ? 'Internal server error'
        : error.message;

    res.status(statusCode).json({
        error: 'Server error',
        message,
        ...(config.server.env !== 'production' && { stack: error.stack })
    });
});

// Export the Express app for Vercel to use
export default app;
