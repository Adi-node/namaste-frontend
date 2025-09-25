import express from 'express';
import authController from '../controllers/authController.js';
import { authenticateToken, authenticateRefreshToken } from '../middleware/auth.js';
import { authRateLimit } from '../middleware/security.js';
import { auditLogger } from '../middleware/audit.js';

const router = express.Router();

// Public authentication routes with rate limiting
router.post('/register', 
    authRateLimit, 
    auditLogger('REGISTER', 'user'),
    authController.register
);

router.post('/login', 
    authRateLimit, 
    auditLogger('LOGIN', 'authentication'),
    authController.login
);

router.post('/refresh', 
    authRateLimit,
    authenticateRefreshToken,
    auditLogger('REFRESH_TOKEN', 'authentication'),
    authController.refreshToken
);

// Protected authentication routes (require authentication)
router.post('/logout', 
    authenticateToken,
    auditLogger('LOGOUT', 'authentication'),
    authController.logout
);

router.get('/profile', 
    authenticateToken,
    auditLogger('GET_PROFILE', 'user'),
    authController.getProfile
);

router.put('/profile', 
    authenticateToken,
    auditLogger('UPDATE_PROFILE', 'user'),
    authController.updateProfile
);

router.post('/change-password', 
    authenticateToken,
    auditLogger('CHANGE_PASSWORD', 'authentication'),
    authController.changePassword
);

export default router;