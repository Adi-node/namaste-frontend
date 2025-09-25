import express from 'express';
import adminController from '../controllers/adminController.js';
import { authenticateToken } from '../middleware/auth.js';
import { requireAdmin } from '../middleware/rbac.js';
import { adminRateLimit } from '../middleware/security.js';
import { auditLogger } from '../middleware/audit.js';

const router = express.Router();

// Apply authentication and admin role requirement to all admin routes
router.use(authenticateToken);
router.use(requireAdmin);
router.use(adminRateLimit);

// User Management Routes
router.get('/users', 
    auditLogger('LIST_USERS', 'user'),
    adminController.getUsers
);

router.get('/users/:userId', 
    auditLogger('VIEW_USER', 'user'),
    adminController.getUserById
);

router.put('/users/:userId/role', 
    auditLogger('UPDATE_USER_ROLE', 'user'),
    adminController.updateUserRole
);

router.put('/users/:userId/status', 
    auditLogger('UPDATE_USER_STATUS', 'user'),
    adminController.updateUserStatus
);

router.delete('/users/:userId', 
    auditLogger('DELETE_USER', 'user'),
    adminController.deleteUser
);

// Audit Log Routes
router.get('/audit', 
    auditLogger('VIEW_AUDIT_LOGS', 'audit'),
    adminController.getAuditLogs
);

router.get('/audit/stats', 
    auditLogger('VIEW_AUDIT_STATS', 'audit'),
    adminController.getAuditStats
);

export default router;