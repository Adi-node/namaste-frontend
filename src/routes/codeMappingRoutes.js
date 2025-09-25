
import express from 'express';
import codeMappingController from '../controllers/codeMappingController.js';
import { authenticateToken } from '../middleware/auth.js';
import { auditLogger } from '../middleware/audit.js';

const router = express.Router();

// Apply authentication to all code mapping routes
router.use(authenticateToken);

// NAMASTE Codes
router.get('/namaste', 
    auditLogger('LIST_NAMASTE_CODES', 'code_mapping'),
    codeMappingController.getNamasteCodes
);
router.get('/namaste/:code', 
    auditLogger('GET_NAMASTE_CODE', 'code_mapping'),
    codeMappingController.getNamasteCodeByCode
);

// ICD-11 Codes
router.get('/icd11', 
    auditLogger('LIST_ICD11_CODES', 'code_mapping'),
    codeMappingController.getIcd11Codes
);
router.get('/icd11/:code', 
    auditLogger('GET_ICD11_CODE', 'code_mapping'),
    codeMappingController.getIcd11CodeByCode
);

// Code Mappings
router.get('/map', 
    auditLogger('SEARCH_CODE_MAPPINGS', 'code_mapping'),
    codeMappingController.searchCodeMappings
);
router.post('/map', 
    auditLogger('CREATE_CODE_MAPPING', 'code_mapping'),
    codeMappingController.createCodeMapping
);

// Autocomplete
router.get('/autocomplete', 
    auditLogger('AUTOCOMPLETE_CODES', 'code_mapping'),
    codeMappingController.autocompleteCodes
);

export default router;
