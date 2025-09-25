
import express from 'express';
import patientController from '../controllers/patientController.js';
import { authenticateToken } from '../middleware/auth.js';
import { auditLogger } from '../middleware/audit.js';

const router = express.Router();

// Apply authentication to all patient routes
router.use(authenticateToken);

// Patient Records
router.post('/', 
    auditLogger('CREATE_PATIENT_RECORD', 'patient_record'),
    patientController.createPatientRecord
);
router.get('/', 
    auditLogger('LIST_PATIENT_RECORDS', 'patient_record'),
    patientController.getPatientRecords
);
router.get('/:patientId', 
    auditLogger('GET_PATIENT_RECORD', 'patient_record'),
    patientController.getPatientRecordById
);
router.put('/:patientId', 
    auditLogger('UPDATE_PATIENT_RECORD', 'patient_record'),
    patientController.updatePatientRecord
);
router.delete('/:patientId', 
    auditLogger('DELETE_PATIENT_RECORD', 'patient_record'),
    patientController.deletePatientRecord
);

// Patient Visits (nested under patient records)
router.post('/:patientId/visits', 
    auditLogger('CREATE_PATIENT_VISIT', 'patient_visit'),
    patientController.createPatientVisit
);
router.get('/:patientId/visits', 
    auditLogger('LIST_PATIENT_VISITS', 'patient_visit'),
    patientController.getPatientVisits
);
router.get('/:patientId/visits/:visitId', 
    auditLogger('GET_PATIENT_VISIT', 'patient_visit'),
    patientController.getPatientVisitById
);
router.put('/:patientId/visits/:visitId', 
    auditLogger('UPDATE_PATIENT_VISIT', 'patient_visit'),
    patientController.updatePatientVisit
);
router.delete('/:patientId/visits/:visitId', 
    auditLogger('DELETE_PATIENT_VISIT', 'patient_visit'),
    patientController.deletePatientVisit
);

export default router;
