
import { getSupabaseServiceClient } from '../config/database.js';
import { logError } from '../config/logger.js';
import Joi from 'joi';

// Joi schemas for validation
const patientRecordSchema = Joi.object({
    patientName: Joi.string().min(2).max(200).required(),
    age: Joi.number().integer().min(0).max(150).optional(),
    gender: Joi.string().valid('Male', 'Female', 'Other').optional(),
    contactNumber: Joi.string().max(20).optional().allow(''),
    email: Joi.string().email().max(255).optional().allow(''),
    address: Joi.string().max(500).optional().allow(''),
    diagnosis: Joi.string().max(500).optional().allow(''),
    namasteCode: Joi.string().max(50).optional().allow(''),
    icd11Code: Joi.string().max(50).optional().allow(''),
    treatmentSummary: Joi.string().optional().allow(''),
    prescription: Joi.string().optional().allow(''),
    diagnosticReports: Joi.object().optional(), // Assuming JSONB for file references/metadata
    hospitalName: Joi.string().max(200).optional().allow(''),
    doctorName: Joi.string().max(200).optional().allow(''),
    doctorRegistration: Joi.string().max(100).optional().allow(''),
    reportDate: Joi.date().iso().optional(),
    followUpDate: Joi.date().iso().optional(),
    status: Joi.string().valid('active', 'discharged', 'deceased').default('active'),
    privacyConsent: Joi.boolean().default(false),
    isActive: Joi.boolean().default(true),
});

const patientVisitSchema = Joi.object({
    visitDate: Joi.date().iso().required(),
    reasonForVisit: Joi.string().required(),
    diagnosis: Joi.string().optional().allow(''),
    namasteCode: Joi.string().max(50).optional().allow(''),
    icd11Code: Joi.string().max(50).optional().allow(''),
    treatment: Joi.string().optional().allow(''),
    prescription: Joi.string().optional().allow(''),
    notes: Joi.string().optional().allow(''),
    followUpRequired: Joi.boolean().default(false),
    followUpDate: Joi.date().iso().optional(),
});

// Helper to check if patient record exists and belongs to user (if not admin)
const checkPatientAccess = async (supabase, patientId, userId, userRole) => {
    const { data: patient, error } = await supabase
        .from('patient_records')
        .select('id, created_by')
        .eq('id', patientId)
        .single();

    if (error || !patient) {
        return { error: { status: 404, message: 'Patient record not found' } };
    }

    if (userRole !== 'admin' && patient.created_by !== userId) {
        return { error: { status: 403, message: 'Access denied to patient record' } };
    }
    return { patient };
};

// Patient Records Controllers
export const createPatientRecord = async (req, res) => {
    try {
        const { error, value } = patientRecordSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: 'Validation failed', message: error.details[0].message });
        }

        const supabase = getSupabaseServiceClient();
        const { data, error: createError } = await supabase
            .from('patient_records')
            .insert({
                patient_name: value.patientName,
                age: value.age,
                gender: value.gender,
                contact_number: value.contactNumber,
                email: value.email,
                address: value.address,
                diagnosis: value.diagnosis,
                namaste_code: value.namasteCode,
                icd11_code: value.icd11Code,
                treatment_summary: value.treatmentSummary,
                prescription: value.prescription,
                diagnostic_reports: value.diagnosticReports,
                hospital_name: value.hospitalName,
                doctor_name: value.doctorName,
                doctor_registration: value.doctorRegistration,
                report_date: value.reportDate,
                follow_up_date: value.followUpDate,
                status: value.status,
                privacy_consent: value.privacyConsent,
                is_active: value.isActive,
                created_by: req.user.id,
            })
            .select()
            .single();

        if (createError) {
            logError(createError, { context: 'createPatientRecord', userId: req.user.id });
            return res.status(500).json({ error: 'Failed to create patient record', message: createError.message });
        }

        res.status(201).json({ message: 'Patient record created successfully', data });

    } catch (error) {
        logError(error, { context: 'createPatientRecord', userId: req.user.id });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const getPatientRecords = async (req, res) => {
    try {
        const { page = 1, limit = 20, search = '', status = '' } = req.query;
        const offset = (page - 1) * limit;
        const supabase = getSupabaseServiceClient();

        let query = supabase
            .from('patient_records')
            .select('*', { count: 'exact' });

        // RLS will handle access control based on created_by or admin role
        if (req.user.role !== 'admin') {
            query = query.eq('created_by', req.user.id);
        }

        if (search) {
            query = query.or(`patient_name.ilike.%${search}%,diagnosis.ilike.%${search}%,namaste_code.ilike.%${search}%,icd11_code.ilike.%${search}%`);
        }

        if (status) {
            query = query.eq('status', status);
        }

        const { data, error, count } = await query
            .range(offset, offset + limit - 1)
            .order('created_at', { ascending: false });

        if (error) {
            logError(error, { context: 'getPatientRecords', userId: req.user.id });
            return res.status(500).json({ error: 'Failed to retrieve patient records', message: error.message });
        }

        const totalPages = Math.ceil(count / limit);

        res.json({
            data,
            pagination: {
                currentPage: parseInt(page),
                totalPages,
                totalCount: count,
                limit: parseInt(limit),
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });

    } catch (error) {
        logError(error, { context: 'getPatientRecords', userId: req.user.id });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const getPatientRecordById = async (req, res) => {
    try {
        const { patientId } = req.params;
        const supabase = getSupabaseServiceClient();

        const { patient, error: accessError } = await checkPatientAccess(supabase, patientId, req.user.id, req.user.role);
        if (accessError) {
            return res.status(accessError.status).json({ error: accessError.message });
        }

        const { data, error } = await supabase
            .from('patient_records')
            .select('*')
            .eq('id', patientId)
            .single();

        if (error || !data) {
            return res.status(404).json({ error: 'Patient record not found', message: error.message });
        }

        res.json(data);

    } catch (error) {
        logError(error, { context: 'getPatientRecordById', userId: req.user.id });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const updatePatientRecord = async (req, res) => {
    try {
        const { patientId } = req.params;
        const { error, value } = patientRecordSchema.validate(req.body, { abortEarly: false });
        if (error) {
            return res.status(400).json({ error: 'Validation failed', message: error.details[0].message });
        }

        const supabase = getSupabaseServiceClient();

        const { error: accessError } = await checkPatientAccess(supabase, patientId, req.user.id, req.user.role);
        if (accessError) {
            return res.status(accessError.status).json({ error: accessError.message });
        }

        const { data, error: updateError } = await supabase
            .from('patient_records')
            .update({
                patient_name: value.patientName,
                age: value.age,
                gender: value.gender,
                contact_number: value.contactNumber,
                email: value.email,
                address: value.address,
                diagnosis: value.diagnosis,
                namaste_code: value.namasteCode,
                icd11_code: value.icd11Code,
                treatment_summary: value.treatmentSummary,
                prescription: value.prescription,
                diagnostic_reports: value.diagnosticReports,
                hospital_name: value.hospitalName,
                doctor_name: value.doctorName,
                doctor_registration: value.doctorRegistration,
                report_date: value.reportDate,
                follow_up_date: value.followUpDate,
                status: value.status,
                privacy_consent: value.privacyConsent,
                is_active: value.isActive,
                updated_by: req.user.id,
            })
            .eq('id', patientId)
            .select()
            .single();

        if (updateError) {
            logError(updateError, { context: 'updatePatientRecord', userId: req.user.id, patientId });
            return res.status(500).json({ error: 'Failed to update patient record', message: updateError.message });
        }

        res.json({ message: 'Patient record updated successfully', data });

    } catch (error) {
        logError(error, { context: 'updatePatientRecord', userId: req.user.id, patientId });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const deletePatientRecord = async (req, res) => {
    try {
        const { patientId } = req.params;
        const supabase = getSupabaseServiceClient();

        const { error: accessError } = await checkPatientAccess(supabase, patientId, req.user.id, req.user.role);
        if (accessError) {
            return res.status(accessError.status).json({ error: accessError.message });
        }

        const { error: deleteError } = await supabase
            .from('patient_records')
            .delete()
            .eq('id', patientId);

        if (deleteError) {
            logError(deleteError, { context: 'deletePatientRecord', userId: req.user.id, patientId });
            return res.status(500).json({ error: 'Failed to delete patient record', message: deleteError.message });
        }

        res.json({ message: 'Patient record deleted successfully' });

    } catch (error) {
        logError(error, { context: 'deletePatientRecord', userId: req.user.id, patientId });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

// Patient Visits Controllers
export const createPatientVisit = async (req, res) => {
    try {
        const { patientId } = req.params;
        const { error, value } = patientVisitSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: 'Validation failed', message: error.details[0].message });
        }

        const supabase = getSupabaseServiceClient();

        const { error: accessError } = await checkPatientAccess(supabase, patientId, req.user.id, req.user.role);
        if (accessError) {
            return res.status(accessError.status).json({ error: accessError.message });
        }

        const { data, error: createError } = await supabase
            .from('patient_visits') // Assuming a patient_visits table exists or will be created
            .insert({
                patient_id: patientId,
                visit_date: value.visitDate,
                reason_for_visit: value.reasonForVisit,
                diagnosis: value.diagnosis,
                namaste_code: value.namasteCode,
                icd11_code: value.icd11Code,
                treatment: value.treatment,
                prescription: value.prescription,
                notes: value.notes,
                follow_up_required: value.followUpRequired,
                follow_up_date: value.followUpDate,
                created_by: req.user.id,
            })
            .select()
            .single();

        if (createError) {
            logError(createError, { context: 'createPatientVisit', userId: req.user.id, patientId });
            return res.status(500).json({ error: 'Failed to create patient visit', message: createError.message });
        }

        res.status(201).json({ message: 'Patient visit created successfully', data });

    } catch (error) {
        logError(error, { context: 'createPatientVisit', userId: req.user.id, patientId });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const getPatientVisits = async (req, res) => {
    try {
        const { patientId } = req.params;
        const { page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        const supabase = getSupabaseServiceClient();

        const { error: accessError } = await checkPatientAccess(supabase, patientId, req.user.id, req.user.role);
        if (accessError) {
            return res.status(accessError.status).json({ error: accessError.message });
        }

        let query = supabase
            .from('patient_visits')
            .select('*', { count: 'exact' })
            .eq('patient_id', patientId);

        const { data, error, count } = await query
            .range(offset, offset + limit - 1)
            .order('visit_date', { ascending: false });

        if (error) {
            logError(error, { context: 'getPatientVisits', userId: req.user.id, patientId });
            return res.status(500).json({ error: 'Failed to retrieve patient visits', message: error.message });
        }

        const totalPages = Math.ceil(count / limit);

        res.json({
            data,
            pagination: {
                currentPage: parseInt(page),
                totalPages,
                totalCount: count,
                limit: parseInt(limit),
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });

    } catch (error) {
        logError(error, { context: 'getPatientVisits', userId: req.user.id, patientId });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const getPatientVisitById = async (req, res) => {
    try {
        const { patientId, visitId } = req.params;
        const supabase = getSupabaseServiceClient();

        const { error: accessError } = await checkPatientAccess(supabase, patientId, req.user.id, req.user.role);
        if (accessError) {
            return res.status(accessError.status).json({ error: accessError.message });
        }

        const { data, error } = await supabase
            .from('patient_visits')
            .select('*')
            .eq('id', visitId)
            .eq('patient_id', patientId)
            .single();

        if (error || !data) {
            return res.status(404).json({ error: 'Patient visit not found', message: error.message });
        }

        res.json(data);

    } catch (error) {
        logError(error, { context: 'getPatientVisitById', userId: req.user.id, patientId, visitId });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const updatePatientVisit = async (req, res) => {
    try {
        const { patientId, visitId } = req.params;
        const { error, value } = patientVisitSchema.validate(req.body, { abortEarly: false });
        if (error) {
            return res.status(400).json({ error: 'Validation failed', message: error.details[0].message });
        }

        const supabase = getSupabaseServiceClient();

        const { error: accessError } = await checkPatientAccess(supabase, patientId, req.user.id, req.user.role);
        if (accessError) {
            return res.status(accessError.status).json({ error: accessError.message });
        }

        const { data, error: updateError } = await supabase
            .from('patient_visits')
            .update({
                visit_date: value.visitDate,
                reason_for_visit: value.reasonForVisit,
                diagnosis: value.diagnosis,
                namaste_code: value.namasteCode,
                icd11_code: value.icd11Code,
                treatment: value.treatment,
                prescription: value.prescription,
                notes: value.notes,
                follow_up_required: value.followUpRequired,
                follow_up_date: value.followUpDate,
                updated_by: req.user.id,
            })
            .eq('id', visitId)
            .eq('patient_id', patientId)
            .select()
            .single();

        if (updateError) {
            logError(updateError, { context: 'updatePatientVisit', userId: req.user.id, patientId, visitId });
            return res.status(500).json({ error: 'Failed to update patient visit', message: updateError.message });
        }

        res.json({ message: 'Patient visit updated successfully', data });

    } catch (error) {
        logError(error, { context: 'updatePatientVisit', userId: req.user.id, patientId, visitId });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const deletePatientVisit = async (req, res) => {
    try {
        const { patientId, visitId } = req.params;
        const supabase = getSupabaseServiceClient();

        const { error: accessError } = await checkPatientAccess(supabase, patientId, req.user.id, req.user.role);
        if (accessError) {
            return res.status(accessError.status).json({ error: accessError.message });
        }

        const { error: deleteError } = await supabase
            .from('patient_visits')
            .delete()
            .eq('id', visitId)
            .eq('patient_id', patientId);

        if (deleteError) {
            logError(deleteError, { context: 'deletePatientVisit', userId: req.user.id, patientId, visitId });
            return res.status(500).json({ error: 'Failed to delete patient visit', message: deleteError.message });
        }

        res.json({ message: 'Patient visit deleted successfully' });

    } catch (error) {
        logError(error, { context: 'deletePatientVisit', userId: req.user.id, patientId, visitId });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export default {
    createPatientRecord,
    getPatientRecords,
    getPatientRecordById,
    updatePatientRecord,
    deletePatientRecord,
    createPatientVisit,
    getPatientVisits,
    getPatientVisitById,
    updatePatientVisit,
    deletePatientVisit
};
