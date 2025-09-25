
import { getSupabaseServiceClient } from '../config/database.js';
import { logError } from '../config/logger.js';
import Joi from 'joi';

// Joi schemas for validation
const createCodeMappingSchema = Joi.object({
    namasteCodeId: Joi.string().uuid().required(),
    icd11CodeId: Joi.string().uuid().required(),
    mappingType: Joi.string().valid('equivalent', 'broader', 'narrower', 'related').default('equivalent'),
    confidenceScore: Joi.number().min(0).max(1).default(1.0),
    notes: Joi.string().allow('').optional(),
});

// Helper function to fetch codes with pagination and search
const fetchCodes = async (tableName, req, res) => {
    try {
        const { page = 1, limit = 20, search = '' } = req.query;
        const offset = (page - 1) * limit;
        const supabase = getSupabaseServiceClient();

        let query = supabase
            .from(tableName)
            .select('*', { count: 'exact' });

        if (search) {
            query = query.or(`code.ilike.%${search}%,display_name.ilike.%${search}%`);
        }

        const { data, error, count } = await query
            .range(offset, offset + limit - 1)
            .order('display_name', { ascending: true });

        if (error) {
            logError(error, { context: `fetchCodes_${tableName}`, userId: req.user.id });
            return res.status(500).json({ error: `Failed to retrieve ${tableName}`, message: error.message });
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
        logError(error, { context: `fetchCodes_${tableName}`, userId: req.user.id });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

// Helper function to get a single code by its code string
const getCodeByCodeString = async (tableName, codeString, req, res) => {
    try {
        const supabase = getSupabaseServiceClient();
        const { data, error } = await supabase
            .from(tableName)
            .select('*')
            .eq('code', codeString)
            .single();

        if (error || !data) {
            return res.status(404).json({ error: 'Code not found', message: `No ${tableName} found with code ${codeString}` });
        }

        res.json(data);

    } catch (error) {
        logError(error, { context: `getCodeByCodeString_${tableName}`, userId: req.user.id });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

// NAMASTE Codes
export const getNamasteCodes = async (req, res) => fetchCodes('namaste_codes', req, res);
export const getNamasteCodeByCode = async (req, res) => getCodeByCodeString('namaste_codes', req.params.code, req, res);

// ICD-11 Codes
export const getIcd11Codes = async (req, res) => fetchCodes('icd11_codes', req, res);
export const getIcd11CodeByCode = async (req, res) => getCodeByCodeString('icd11_codes', req.params.code, req, res);

// Code Mappings
export const searchCodeMappings = async (req, res) => {
    try {
        const { page = 1, limit = 20, namasteCodeId, icd11CodeId, mappingType } = req.query;
        const offset = (page - 1) * limit;
        const supabase = getSupabaseServiceClient();

        let query = supabase
            .from('code_mappings')
            .select(`
                id,
                mapping_type,
                confidence_score,
                notes,
                created_at,
                updated_at,
                namaste_codes(id, code, display_name, sanskrit_name),
                icd11_codes(id, code, display_name)
            `, { count: 'exact' });

        if (namasteCodeId) query = query.eq('namaste_code_id', namasteCodeId);
        if (icd11CodeId) query = query.eq('icd11_code_id', icd11CodeId);
        if (mappingType) query = query.eq('mapping_type', mappingType);

        const { data, error, count } = await query
            .range(offset, offset + limit - 1)
            .order('created_at', { ascending: false });

        if (error) {
            logError(error, { context: 'searchCodeMappings', userId: req.user.id });
            return res.status(500).json({ error: 'Failed to retrieve code mappings', message: error.message });
        }

        const totalPages = Math.ceil(count / limit);

        res.json({
            data: data.map(mapping => ({
                id: mapping.id,
                namasteCode: mapping.namaste_codes,
                icd11Code: mapping.icd11_codes,
                mappingType: mapping.mapping_type,
                confidenceScore: mapping.confidence_score,
                notes: mapping.notes,
                createdAt: mapping.created_at,
                updatedAt: mapping.updated_at,
            })),
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
        logError(error, { context: 'searchCodeMappings', userId: req.user.id });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const createCodeMapping = async (req, res) => {
    try {
        const { error, value } = createCodeMappingSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: 'Validation failed', message: error.details[0].message });
        }

        const { namasteCodeId, icd11CodeId, mappingType, confidenceScore, notes } = value;
        const supabase = getSupabaseServiceClient();

        // Check if mapping already exists
        const { data: existingMapping } = await supabase
            .from('code_mappings')
            .select('id')
            .eq('namaste_code_id', namasteCodeId)
            .eq('icd11_code_id', icd11CodeId)
            .single();

        if (existingMapping) {
            return res.status(409).json({ error: 'Conflict', message: 'This code mapping already exists.' });
        }

        const { data, error: createError } = await supabase
            .from('code_mappings')
            .insert({
                namaste_code_id: namasteCodeId,
                icd11_code_id: icd11CodeId,
                mapping_type: mappingType,
                confidence_score: confidenceScore,
                notes,
                mapped_by: req.user.id, // Assuming req.user.id is available from auth middleware
            })
            .select()
            .single();

        if (createError) {
            logError(createError, { context: 'createCodeMapping', userId: req.user.id });
            return res.status(500).json({ error: 'Failed to create code mapping', message: createError.message });
        }

        res.status(201).json({ message: 'Code mapping created successfully', data });

    } catch (error) {
        logError(error, { context: 'createCodeMapping', userId: req.user.id });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export const autocompleteCodes = async (req, res) => {
    try {
        const { query = '' } = req.query;
        if (query.length < 2) {
            return res.json({ namaste: [], icd11: [] });
        }

        const supabase = getSupabaseServiceClient();

        // Search NAMASTE codes
        const { data: namasteResults, error: namasteError } = await supabase
            .from('namaste_codes')
            .select('id, code, display_name, sanskrit_name')
            .or(`code.ilike.%${query}%,display_name.ilike.%${query}%,sanskrit_name.ilike.%${query}%`)
            .limit(10);

        // Search ICD-11 codes
        const { data: icd11Results, error: icd11Error } = await supabase
            .from('icd11_codes')
            .select('id, code, display_name')
            .or(`code.ilike.%${query}%,display_name.ilike.%${query}%`)
            .limit(10);

        if (namasteError || icd11Error) {
            logError(namasteError || icd11Error, { context: 'autocompleteCodes', userId: req.user.id });
            return res.status(500).json({ error: 'Failed to fetch autocomplete suggestions', message: (namasteError || icd11Error).message });
        }

        res.json({
            namaste: namasteResults,
            icd11: icd11Results
        });

    } catch (error) {
        logError(error, { context: 'autocompleteCodes', userId: req.user.id });
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export default {
    getNamasteCodes,
    getNamasteCodeByCode,
    getIcd11Codes,
    getIcd11CodeByCode,
    searchCodeMappings,
    createCodeMapping,
    autocompleteCodes
};
