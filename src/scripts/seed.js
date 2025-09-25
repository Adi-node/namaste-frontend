import { initializeSupabase, getSupabaseServiceClient } from '../config/database.js';
import { hashPassword } from '../utils/auth.js';
import { logSystem, logError } from '../config/logger.js';
import fs from 'fs';
import path from 'path';

const seedDatabase = async () => {
    try {
        console.log('🌱 Starting database seeding...');
        
        // Initialize Supabase connection
        const initialized = initializeSupabase();
        if (!initialized) {
            throw new Error('Failed to initialize Supabase connection');
        }

        const supabase = getSupabaseServiceClient();

        // Step 1: Create tables using schema
        console.log('📋 Creating database schema...');
        await createTables(supabase);

        // Step 2: Seed users
        console.log('👥 Seeding users...');
        await seedUsers(supabase);

        // Step 3: Seed healthcare data
        console.log('🏥 Seeding healthcare terminology data...');
        await seedHealthcareData(supabase);

        console.log('✅ Database seeding completed successfully!');
        logSystem('Database seeding completed', { success: true });

    } catch (error) {
        console.error('❌ Database seeding failed:', error.message);
        logError(error, { context: 'seedDatabase' });
        process.exit(1);
    }
};

const createTables = async (supabase) => {
    try {
        // Read and execute schema file
        const schemaPath = path.join(process.cwd(), 'src/scripts/database_schema.sql');
        const schemaSQL = fs.readFileSync(schemaPath, 'utf8');

        // Split SQL commands and execute them one by one
        const commands = schemaSQL.split(';').filter(cmd => cmd.trim().length > 0);
        
        for (const command of commands) {
            const trimmedCommand = command.trim();
            if (trimmedCommand) {
                const { error } = await supabase.rpc('exec_sql', { sql_query: trimmedCommand });
                if (error && !error.message.includes('already exists')) {
                    console.warn('Schema warning:', error.message);
                }
            }
        }

        console.log('  ✓ Database schema created');
    } catch (error) {
        // For Supabase, we'll create tables using the client instead
        await createTablesDirectly(supabase);
    }
};

const createTablesDirectly = async (supabase) => {
    // Since we can't execute raw SQL directly, we'll ensure tables exist through Supabase client
    console.log('  ℹ Using Supabase client for table creation');
    console.log('  ⚠ Please ensure your database schema is created in Supabase dashboard');
    console.log('  📖 Run the SQL from src/scripts/database_schema.sql in your Supabase SQL editor');
};

const seedUsers = async (supabase) => {
    try {
        // Check if users already exist
        const { data: existingUsers } = await supabase
            .from('users')
            .select('email');

        if (existingUsers && existingUsers.length > 0) {
            console.log('  ℹ Users already exist, skipping user seeding');
            return;
        }

        // Create admin user
        const adminPassword = await hashPassword('Admin123!');
        const userPassword = await hashPassword('User123!');

        const usersToInsert = [
            {
                email: 'admin@namaste.health',
                password_hash: adminPassword,
                full_name: 'System Administrator',
                role: 'admin',
                email_verified: true,
                is_active: true
            },
            {
                email: 'user@namaste.health',
                password_hash: userPassword,
                full_name: 'Healthcare User',
                role: 'user',
                email_verified: true,
                is_active: true
            },
            {
                email: 'doctor@namaste.health',
                password_hash: userPassword,
                full_name: 'Dr. Priya Sharma',
                role: 'user',
                email_verified: true,
                is_active: true
            }
        ];

        const { error: usersError } = await supabase
            .from('users')
            .insert(usersToInsert);

        if (usersError) {
            throw usersError;
        }

        console.log('  ✓ Sample users created');
        console.log('    👨‍💼 Admin: admin@namaste.health / Admin123!');
        console.log('    👩‍⚕️ User: user@namaste.health / User123!');
        console.log('    🩺 Doctor: doctor@namaste.health / User123!');

    } catch (error) {
        if (error.message.includes('duplicate key value')) {
            console.log('  ℹ Users already exist, skipping');
        } else {
            throw error;
        }
    }
};

const seedHealthcareData = async (supabase) => {
    try {
        // Check if healthcare data already exists
        const { data: existingCodes } = await supabase
            .from('namaste_codes')
            .select('id')
            .limit(1);

        if (existingCodes && existingCodes.length > 0) {
            console.log('  ℹ Healthcare data already exists, skipping');
            return;
        }

        // Get admin user ID for created_by fields
        const { data: adminUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', 'admin@namaste.health')
            .single();

        const adminId = adminUser?.id;

        // Seed NAMASTE codes
        console.log('    📊 Creating NAMASTE codes...');
        const namasteCodes = await seedNamasteCodes(supabase, adminId);

        // Seed ICD-11 codes
        console.log('    📊 Creating ICD-11 codes...');
        const icd11Codes = await seedICD11Codes(supabase, adminId);

        // Create code mappings
        console.log('    🔗 Creating code mappings...');
        await seedCodeMappings(supabase, namasteCodes, icd11Codes, adminId);

        // Seed sample patient records
        console.log('    🏥 Creating sample patient records...');
        await seedPatientRecords(supabase, adminId);

        console.log('  ✓ Healthcare terminology data seeded');

    } catch (error) {
        throw error;
    }
};

const seedNamasteCodes = async (supabase, createdBy) => {
    const namasteCodes = [
        // Digestive System
        {
            code: 'NAM.DIG.001.234',
            display_name: 'Ajirna - Indigestion',
            sanskrit_name: 'अजीर्ण',
            description: 'Digestive disorder characterized by impaired digestion leading to various gastrointestinal symptoms in Ayurvedic medicine.',
            category: 'Digestive System',
            subcategory: 'Agni Vikara',
            system_type: 'Ayurveda',
            synonyms: ['Mandagni', 'Vishamagni', 'Pachakagni Dushti'],
            created_by: createdBy
        },
        {
            code: 'NAM.DIG.002.456',
            display_name: 'Grahani - Malabsorption Syndrome',
            sanskrit_name: 'ग्रहणी',
            description: 'Chronic digestive disorder affecting absorption and metabolism of nutrients.',
            category: 'Digestive System',
            subcategory: 'Grahani Roga',
            system_type: 'Ayurveda',
            synonyms: ['Sangrahani', 'Pravahika'],
            created_by: createdBy
        },
        // Respiratory System
        {
            code: 'NAM.RESP.003.789',
            display_name: 'Kasa - Cough',
            sanskrit_name: 'कास',
            description: 'Respiratory disorder characterized by persistent cough and related symptoms.',
            category: 'Respiratory System',
            subcategory: 'Pranvaha Srotas',
            system_type: 'Ayurveda',
            synonyms: ['Kshaya', 'Kshataja Kasa'],
            created_by: createdBy
        },
        {
            code: 'NAM.RESP.004.012',
            display_name: 'Swasa - Dyspnea',
            sanskrit_name: 'श्वास',
            description: 'Breathing difficulties and respiratory distress in traditional medicine.',
            category: 'Respiratory System',
            subcategory: 'Pranvaha Srotas',
            system_type: 'Ayurveda',
            synonyms: ['Shwasa Roga', 'Uras Kshata'],
            created_by: createdBy
        },
        // Musculoskeletal System
        {
            code: 'NAM.MSK.005.345',
            display_name: 'Sandhivata - Joint Pain',
            sanskrit_name: 'संधिवात',
            description: 'Joint disorders characterized by pain, stiffness, and limited mobility.',
            category: 'Musculoskeletal System',
            subcategory: 'Asthi Majja Gata Vata',
            system_type: 'Ayurveda',
            synonyms: ['Sandhigatavata', 'Jirna Sandhivata'],
            created_by: createdBy
        },
        {
            code: 'NAM.MSK.006.678',
            display_name: 'Amavata - Rheumatoid Arthritis',
            sanskrit_name: 'आमवात',
            description: 'Systemic inflammatory condition affecting joints and connective tissues.',
            category: 'Musculoskeletal System',
            subcategory: 'Ama Dosha Vikara',
            system_type: 'Ayurveda',
            synonyms: ['Sandhi Sotha', 'Vatarakta'],
            created_by: createdBy
        },
        // Cardiovascular System
        {
            code: 'NAM.CVS.007.901',
            display_name: 'Hrid Roga - Heart Disease',
            sanskrit_name: 'हृद्रोग',
            description: 'Cardiovascular disorders affecting heart function and circulation.',
            category: 'Cardiovascular System',
            subcategory: 'Raktavaha Srotas',
            system_type: 'Ayurveda',
            synonyms: ['Hridaya Vikara', 'Marma Abhighata'],
            created_by: createdBy
        },
        // Mental Health
        {
            code: 'NAM.MENT.008.234',
            display_name: 'Unmada - Mental Disorder',
            sanskrit_name: 'उन्माद',
            description: 'Psychiatric conditions affecting mental stability and cognitive function.',
            category: 'Mental Health',
            subcategory: 'Satvavaha Srotas',
            system_type: 'Ayurveda',
            synonyms: ['Manas Roga', 'Budhi Bhrama'],
            created_by: createdBy
        }
    ];

    const { data, error } = await supabase
        .from('namaste_codes')
        .insert(namasteCodes)
        .select();

    if (error) throw error;
    return data;
};

const seedICD11Codes = async (supabase, createdBy) => {
    const icd11Codes = [
        {
            code: 'DA90.0',
            display_name: 'Functional Dyspepsia',
            description: 'Chronic or recurrent pain or discomfort centered in the upper abdomen without evidence of organic disease.',
            category: 'Gastrointestinal',
            parent_code: 'DA90',
            created_by: createdBy
        },
        {
            code: 'DD90.1',
            display_name: 'Malabsorption, Unspecified',
            description: 'Impaired absorption of nutrients from the gastrointestinal tract.',
            category: 'Gastrointestinal',
            parent_code: 'DD90',
            created_by: createdBy
        },
        {
            code: 'CA23',
            display_name: 'Acute Bronchitis',
            description: 'Acute inflammation of the bronchi, usually caused by viral infection.',
            category: 'Respiratory',
            parent_code: 'CA20-CA2Z',
            created_by: createdBy
        },
        {
            code: 'CB03.4',
            display_name: 'Chronic Obstructive Pulmonary Disease',
            description: 'Progressive lung disease characterized by airflow limitation.',
            category: 'Respiratory',
            parent_code: 'CB03',
            created_by: createdBy
        },
        {
            code: 'FB50.1',
            display_name: 'Chronic Back Pain',
            description: 'Persistent pain in the back lasting more than 12 weeks.',
            category: 'Musculoskeletal',
            parent_code: 'FB50',
            created_by: createdBy
        },
        {
            code: 'FA20.2',
            display_name: 'Rheumatoid Arthritis',
            description: 'Chronic inflammatory disorder affecting joints and other tissues.',
            category: 'Musculoskeletal',
            parent_code: 'FA20',
            created_by: createdBy
        },
        {
            code: 'BA00.Z',
            display_name: 'Essential Hypertension',
            description: 'High blood pressure of unknown cause.',
            category: 'Cardiovascular',
            parent_code: 'BA00',
            created_by: createdBy
        },
        {
            code: '6A60',
            display_name: 'Anxiety Disorders',
            description: 'Group of mental disorders characterized by anxiety and fear.',
            category: 'Mental Health',
            parent_code: '6A6',
            created_by: createdBy
        }
    ];

    const { data, error } = await supabase
        .from('icd11_codes')
        .insert(icd11Codes)
        .select();

    if (error) throw error;
    return data;
};

const seedCodeMappings = async (supabase, namasteCodes, icd11Codes, mappedBy) => {
    // Create mappings between NAMASTE and ICD-11 codes
    const mappings = [
        { namasteCode: 'NAM.DIG.001.234', icd11Code: 'DA90.0', confidence: 0.85 },
        { namasteCode: 'NAM.DIG.002.456', icd11Code: 'DD90.1', confidence: 0.78 },
        { namasteCode: 'NAM.RESP.003.789', icd11Code: 'CA23', confidence: 0.92 },
        { namasteCode: 'NAM.RESP.004.012', icd11Code: 'CB03.4', confidence: 0.71 },
        { namasteCode: 'NAM.MSK.005.345', icd11Code: 'FB50.1', confidence: 0.88 },
        { namasteCode: 'NAM.MSK.006.678', icd11Code: 'FA20.2', confidence: 0.95 },
        { namasteCode: 'NAM.CVS.007.901', icd11Code: 'BA00.Z', confidence: 0.82 },
        { namasteCode: 'NAM.MENT.008.234', icd11Code: '6A60', confidence: 0.76 }
    ];

    const codeMappings = [];

    for (const mapping of mappings) {
        const namasteRecord = namasteCodes.find(nc => nc.code === mapping.namasteCode);
        const icd11Record = icd11Codes.find(ic => ic.code === mapping.icd11Code);

        if (namasteRecord && icd11Record) {
            codeMappings.push({
                namaste_code_id: namasteRecord.id,
                icd11_code_id: icd11Record.id,
                mapping_type: 'equivalent',
                confidence_score: mapping.confidence,
                notes: `Automated mapping based on clinical correlation`,
                mapped_by: mappedBy,
                is_verified: true
            });
        }
    }

    const { error } = await supabase
        .from('code_mappings')
        .insert(codeMappings);

    if (error) throw error;
};

const seedPatientRecords = async (supabase, createdBy) => {
    const patientRecords = [
        {
            patient_name: 'Priya Sharma',
            age: 45,
            gender: 'Female',
            contact_number: '+91 98765 43210',
            email: 'priya.sharma@email.com',
            address: 'Mumbai, Maharashtra',
            diagnosis: 'Functional Dyspepsia with traditional medicine correlation',
            namaste_code: 'NAM.DIG.001.234',
            icd11_code: 'DA90.0',
            treatment_summary: 'Ayurvedic treatment with digestive herbs and dietary modifications',
            prescription: 'Avipattikar Churna 3g twice daily, Hingwashtak Churna 1g before meals',
            hospital_name: 'NAMASTE Integrated Health Center',
            doctor_name: 'Dr. Rajesh Kumar',
            doctor_registration: 'AY12345',
            report_date: new Date().toISOString().split('T')[0],
            status: 'active',
            privacy_consent: true,
            created_by: createdBy
        },
        {
            patient_name: 'Rajesh Kumar',
            age: 52,
            gender: 'Male',
            contact_number: '+91 87654 32109',
            diagnosis: 'Chronic back pain with joint involvement',
            namaste_code: 'NAM.MSK.005.345',
            icd11_code: 'FB50.1',
            treatment_summary: 'Combined Ayurvedic and physiotherapy approach',
            prescription: 'Yogaraja Guggulu 500mg twice daily, external Pinda Sweda therapy',
            hospital_name: 'Integrated Wellness Clinic',
            doctor_name: 'Dr. Anita Verma',
            report_date: new Date().toISOString().split('T')[0],
            status: 'active',
            privacy_consent: true,
            created_by: createdBy
        },
        {
            patient_name: 'Anita Verma',
            age: 38,
            gender: 'Female',
            contact_number: '+91 76543 21098',
            diagnosis: 'Anxiety disorder with stress-related symptoms',
            namaste_code: 'NAM.MENT.008.234',
            icd11_code: '6A60',
            treatment_summary: 'Holistic treatment combining yoga therapy and herbal medicine',
            prescription: 'Saraswatarishta 15ml twice daily, Brahmi Ghrita 5ml at bedtime',
            hospital_name: 'Mind-Body Wellness Center',
            doctor_name: 'Dr. Priya Sharma',
            report_date: new Date().toISOString().split('T')[0],
            status: 'active',
            privacy_consent: true,
            created_by: createdBy
        }
    ];

    const { error } = await supabase
        .from('patient_records')
        .insert(patientRecords);

    if (error) throw error;
};

// Run the seeding process
if (import.meta.url === `file://${process.argv[1]}`) {
    seedDatabase();
}

export { seedDatabase };