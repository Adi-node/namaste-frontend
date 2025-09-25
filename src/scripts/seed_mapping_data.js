
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import config from '../config/config.js';

dotenv.config();

const supabaseUrl = config.database.url;
const supabaseServiceRoleKey = config.database.serviceRoleKey;

const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

async function seedMappingData() {
    console.log('🌱 Seeding mapping data...');

    try {
        // Clear existing data (optional, for fresh seeding)
        // await supabase.from('code_mappings').delete().gt('created_at', '2000-01-01');
        // await supabase.from('namaste_codes').delete().gt('created_at', '2000-01-01');
        // await supabase.from('icd11_codes').delete().gt('created_at', '2000-01-01');

        // --- Insert NAMASTE Codes ---
        const namasteCodesToInsert = [
            {
                code: 'NAM.DIG.001.234',
                display_name: 'Ajirna (Indigestion)',
                sanskrit_name: 'अजीर्ण',
                description: 'Digestive disorder characterized by impaired digestion leading to various gastrointestinal symptoms in Ayurvedic medicine.',
                category: 'Digestive System',
                subcategory: 'Agni Vikara',
                synonyms: ['Mandagni', 'Vishamagni', 'Pachakagni Dushti'],
            },
            {
                code: 'NAM.RES.002.101',
                display_name: 'Kasa (Cough)',
                sanskrit_name: 'कास',
                description: 'A common respiratory symptom in Ayurveda, often classified by its origin and associated doshas.',
                category: 'Respiratory System',
                subcategory: 'Pranavaha Srotas',
                synonyms: ['Shwasa', 'Kshaya Kasa'],
            },
            {
                code: 'NAM.CARD.003.500',
                display_name: 'Hridroga (Heart Disease)',
                sanskrit_name: 'हृद्रोग',
                description: 'A broad term in Ayurveda encompassing various cardiac ailments, often linked to imbalances in Rasa Dhatu.',
                category: 'Cardiovascular System',
                subcategory: 'Rasa Dhatu Vikara',
                synonyms: ['Hridaya Roga'],
            },
        ];

        const { data: namasteData, error: namasteError } = await supabase
            .from('namaste_codes')
            .upsert(namasteCodesToInsert, { onConflict: 'code' })
            .select();

        if (namasteError) throw namasteError;
        console.log(`✅ Inserted/Updated ${namasteData.length} NAMASTE codes.`);

        // --- Insert ICD-11 Codes ---
        const icd11CodesToInsert = [
            {
                code: 'DA90.0',
                display_name: 'Functional dyspepsia',
                description: 'Chronic or recurrent pain or discomfort centered in the upper abdomen without evidence of organic disease.',
                category: 'Diseases of the digestive system',
                parent_code: 'DA90',
            },
            {
                code: 'CA00.0',
                display_name: 'Acute bronchitis',
                description: 'Acute inflammation of the bronchi, usually viral in origin.',
                category: 'Diseases of the respiratory system',
                parent_code: 'CA00',
            },
            {
                code: 'BA00.0',
                display_name: 'Essential hypertension',
                description: 'High blood pressure with no identifiable secondary cause.',
                category: 'Diseases of the circulatory system',
                parent_code: 'BA00',
            },
        ];

        const { data: icd11Data, error: icd11Error } = await supabase
            .from('icd11_codes')
            .upsert(icd11CodesToInsert, { onConflict: 'code' })
            .select();

        if (icd11Error) throw icd11Error;
        console.log(`✅ Inserted/Updated ${icd11Data.length} ICD-11 codes.`);

        // --- Insert Code Mappings ---
        // Fetch IDs of the codes we just inserted
        const namasteAjirna = namasteData.find(c => c.code === 'NAM.DIG.001.234');
        const namasteKasa = namasteData.find(c => c.code === 'NAM.RES.002.101');
        const namasteHridroga = namasteData.find(c => c.code === 'NAM.CARD.003.500');

        const icd11Dyspepsia = icd11Data.find(c => c.code === 'DA90.0');
        const icd11Bronchitis = icd11Data.find(c => c.code === 'CA00.0');
        const icd11Hypertension = icd11Data.find(c => c.code === 'BA00.0');

        const mappingsToInsert = [
            {
                namaste_code_id: namasteAjirna.id,
                icd11_code_id: icd11Dyspepsia.id,
                mapping_type: 'equivalent',
                confidence_score: 0.95,
                notes: 'Direct conceptual match based on symptoms and etiology.',
                mapped_by: '3159fd7f-cce7-4a01-aebd-41c29c40b12f', // Actual admin user ID
            },
            {
                namaste_code_id: namasteKasa.id,
                icd11_code_id: icd11Bronchitis.id,
                mapping_type: 'broader',
                confidence_score: 0.80,
                notes: 'Kasa is a broader Ayurvedic concept, acute bronchitis is a specific modern diagnosis.',
                mapped_by: '3159fd7f-cce7-4a01-aebd-41c29c40b12f', // Actual admin user ID
            },
            {
                namaste_code_id: namasteHridroga.id,
                icd11_code_id: icd11Hypertension.id,
                mapping_type: 'related',
                confidence_score: 0.70,
                notes: 'Hridroga can include conditions leading to hypertension, but not a direct equivalent.',
                mapped_by: '3159fd7f-cce7-4a01-aebd-41c29c40b12f', // Actual admin user ID
            },
        ];

        const { data: mappingData, error: mappingError } = await supabase
            .from('code_mappings')
            .upsert(mappingsToInsert, { onConflict: ['namaste_code_id', 'icd11_code_id'] })
            .select();

        if (mappingError) throw mappingError;
        console.log(`✅ Inserted/Updated ${mappingData.length} code mappings.`);

        console.log('🎉 Mapping data seeding complete!');

    } catch (error) {
        console.error('❌ Error seeding mapping data:', error.message);
        process.exit(1);
    }
}

seedMappingData();
