
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import config from '../config/config.js';

dotenv.config();

const supabaseUrl = config.database.url;
const supabaseServiceRoleKey = config.database.serviceRoleKey;

const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

async function getAdminUserId() {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id')
            .eq('email', 'admin@namaste.health')
            .single();

        if (error) throw error;

        console.log('Admin User ID:', data.id);
        return data.id;
    } catch (error) {
        console.error('Error fetching admin user ID:', error.message);
        process.exit(1);
    }
}

getAdminUserId();
