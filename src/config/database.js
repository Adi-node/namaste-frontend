import { createClient } from '@supabase/supabase-js';
import config from './config.js';

// Create Supabase clients for different access levels
let supabaseClient = null;
let supabaseServiceClient = null;

// Initialize the standard client (for authenticated users)
export const initializeSupabase = () => {
    try {
        // Standard client with anon key (for regular operations)
        supabaseClient = createClient(config.database.url, config.database.anonKey, {
            auth: {
                autoRefreshToken: true,
                persistSession: false, // We handle sessions with JWT
                detectSessionInUrl: false
            },
            realtime: {
                params: {
                    eventsPerSecond: 10
                }
            }
        });

        // Service role client (for admin operations and bypassing RLS)
        if (config.database.serviceRoleKey) {
            supabaseServiceClient = createClient(config.database.url, config.database.serviceRoleKey, {
                auth: {
                    autoRefreshToken: false,
                    persistSession: false
                }
            });
        }

        console.log('✅ Supabase clients initialized successfully');
        return true;
    } catch (error) {
        console.error('❌ Failed to initialize Supabase clients:', error.message);
        return false;
    }
};

// Get the standard Supabase client
export const getSupabaseClient = () => {
    if (!supabaseClient) {
        throw new Error('Supabase client not initialized. Call initializeSupabase() first.');
    }
    return supabaseClient;
};

// Get the service role client (for admin operations)
export const getSupabaseServiceClient = () => {
    if (!supabaseServiceClient) {
        console.warn('⚠️ Service role client not available. Some admin operations may fail.');
        return supabaseClient; // Fallback to regular client
    }
    return supabaseServiceClient;
};

// Set user context for Row Level Security (RLS)
export const setUserContext = async (userId, userRole) => {
    try {
        const client = getSupabaseClient();
        
        // Set user context for RLS policies
        const { error } = await client.rpc('set_config', {
            setting: 'app.user_id',
            value: userId
        });
        
        if (error) {
            console.warn('Failed to set user_id context:', error.message);
        }

        const { error: roleError } = await client.rpc('set_config', {
            setting: 'app.user_role', 
            value: userRole
        });

        if (roleError) {
            console.warn('Failed to set user_role context:', roleError.message);
        }

        return true;
    } catch (error) {
        console.error('Error setting user context:', error.message);
        return false;
    }
};

// Database health check
export const checkDatabaseHealth = async () => {
    try {
        const client = getSupabaseClient();
        const start = Date.now();
        
        // Simple query to test connection
        const { data, error } = await client
            .from('users')
            .select('id')
            .limit(1);
            
        const responseTime = Date.now() - start;
        
        if (error) {
            return {
                status: 'unhealthy',
                message: error.message,
                responseTime
            };
        }
        
        return {
            status: 'healthy',
            message: 'Database connection successful',
            responseTime,
            recordsAccessible: Array.isArray(data)
        };
    } catch (error) {
        return {
            status: 'unhealthy',
            message: error.message,
            responseTime: null
        };
    }
};

// Generic database operation wrapper with error handling
export const executeQuery = async (operation, tableName = 'unknown') => {
    try {
        const result = await operation();
        
        if (result.error) {
            console.error(`Database error in ${tableName}:`, result.error);
            throw new Error(`Database operation failed: ${result.error.message}`);
        }
        
        return result;
    } catch (error) {
        console.error(`Query execution error in ${tableName}:`, error.message);
        throw error;
    }
};

// Transaction helper (for complex operations)
export const executeTransaction = async (operations) => {
    const client = getSupabaseServiceClient();
    
    try {
        // Note: Supabase doesn't have explicit transactions like traditional SQL
        // We'll implement this using sequential operations with rollback logic
        const results = [];
        const rollbackOperations = [];
        
        for (const operation of operations) {
            try {
                const result = await operation.execute(client);
                results.push(result);
                
                if (operation.rollback) {
                    rollbackOperations.unshift(operation.rollback); // Reverse order for rollback
                }
            } catch (error) {
                // If any operation fails, attempt to rollback previous operations
                console.error('Transaction failed, attempting rollback:', error.message);
                
                for (const rollback of rollbackOperations) {
                    try {
                        await rollback(client);
                    } catch (rollbackError) {
                        console.error('Rollback operation failed:', rollbackError.message);
                    }
                }
                
                throw error;
            }
        }
        
        return results;
    } catch (error) {
        console.error('Transaction execution failed:', error.message);
        throw error;
    }
};

// Cleanup function for graceful shutdown
export const closeConnections = async () => {
    try {
        // Supabase handles connection cleanup automatically
        // but we can reset our client references
        supabaseClient = null;
        supabaseServiceClient = null;
        console.log('✅ Database connections cleaned up');
    } catch (error) {
        console.error('❌ Error during database cleanup:', error.message);
    }
};

export default {
    initializeSupabase,
    getSupabaseClient,
    getSupabaseServiceClient,
    setUserContext,
    checkDatabaseHealth,
    executeQuery,
    executeTransaction,
    closeConnections
};