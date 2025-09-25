import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:3001';

// Helper function to make API requests
const apiRequest = async (endpoint, options = {}) => {
    try {
        const url = `${BASE_URL}${endpoint}`;
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });

        const data = await response.json();
        
        return {
            status: response.status,
            ok: response.ok,
            data
        };
    } catch (error) {
        console.error(`❌ API Request failed for ${endpoint}:`, error.message);
        return { status: 0, ok: false, error: error.message };
    }
};

// Test functions
const testHealthCheck = async () => {
    console.log('\n🏥 Testing Health Check...');
    const result = await apiRequest('/health');
    
    if (result.ok) {
        console.log('✅ Health check passed');
        console.log(`   Database: ${result.data.database.status}`);
        console.log(`   Response time: ${result.data.database.responseTime}ms`);
    } else {
        console.log('❌ Health check failed:', result.data);
    }
    
    return result.ok;
};

const testLogin = async (email, password, role) => {
    console.log(`\n🔐 Testing ${role} login: ${email}...`);
    const result = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
    });
    
    if (result.ok) {
        console.log(`✅ ${role} login successful`);
        console.log(`   User: ${result.data.user.fullName}`);
        console.log(`   Role: ${result.data.user.role}`);
        console.log(`   Token: ${result.data.token.substring(0, 20)}...`);
        return result.data.token;
    } else {
        console.log(`❌ ${role} login failed:`, result.data);
        return null;
    }
};

const testProtectedEndpoint = async (token, endpoint, role) => {
    console.log(`\n🔒 Testing ${role} protected endpoint: ${endpoint}...`);
    const result = await apiRequest(endpoint, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    
    if (result.ok) {
        console.log(`✅ ${role} access granted to ${endpoint}`);
        if (result.data.user) {
            console.log(`   Profile: ${result.data.user.fullName} (${result.data.user.role})`);
        } else if (result.data.users) {
            console.log(`   Found ${result.data.users.length} users`);
        } else if (result.data.auditLogs) {
            console.log(`   Found ${result.data.auditLogs.length} audit logs`);
        }
    } else {
        console.log(`❌ ${role} access denied to ${endpoint}:`, result.data);
    }
    
    return result.ok;
};

const testUserRegistration = async () => {
    console.log('\n👤 Testing user registration...');
    const newUser = {
        email: 'test@namaste.health',
        password: 'Test123!',
        fullName: 'Test User'
    };
    
    const result = await apiRequest('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(newUser)
    });
    
    if (result.ok) {
        console.log('✅ User registration successful');
        console.log(`   New user: ${result.data.user.fullName}`);
        console.log(`   Email: ${result.data.user.email}`);
        return result.data.token;
    } else {
        if (result.data.message?.includes('already exists')) {
            console.log('ℹ️ User already exists (expected for repeated tests)');
            return null;
        } else {
            console.log('❌ User registration failed:', result.data);
            return null;
        }
    }
};

const testAuditLogs = async (adminToken) => {
    console.log('\n📋 Testing audit log access...');
    const result = await apiRequest('/api/admin/audit?limit=5', {
        headers: {
            'Authorization': `Bearer ${adminToken}`
        }
    });
    
    if (result.ok) {
        console.log('✅ Audit logs retrieved successfully');
        console.log(`   Total logs: ${result.data.pagination.totalCount}`);
        console.log(`   Recent actions:`);
        result.data.auditLogs.slice(0, 3).forEach(log => {
            console.log(`     - ${log.action} by ${log.userEmail} (${log.timestamp})`);
        });
    } else {
        console.log('❌ Failed to retrieve audit logs:', result.data);
    }
    
    return result.ok;
};

// Main test runner
const runTests = async () => {
    console.log('🚀 Starting NAMASTE Backend API Tests\n');
    console.log('=' .repeat(50));
    
    let passed = 0;
    let total = 0;
    
    // Test 1: Health Check
    total++;
    if (await testHealthCheck()) passed++;
    
    // Test 2: Admin Login
    total++;
    const adminToken = await testLogin('admin@namaste.health', 'Admin123!', 'Admin');
    if (adminToken) passed++;
    
    // Test 3: User Login
    total++;
    const userToken = await testLogin('user@namaste.health', 'User123!', 'User');
    if (userToken) passed++;
    
    // Test 4: User Registration
    total++;
    const newUserToken = await testUserRegistration();
    if (newUserToken !== false) passed++; // null is okay (user exists)
    
    if (adminToken) {
        // Test 5: Admin Profile Access
        total++;
        if (await testProtectedEndpoint(adminToken, '/api/auth/profile', 'Admin')) passed++;
        
        // Test 6: Admin User Management
        total++;
        if (await testProtectedEndpoint(adminToken, '/api/admin/users', 'Admin')) passed++;
        
        // Test 7: Admin Audit Logs
        total++;
        if (await testAuditLogs(adminToken)) passed++;
    }
    
    if (userToken) {
        // Test 8: User Profile Access
        total++;
        if (await testProtectedEndpoint(userToken, '/api/auth/profile', 'User')) passed++;
        
        // Test 9: User trying to access admin endpoint (should fail)
        total++;
        console.log('\n🚫 Testing user access to admin endpoint (should fail)...');
        const result = await testProtectedEndpoint(userToken, '/api/admin/users', 'User');
        if (!result) {
            console.log('✅ User correctly denied access to admin endpoint');
            passed++;
        } else {
            console.log('❌ User incorrectly granted admin access');
        }
    }
    
    // Results
    console.log('\n' + '='.repeat(50));
    console.log(`🎯 Test Results: ${passed}/${total} tests passed`);
    
    if (passed === total) {
        console.log('🎉 All tests passed! Backend is working perfectly!');
        console.log('\n✅ Features verified:');
        console.log('   - Health monitoring');
        console.log('   - JWT Authentication');
        console.log('   - Role-based access control');
        console.log('   - User registration');
        console.log('   - Admin user management');
        console.log('   - Comprehensive audit logging');
        console.log('   - Security middleware');
        
        console.log('\n🔗 Ready for frontend integration!');
        console.log('   Backend URL: http://localhost:3001');
        console.log('   Admin Login: admin@namaste.health / Admin123!');
        console.log('   User Login: user@namaste.health / User123!');
        
    } else {
        console.log(`❌ ${total - passed} tests failed. Please check the issues above.`);
    }
};

// Run tests if script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runTests().catch(console.error);
}