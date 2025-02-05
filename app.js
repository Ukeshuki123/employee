const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 8090;
const JWT_SECRET = 'your-secret-key'; // In production, use environment variable

// Database configuration
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: 'Uki@12345',
    database: 'employee_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Create the connection pool
const pool = mysql.createPool(dbConfig);

// Test database connection
async function testConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('Database connected successfully');
        connection.release();
    } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
    }
}

// Test connection on startup
testConnection();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Root path redirects to login
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

// Serve login page
app.get('/login', (req, res) => {
    res.redirect('/login.html');
});

// Serve index page
app.get('/index', (req, res) => {
    res.redirect('/index.html');
});

// Serve employee page
app.get('/employee', (req, res) => {
    res.redirect('/employee.html');
});

// Serve checklist page
app.get('/checklist', (req, res) => {
    res.redirect('/checklist.html');
});

// Verify JWT token middleware
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access token is required' 
        });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
        req.user = decoded;
        next();
    });
};

// Check authentication status
app.get('/api/check-auth', verifyToken, (req, res) => {
    res.json({
        success: true,
        user: {
            id: req.user.id,
            username: req.user.username,
            role: req.user.role,
            branch: req.user.branch
        }
    });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Query for user
        const [rows] = await pool.query(
            'SELECT id, username, password, role, branchname FROM employees WHERE username = ?',
            [username]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        const user = rows[0];

        // Compare password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Create token with user info
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                role: user.role,
                branch: user.branchname
            },
            JWT_SECRET,
            { expiresIn: '30d' }
        );

        // Send response
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                branch: user.branchname
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed',
            error: error.message
        });
    }
});

// Add new employee
app.post('/api/employees', verifyToken, async (req, res) => {
    try {
        const { username, password, role, branchname } = req.body;

        // Validate input
        if (!username || !password || !role || !branchname) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }

        // Check if user has permission
        if (req.user.role !== 'admin' && req.user.role !== 'management') {
            return res.status(403).json({ success: false, message: 'Unauthorized to add employees' });
        }

        // Management users can only add regular users
        if (req.user.role === 'management' && role !== 'user') {
            return res.status(403).json({ success: false, message: 'Management users can only add regular users' });
        }

        // Check if username already exists
        let connection;
        connection = await pool.getConnection();
        const [existingUser] = await connection.query(
            'SELECT id FROM employees WHERE username = ?',
            [username]
        );

        if (existingUser.length > 0) {
            connection.release();
            return res.status(400).json({ success: false, message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new employee
        await connection.query(
            'INSERT INTO employees (username, password, role, branchname) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, role, branchname]
        );
        connection.release();
        res.json({ success: true, message: 'Employee added successfully' });
    } catch (error) {
        console.error('Error adding employee:', error);
        res.status(500).json({ success: false, message: 'Error adding employee' });
    }
});

// Get all employees
app.get('/api/employees', verifyToken, async (req, res) => {
    try {
        let query = 'SELECT id, username, role, branchname, created_at FROM employees';
        
        // If management user, only show regular users
        if (req.user.role === 'management') {
            query += " WHERE role = 'user'";
        }

        let connection;
        connection = await pool.getConnection();
        const [employees] = await connection.query(query);
        connection.release();
        res.json({ success: true, employees });
    } catch (error) {
        console.error('Error getting employees:', error);
        res.status(500).json({ success: false, message: 'Error getting employees' });
    }
});

// Delete employee
app.delete('/api/employees/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Check if user has permission
        if (req.user.role !== 'admin' && req.user.role !== 'management') {
            return res.status(403).json({ success: false, message: 'Unauthorized to delete employees' });
        }

        // Get employee details
        let connection;
        connection = await pool.getConnection();
        const [employee] = await connection.query(
            'SELECT role FROM employees WHERE id = ?',
            [id]
        );

        if (employee.length === 0) {
            connection.release();
            return res.status(404).json({ success: false, message: 'Employee not found' });
        }

        // Management users can only delete regular users
        if (req.user.role === 'management' && employee[0].role !== 'user') {
            connection.release();
            return res.status(403).json({ success: false, message: 'Management users can only delete regular users' });
        }

        await connection.query(
            'DELETE FROM employees WHERE id = ?',
            [id]
        );
        connection.release();
        res.json({ success: true, message: 'Employee deleted successfully' });
    } catch (error) {
        console.error('Error deleting employee:', error);
        res.status(500).json({ success: false, message: 'Error deleting employee' });
    }
});

// Get checklist questions
app.get('/api/checklist/questions', verifyToken, async (req, res) => {
    try {
        let connection;
        connection = await pool.getConnection();
        const [rows] = await connection.query(`
            SELECT id, section, question_text as question, question_type as type
            FROM checklist_questions
            ORDER BY section, id
        `);
        connection.release();
        res.json({
            success: true,
            questions: rows
        });
    } catch (error) {
        console.error('Error fetching questions:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch questions',
            error: error.message
        });
    }
});

// Submit checklist responses
app.post('/api/checklist/submit', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const { responses } = req.body;
        const employeeId = req.user.id;
        const currentTime = new Date();

        // Get employee details
        const [employeeDetails] = await connection.query(
            'SELECT username, branchname FROM employees WHERE id = ?',
            [employeeId]
        );

        if (!employeeDetails || employeeDetails.length === 0) {
            throw new Error('Employee not found');
        }

        const { username, branchname } = employeeDetails[0];

        // Validate responses
        if (!Array.isArray(responses) || responses.length === 0) {
            throw new Error('No responses provided');
        }

        // Insert each response
        for (const response of responses) {
            // Validate required fields
            if (!response.question_id || !response.type || !response.question_text) {
                throw new Error('Missing required fields in response');
            }

            // Insert response
            await connection.query(
                `INSERT INTO checklist_responses (
                    employee_id,
                    username,
                    branchname,
                    question_id,
                    question_text,
                    question_type,
                    mcq_status,
                    answer_text,
                    submitted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    employeeId,
                    username,
                    branchname,
                    response.question_id,
                    response.question_text.trim(),
                    response.type,
                    response.type === 'mcq' ? response.status : null,
                    response.type === 'text' ? response.answer : null,
                    currentTime
                ]
            );
        }

        await connection.commit();
        res.json({
            success: true,
            message: 'Responses submitted successfully',
            timestamp: currentTime
        });
    } catch (error) {
        if (connection) {
            await connection.rollback();
        }
        console.error('Error submitting responses:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to submit responses: ' + error.message
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Get latest checklist responses (admin only)
app.get('/api/checklist/latest', verifyToken, async (req, res) => {
    try {
        // Check if user exists and is admin
        let connection;
        connection = await pool.getConnection();
        const [userRows] = await connection.query(
            'SELECT role FROM employees WHERE username = ?',
            [req.user.username]
        );

        if (!userRows || userRows.length === 0) {
            connection.release();
            return res.status(403).json({
                success: false,
                message: 'User not found'
            });
        }

        const isAdmin = userRows[0].role === 'admin';
        if (!isAdmin) {
            connection.release();
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        // Get latest responses with question and employee details
        const [responses] = await connection.query(`
            SELECT 
                cr.id,
                cr.question_id,
                cr.employee_id,
                cr.answer_text as answer,
                cr.mcq_status as status,
                cr.submitted_at as time,
                cq.question_text as question,
                cq.section,
                cq.question_type as type,
                e.username as employee_name,
                e.branchname as employee_branch
            FROM responses cr
            JOIN checklist_questions cq ON cr.question_id = cq.id
            JOIN employees e ON cr.employee_id = e.id
            WHERE cr.id IN (
                SELECT MAX(id)
                FROM responses
                GROUP BY question_id, employee_id
            )
            ORDER BY cr.submitted_at DESC
        `);
        connection.release();
        // Initialize response objects
        const byStatus = {
            yes: [],
            no: [],
            pending: []
        };

        const writtenResponses = {
            Kitchen: [],
            Cafe: []
        };

        // Process each response
        responses.forEach(row => {
            const response = {
                id: row.id,
                question_id: row.question_id,
                employee_id: row.employee_id,
                status: row.status?.toLowerCase() || 'pending',
                answer: row.answer || '',
                time: row.time,
                question: row.question,
                section: row.section,
                type: row.type,
                employee: row.employee_name,
                branch: row.employee_branch
            };

            if (row.type === 'written') {
                writtenResponses[row.section].push(response);
            } else {
                byStatus[response.status || 'pending'].push(response);
            }
        });

        res.json({
            success: true,
            byStatus,
            writtenResponses
        });
    } catch (error) {
        console.error('Error fetching latest responses:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch responses',
            error: error.message
        });
    }
});

// Delete response (admin only)
app.delete('/api/checklist/response/:id', verifyToken, async (req, res) => {
    try {
        // Check if user is admin
        let connection;
        connection = await pool.getConnection();
        const [userRows] = await connection.query(
            'SELECT role FROM employees WHERE username = ?',
            [req.user.username]
        );

        if (!userRows || userRows.length === 0 || userRows[0].role !== 'admin') {
            connection.release();
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const responseId = req.params.id;
        await connection.query('DELETE FROM responses WHERE id = ?', [responseId]);
        connection.release();
        res.json({
            success: true,
            message: 'Response deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting response:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete response',
            error: error.message
        });
    }
});

// Get checklist responses
app.get('/api/checklist/responses', verifyToken, async (req, res) => {
    try {
        let connection;
        try {
            connection = await pool.getConnection();
            
            let query = `
                SELECT 
                    cr.id,
                    cr.submitted_at as created_at,
                    cr.mcq_status as status,
                    e.username,
                    e.branchname as branch,
                    JSON_ARRAYAGG(
                        JSON_OBJECT(
                            'question', cq.question_text,
                            'response', COALESCE(cr.mcq_status, cr.answer_text)
                        )
                    ) as answers
                FROM responses cr
                JOIN employees e ON cr.employee_id = e.id
                JOIN checklist_questions cq ON cr.question_id = cq.id
                WHERE 1=1
            `;
            
            const params = [];
            
            if (req.query.branch) {
                query += ' AND e.branchname = ?';
                params.push(req.query.branch);
            }
            
            if (req.query.date) {
                query += ' AND DATE(cr.submitted_at) = ?';
                params.push(req.query.date);
            }
            
            if (req.query.responseType) {
                query += ' AND cr.mcq_status = ?';
                params.push(req.query.responseType);
            }
            
            query += ' GROUP BY cr.id, cr.submitted_at, cr.mcq_status, e.username, e.branchname';
            query += ' ORDER BY cr.submitted_at DESC';
            
            const [responses] = await connection.query(query, params);
            
            // Parse the answers JSON for each response
            responses.forEach(response => {
                if (typeof response.answers === 'string') {
                    response.answers = JSON.parse(response.answers);
                }
            });
            
            res.json({ responses });
            
        } finally {
            if (connection) connection.release();
        }
    } catch (error) {
        console.error('Error getting checklist responses:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get checklist statistics
app.get('/api/checklist/stats', verifyToken, async (req, res) => {
    try {
        let connection;
        try {
            connection = await pool.getConnection();
            
            const today = new Date().toISOString().split('T')[0];
            
            const [stats] = await connection.query(`
                SELECT
                    (SELECT COUNT(DISTINCT id) FROM responses) as totalChecklists,
                    (SELECT COUNT(DISTINCT id) FROM responses WHERE mcq_status = 'yes') as completedChecklists,
                    (SELECT COUNT(DISTINCT id) FROM responses WHERE DATE(submitted_at) = ?) as todayUpdates,
                    (SELECT COUNT(DISTINCT id) FROM responses WHERE mcq_status = 'yes') as yesResponses,
                    (SELECT COUNT(DISTINCT id) FROM responses WHERE mcq_status = 'no') as noResponses,
                    (SELECT COUNT(DISTINCT id) FROM responses WHERE mcq_status = 'pending') as pendingResponses,
                    (SELECT COUNT(DISTINCT id) FROM responses WHERE mcq_status IS NOT NULL) as allResponses
            `, [today]);
            
            res.json(stats[0]);
            
        } finally {
            if (connection) connection.release();
        }
    } catch (error) {
        console.error('Error getting checklist stats:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get branches
app.get('/api/branches', verifyToken, async (req, res) => {
    try {
        let connection;
        try {
            connection = await pool.getConnection();
            
            const [branches] = await connection.query(`
                SELECT DISTINCT branchname as name
                FROM employees
                ORDER BY branchname
            `);
            
            res.json({ branches });
            
        } finally {
            if (connection) connection.release();
        }
    } catch (error) {
        console.error('Error getting branches:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all branches
app.get('/api/branches', verifyToken, async (req, res) => {
    try {
        const query = `SELECT DISTINCT branchname FROM employees`;
        const result = await pool.query(query);
        res.json({ branches: result.rows.map(row => row.branchname) });
    } catch (error) {
        console.error('Error getting branches:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get response statistics
app.get('/api/responses/stats', verifyToken, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        
        // Get total branches (from employees)
        const branchesQuery = `SELECT COUNT(DISTINCT branchname) as total FROM employees`;
        const branchesResult = await pool.query(branchesQuery);
        
        // Get completed checklists
        const completedQuery = `SELECT COUNT(DISTINCT branchname) as total FROM responses WHERE DATE(submitted_at) <= $1`;
        const completedResult = await pool.query(completedQuery, [today]);
        
        // Get today's updates
        const todayQuery = `SELECT COUNT(DISTINCT branchname) as total FROM responses WHERE DATE(submitted_at) = $1`;
        const todayResult = await pool.query(todayQuery, [today]);
        
        // Get response counts by type
        const statusQuery = `
            SELECT 
                mcq_status,
                COUNT(*) as count
            FROM responses 
            WHERE mcq_status IS NOT NULL
            GROUP BY mcq_status`;
        const statusResult = await pool.query(statusQuery);
        
        // Get total responses
        const totalResponsesQuery = `SELECT COUNT(*) as total FROM responses`;
        const totalResult = await pool.query(totalResponsesQuery);
        
        const stats = {
            totalBranches: branchesResult.rows[0].total,
            completedChecklists: completedResult.rows[0].total,
            todayUpdates: todayResult.rows[0].total,
            yes: 0,
            no: 0,
            pending: 0,
            totalResponses: totalResult.rows[0].total
        };
        
        statusResult.rows.forEach(row => {
            if (row.mcq_status === 'yes') stats.yes = parseInt(row.count);
            if (row.mcq_status === 'no') stats.no = parseInt(row.count);
            if (row.mcq_status === 'pending') stats.pending = parseInt(row.count);
        });
        
        res.json(stats);
    } catch (error) {
        console.error('Error getting response stats:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get detailed responses by type
app.get('/api/responses/details/:type', verifyToken, async (req, res) => {
    try {
        const { type } = req.params;
        let query = '';
        const params = [];

        switch (type) {
            case 'total-branches':
                query = `SELECT DISTINCT branchname FROM employees ORDER BY branchname`;
                break;

            case 'completed-checklists':
                query = `
                    SELECT DISTINCT r.branchname 
                    FROM responses r 
                    WHERE DATE(r.created_at) = CURDATE()
                    ORDER BY r.branchname
                `;
                break;

            case 'today-updates':
                query = `
                    SELECT DISTINCT r.branchname 
                    FROM responses r 
                    WHERE DATE(r.created_at) = CURDATE()
                    ORDER BY r.branchname
                `;
                break;

            case 'yes':
            case 'no':
            case 'pending':
                query = `
                    SELECT 
                        r.id,
                        r.branchname,
                        r.username,
                        r.question_text,
                        r.mcq_status,
                        DATE_FORMAT(r.created_at, '%Y-%m-%d %H:%i:%s') as formatted_date
                    FROM responses r
                    WHERE r.mcq_status = ?
                    ORDER BY r.created_at DESC
                `;
                params.push(type);
                break;

            case 'all':
                query = `
                    SELECT 
                        r.id,
                        r.branchname,
                        r.username,
                        r.question_text,
                        r.mcq_status,
                        DATE_FORMAT(r.created_at, '%Y-%m-%d %H:%i:%s') as formatted_date
                    FROM responses r
                    ORDER BY r.created_at DESC
                `;
                break;

            default:
                return res.status(400).json({ error: 'Invalid type' });
        }

        const [rows] = await pool.query(query, params);
        res.json({ responses: rows });
    } catch (error) {
        console.error('Error getting response details:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all responses with filters
app.get('/api/responses', verifyToken, async (req, res) => {
    try {
        const { branch, status, fromDate, toDate } = req.query;
        
        let query = `
            SELECT 
                cr.id,
                cr.employee_id,
                cr.username,
                cr.branchname,
                cr.question_id,
                cr.question_text,
                cr.question_type,
                cr.mcq_status,
                cr.answer_text,
                DATE_FORMAT(cr.submitted_at, '%Y-%m-%d %H:%i:%s') as formatted_date
            FROM checklist_responses cr
            WHERE 1=1
        `;
        
        const params = [];

        if (branch) {
            query += ` AND cr.branchname = ?`;
            params.push(branch);
        }

        if (status) {
            query += ` AND cr.mcq_status = ?`;
            params.push(status);
        }

        if (fromDate) {
            query += ` AND DATE(cr.submitted_at) >= ?`;
            params.push(fromDate);
        }

        if (toDate) {
            query += ` AND DATE(cr.submitted_at) <= ?`;
            params.push(toDate);
        }

        query += ` ORDER BY cr.submitted_at DESC`;

        const [responses] = await pool.query(query, params);
        
        // Get unique branches for filter
        const [branches] = await pool.query('SELECT DISTINCT branchname FROM checklist_responses ORDER BY branchname');

        // Get statistics
        const [stats] = await pool.query(`
            SELECT 
                COUNT(DISTINCT branchname) as total_branches,
                COUNT(DISTINCT CASE WHEN DATE(submitted_at) = CURDATE() THEN employee_id END) as completed_today,
                COUNT(CASE WHEN DATE(submitted_at) = CURDATE() THEN 1 END) as today_updates,
                SUM(CASE WHEN mcq_status = 'yes' THEN 1 ELSE 0 END) as yes_count,
                SUM(CASE WHEN mcq_status = 'no' THEN 1 ELSE 0 END) as no_count,
                SUM(CASE WHEN mcq_status = 'pending' THEN 1 ELSE 0 END) as pending_count
            FROM checklist_responses
        `);

        res.json({
            responses,
            branches: branches.map(b => b.branchname),
            stats: {
                totalBranches: stats[0].total_branches || 0,
                completedToday: stats[0].completed_today || 0,
                todayUpdates: stats[0].today_updates || 0,
                yesCount: stats[0].yes_count || 0,
                noCount: stats[0].no_count || 0,
                pendingCount: stats[0].pending_count || 0
            }
        });
    } catch (error) {
        console.error('Error fetching responses:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get response statistics
app.get('/api/responses/stats', verifyToken, async (req, res) => {
    try {
        // Get total branches
        const [totalBranches] = await pool.query('SELECT COUNT(DISTINCT branchname) as count FROM checklist_responses');
        
        // Get completed checklists
        const [completedChecklists] = await pool.query(`
            SELECT COUNT(DISTINCT branchname) as count 
            FROM checklist_responses 
            WHERE DATE(submitted_at) = CURDATE() 
            AND mcq_status = 'yes'
        `);
        
        // Get today's updates
        const [todayUpdates] = await pool.query(`
            SELECT COUNT(*) as count 
            FROM checklist_responses 
            WHERE DATE(submitted_at) = CURDATE()
        `);
        
        // Get response counts by status
        const [statusCounts] = await pool.query(`
            SELECT 
                SUM(CASE WHEN mcq_status = 'yes' THEN 1 ELSE 0 END) as yes_count,
                SUM(CASE WHEN mcq_status = 'no' THEN 1 ELSE 0 END) as no_count,
                SUM(CASE WHEN mcq_status = 'pending' THEN 1 ELSE 0 END) as pending_count,
                COUNT(*) as total_count
            FROM checklist_responses
            WHERE question_type = 'mcq'
        `);
        
        res.json({
            totalBranches: totalBranches[0].count || 0,
            completedChecklists: completedChecklists[0].count || 0,
            todayUpdates: todayUpdates[0].count || 0,
            yes: statusCounts[0].yes_count || 0,
            no: statusCounts[0].no_count || 0,
            pending: statusCounts[0].pending_count || 0,
            totalResponses: statusCounts[0].total_count || 0
        });
    } catch (error) {
        console.error('Error getting response statistics:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get response details by type
app.get('/api/responses/details/:type', verifyToken, async (req, res) => {
    try {
        const { type } = req.params;
        let query = '';
        const params = [];

        switch (type) {
            case 'total-branches':
                query = `SELECT DISTINCT branchname FROM employees ORDER BY branchname`;
                break;

            case 'completed-checklists':
                query = `
                    SELECT DISTINCT e.branchname 
                    FROM responses r 
                    JOIN employees e ON r.employee_id = e.id
                    WHERE DATE(r.created_at) = CURDATE()
                    ORDER BY e.branchname
                `;
                break;

            case 'today-updates':
                query = `
                    SELECT DISTINCT e.branchname 
                    FROM responses r 
                    JOIN employees e ON r.employee_id = e.id
                    WHERE DATE(r.created_at) = CURDATE()
                    ORDER BY e.branchname
                `;
                break;

            case 'yes':
            case 'no':
            case 'pending':
                query = `
                    SELECT 
                        r.id,
                        e.branchname,
                        q.question_text,
                        r.mcq_status,
                        r.answer_text,
                        DATE_FORMAT(r.created_at, '%Y-%m-%d %H:%i:%s') as formatted_date
                    FROM responses r 
                    JOIN employees e ON r.employee_id = e.id
                    JOIN checklist_questions q ON r.question_id = q.id
                    WHERE r.mcq_status = ?
                    ORDER BY r.created_at DESC
                `;
                params.push(type);
                break;

            case 'all':
                query = `
                    SELECT 
                        r.id,
                        e.branchname,
                        q.question_text,
                        r.mcq_status,
                        r.answer_text,
                        DATE_FORMAT(r.created_at, '%Y-%m-%d %H:%i:%s') as formatted_date
                    FROM responses r 
                    JOIN employees e ON r.employee_id = e.id
                    JOIN checklist_questions q ON r.question_id = q.id
                    ORDER BY r.created_at DESC
                `;
                break;

            default:
                return res.status(400).json({ error: 'Invalid type' });
        }

        const [rows] = await pool.query(query, params);
        res.json({ responses: rows });
    } catch (error) {
        console.error('Error getting response details:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get missing checklist branches
app.get('/api/responses/missing-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        
        // Get all branches that haven't submitted today
        const query = `
            SELECT DISTINCT
                e.branchname
            FROM employee_db.employees e
            WHERE e.branchname NOT IN (
                SELECT DISTINCT branchname 
                FROM checklist_responses 
                WHERE DATE(submitted_at) = CURDATE() 
                AND mcq_status = 'yes'
            )
            ORDER BY e.branchname ASC;
        `;
        
        // Get counts
        const countQuery = `
            SELECT 
                (SELECT COUNT(DISTINCT branchname) FROM employees) as total,
                (
                    SELECT COUNT(DISTINCT branchname) 
                    FROM checklist_responses 
                    WHERE DATE(submitted_at) = CURDATE() 
                    AND mcq_status = 'yes'
                ) as submitted
        `;
        
        const [branches] = await connection.query(query);
        const [counts] = await connection.query(countQuery);
        
        console.log('Query result - branches:', branches); // Debug log
        
        res.json({ 
            branches: branches,
            stats: {
                total: counts[0].total || 0,
                submitted: counts[0].submitted || 0,
                missing: branches.length
            }
        });
    } catch (error) {
        console.error('Error getting missing branches:', error);
        res.status(500).json({ 
            error: 'Failed to retrieve missing branches',
            details: error.message,
            branches: [],
            stats: {
                total: 0,
                submitted: 0,
                missing: 0
            }
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Get completed checklist branches
app.get('/api/responses/completed-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        
        // Get all branches that have submitted checklists
        const query = `
            SELECT DISTINCT cr.branchname as name
            FROM checklist_responses cr
            WHERE cr.mcq_status = 'yes'
            ORDER BY cr.branchname ASC;
        `;
        
        const [branches] = await connection.query(query);
        console.log('Raw query results:', branches);
        
        if (!branches || branches.length === 0) {
            console.log('No branches found');
            return res.json({ branches: [] });
        }
        
        // Make sure we have valid branch names
        const validBranches = branches.filter(b => b && b.name);
        console.log('Valid branches:', validBranches);
        
        res.json({ 
            branches: validBranches
        });
    } catch (error) {
        console.error('Error getting completed branches:', error);
        res.status(500).json({
            error: 'Failed to retrieve completed branches',
            branches: []
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Get today's updates by branch
app.get('/api/responses/today-updates', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                branchname,
                COUNT(*) as update_count
            FROM checklist_responses 
            WHERE DATE(submitted_at) = CURDATE()
            GROUP BY branchname
            ORDER BY branchname
        `;
        
        const [updates] = await pool.query(query);
        res.json({ updates });
    } catch (error) {
        console.error('Error getting today updates:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get responses by status
app.get('/api/responses/by-status/:status', verifyToken, async (req, res) => {
    try {
        const { status } = req.params;
        const query = `
            SELECT 
                r.id,
                r.branchname,
                r.username,
                r.question_text,
                r.mcq_status,
                DATE_FORMAT(r.submitted_at, '%Y-%m-%d %H:%i:%s') as formatted_date
            FROM checklist_responses r
            WHERE r.mcq_status = ?
            ORDER BY r.submitted_at DESC
        `;
        
        const [responses] = await pool.query(query, [status]);
        res.json({ responses });
    } catch (error) {
        console.error('Error getting responses by status:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get response counts
app.get('/api/responses/counts', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                SUM(CASE WHEN mcq_status = 'yes' THEN 1 ELSE 0 END) as yes_count,
                SUM(CASE WHEN mcq_status = 'no' THEN 1 ELSE 0 END) as no_count,
                SUM(CASE WHEN mcq_status = 'pending' THEN 1 ELSE 0 END) as pending_count
            FROM checklist_responses
            WHERE DATE(submitted_at) = CURDATE()
        `;
        
        const [counts] = await pool.query(query);
        
        res.json({
            yes: counts[0].yes_count || 0,
            no: counts[0].no_count || 0,
            pending: counts[0].pending_count || 0
        });
    } catch (error) {
        console.error('Error getting response counts:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get completed checklist branches with counts
app.get('/api/responses/completed-branches', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                r.branchname,
                COUNT(*) as response_count
            FROM checklist_responses r
            WHERE 
                r.mcq_status = 'yes' 
                AND DATE(r.submitted_at) = CURDATE()
            GROUP BY r.branchname
            ORDER BY r.branchname ASC
        `;
        
        const [rows] = await pool.query(query);
        res.json({ branches: rows });
    } catch (error) {
        console.error('Error getting completed branches:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get completed checklist branches with all their data
app.get('/api/responses/completed-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        
        // Get all completed checklists grouped by branch
        const query = `
            SELECT 
                r.branchname,
                COUNT(*) as total_responses,
                MAX(DATE(r.submitted_at)) as last_submission_date,
                GROUP_CONCAT(DISTINCT DATE(r.submitted_at) ORDER BY r.submitted_at DESC) as submission_dates,
                (
                    SELECT COUNT(*)
                    FROM checklist_responses r2
                    WHERE r2.branchname = r.branchname
                    AND DATE(r2.submitted_at) = CURDATE()
                    AND r2.mcq_status = 'yes'
                ) as today_responses
            FROM checklist_responses r
            WHERE r.mcq_status = 'yes'
            GROUP BY r.branchname
            ORDER BY 
                today_responses DESC,
                last_submission_date DESC,
                r.branchname ASC
        `;
        
        // Get total branches count
        const [totalCount] = await connection.query(
            'SELECT COUNT(DISTINCT branchname) as count FROM employees'
        );
        
        // Get branches that completed today
        const [todayCount] = await connection.query(`
            SELECT COUNT(DISTINCT branchname) as count 
            FROM checklist_responses 
            WHERE DATE(submitted_at) = CURDATE() 
            AND mcq_status = 'yes'
        `);
        
        // Process the data to include submission history
        const [branches] = await connection.query(query);
        const processedBranches = branches.map(branch => ({
            ...branch,
            submission_dates: branch.submission_dates ? branch.submission_dates.split(',') : [],
            has_submitted_today: branch.today_responses > 0
        }));
        
        const stats = {
            total_branches: totalCount[0].count,
            completed_today: todayCount[0].count,
            total_completed: branches.length
        };
        
        res.json({ 
            branches: processedBranches,
            stats: stats
        });
    } catch (error) {
        console.error('Error getting completed branches:', error);
        res.status(500).json({ 
            error: 'Failed to retrieve completed branches',
            details: error.message 
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Get completed checklist branches
app.get('/api/responses/completed-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        
        // Get all branches that have submitted checklists
        const query = `
            SELECT DISTINCT
                r.branchname,
                COUNT(*) as total_submissions,
                MAX(DATE(r.submitted_at)) as last_submission,
                CASE 
                    WHEN EXISTS (
                        SELECT 1 
                        FROM checklist_responses 
                        WHERE branchname = r.branchname 
                        AND DATE(submitted_at) = CURDATE()
                        AND mcq_status = 'yes'
                    ) THEN 1 
                    ELSE 0 
                END as submitted_today
            FROM checklist_responses r
            WHERE r.mcq_status = 'yes'
            GROUP BY r.branchname
            ORDER BY submitted_today DESC, last_submission DESC;
        `;
        
        const [branches] = await connection.query(query);
        console.log('Completed branches:', branches); // Debug log
        
        res.json({ 
            branches: branches.map(branch => ({
                branchname: branch.branchname,
                total_submissions: branch.total_submissions,
                last_submission: branch.last_submission,
                submitted_today: branch.submitted_today === 1
            }))
        });
    } catch (error) {
        console.error('Error getting completed branches:', error);
        res.status(500).json({ 
            error: 'Failed to retrieve completed branches',
            branches: []
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
