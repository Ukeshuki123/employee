const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

async function setupDatabase() {
    // Create connection pool
    const pool = mysql.createPool({
        host: 'localhost',
        user: 'root',
        password: 'Uki@12345',
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });

    try {
        // Create database
        await pool.query('CREATE DATABASE IF NOT EXISTS employee_db');
        await pool.query('USE employee_db');

        // Create employees table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS employees (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'user',
                branchname VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Hash password for test users
        const password = await bcrypt.hash('admin123', 10);

        // Insert test users if they don't exist
        const testUsers = [
            ['admin', password, 'admin', 'Head Office'],
            ['john', password, 'user', 'Branch A'],
            ['jane', password, 'user', 'Branch B']
        ];

        for (const [username, password, role, branchname] of testUsers) {
            try {
                await pool.query(
                    'INSERT INTO employees (username, password, role, branchname) VALUES (?, ?, ?, ?)',
                    [username, password, role, branchname]
                );
                console.log(`User ${username} created successfully`);
            } catch (error) {
                if (error.code === 'ER_DUP_ENTRY') {
                    console.log(`User ${username} already exists`);
                } else {
                    throw error;
                }
            }
        }

        console.log('Database setup completed successfully');
    } catch (error) {
        console.error('Error setting up database:', error);
    } finally {
        await pool.end();
    }
}

setupDatabase();
