const mysql = require('mysql2/promise');

const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: 'Uki@12345',
    database: 'employee_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

async function createTable() {
    const pool = mysql.createPool(dbConfig);
    
    try {
        const createTableQuery = `
        CREATE TABLE IF NOT EXISTS checklist_responses (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_id INT NOT NULL,
            username VARCHAR(100) NOT NULL,
            branchname VARCHAR(100) NOT NULL,
            question_id INT NOT NULL,
            question_text TEXT NOT NULL,
            question_type ENUM('mcq', 'text') NOT NULL,
            mcq_status ENUM('yes', 'no', 'pending'),
            answer_text TEXT,
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
            FOREIGN KEY (question_id) REFERENCES checklist_questions(id) ON DELETE CASCADE,
            INDEX idx_employee (employee_id),
            INDEX idx_question (question_id),
            INDEX idx_submitted_at (submitted_at),
            INDEX idx_branch (branchname)
        )`;

        await pool.query(createTableQuery);
        console.log('checklist_responses table created successfully');
    } catch (error) {
        console.error('Error creating table:', error);
    } finally {
        await pool.end();
    }
}

createTable();
