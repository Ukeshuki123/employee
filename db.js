const mysql = require('mysql2');

// Create MySQL connection
const db = mysql.createConnection({
    host: 'localhost',         // Replace with your MySQL host
    user: 'root',              // Replace with your MySQL username
    password: 'Uki@12345',              // Replace with your MySQL password
    database: 'employee_db',   // Replace with your database name
});

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('MySQL connection failed: ' + err.message);
        process.exit(1);
    }
    console.log('Connected to MySQL database');
});

module.exports = db;
