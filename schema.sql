DROP DATABASE IF EXISTS employee_db;
CREATE DATABASE employee_db;
USE employee_db;

-- Create employees table
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'management', 'user') NOT NULL DEFAULT 'user',
    branchname VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create checklist_questions table
CREATE TABLE checklist_questions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    section ENUM('Kitchen', 'Cafe') NOT NULL,
    question_text TEXT NOT NULL,
    question_type ENUM('mcq', 'written') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create checklist_responses table
CREATE TABLE checklist_responses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    question_id INT NOT NULL,
    answer_text TEXT,
    mcq_status ENUM('yes', 'no', 'pending') DEFAULT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (employee_id) REFERENCES employees(id),
    FOREIGN KEY (question_id) REFERENCES checklist_questions(id)
);

-- Insert default admin user (password: admin123)
INSERT INTO employees (username, password, role, branchname) VALUES 
('admin', '$2b$10$vKYDZWvqZzTX4ZZtPDVcEOEp8mHK9s6B3/jQn0YR1ePTDVoKiHNGi', 'admin', 'Head Office');

-- Insert management user (password: user123)
INSERT INTO employees (username, password, role, branchname) VALUES 
('manager', '$2b$10$vKYDZWvqZzTX4ZZtPDVcEOEp8mHK9s6B3/jQn0YR1ePTDVoKiHNGi', 'management', 'Branch A');

-- Insert regular users (password: user123)
INSERT INTO employees (username, password, role, branchname) VALUES 
('john', '$2b$10$vKYDZWvqZzTX4ZZtPDVcEOEp8mHK9s6B3/jQn0YR1ePTDVoKiHNGi', 'user', 'Branch A'),
('jane', '$2b$10$vKYDZWvqZzTX4ZZtPDVcEOEp8mHK9s6B3/jQn0YR1ePTDVoKiHNGi', 'user', 'Branch B');

-- Insert Kitchen Questions
INSERT INTO checklist_questions (section, question_text, question_type) VALUES
('Kitchen', 'What is the current refrigerator temperature reading?', 'written'),
('Kitchen', 'List any kitchen equipment that needs maintenance:', 'written'),
('Kitchen', 'Have all cooking surfaces been cleaned and sanitized?', 'mcq'),
('Kitchen', 'Is the food storage area properly organized?', 'mcq'),
('Kitchen', 'Are all safety equipment and fire extinguishers in place?', 'mcq');

-- Insert Cafe Questions
INSERT INTO checklist_questions (section, question_text, question_type) VALUES
('Cafe', 'What is the current coffee machine temperature setting?', 'written'),
('Cafe', 'List items that need immediate restocking:', 'written'),
('Cafe', 'Have all serving areas been sanitized?', 'mcq'),
('Cafe', 'Are all tables and chairs properly arranged?', 'mcq'),
('Cafe', 'Is the display case at the correct temperature?', 'mcq');
