-- Use the employee database
USE employee_db;
GO

-- Insert sample employees
INSERT INTO employees (username, branchname, password) VALUES
    (N'john.doe', N'Main Branch', N'password123'),
    (N'jane.smith', N'North Branch', N'password456'),
    (N'bob.wilson', N'South Branch', N'password789'),
    (N'alice.jones', N'Main Branch', N'passwordabc'),
    (N'charlie.brown', N'North Branch', N'passworddef'),
    (N'diana.prince', N'South Branch', N'passwordxyz'),
    (N'bruce.wayne', N'Main Branch', N'password321'),
    (N'peter.parker', N'North Branch', N'password654'),
    (N'tony.stark', N'South Branch', N'password987');
GO

-- Assign admin role to first employee
INSERT INTO employee_roles (employee_id, role_id)
SELECT e.id, r.id
FROM employees e
INNER JOIN roles r ON r.name = 'admin'
WHERE e.username = 'john.doe';
GO

-- Assign manager role to some employees
INSERT INTO employee_roles (employee_id, role_id)
SELECT e.id, r.id
FROM employees e
INNER JOIN roles r ON r.name = 'manager'
WHERE e.username IN ('jane.smith', 'bob.wilson', 'alice.jones');
GO

-- Assign employee role to all employees
INSERT INTO employee_roles (employee_id, role_id)
SELECT e.id, r.id
FROM employees e
CROSS JOIN roles r
WHERE r.name = 'employee'
AND NOT EXISTS (
    SELECT 1 
    FROM employee_roles er 
    WHERE er.employee_id = e.id 
    AND er.role_id = r.id
);
GO

-- Create view for employee details
IF EXISTS (SELECT * FROM sys.views WHERE name = 'employee_details')
    DROP VIEW employee_details;
GO

CREATE VIEW employee_details AS
SELECT 
    e.id,
    e.username,
    e.branchname,
    b.location as branch_location,
    STUFF((
        SELECT ', ' + r.name
        FROM employee_roles er
        JOIN roles r ON er.role_id = r.id
        WHERE er.employee_id = e.id
        FOR XML PATH('')
    ), 1, 2, '') as roles,
    e.created_at,
    e.updated_at
FROM employees e
LEFT JOIN branches b ON e.branchname = b.name;
GO

-- Sample queries

-- 1. Get all employees with their roles
SELECT * FROM employee_details;
GO

-- 2. Get employees by branch
SELECT * FROM employee_details WHERE branchname = N'Main Branch';
GO

-- 3. Find all managers
SELECT * FROM employee_details WHERE roles LIKE N'%manager%';
GO

-- 4. Find employees created in the last 24 hours
SELECT * FROM employee_details 
WHERE created_at >= DATEADD(day, -1, GETDATE());
GO

-- 5. Count employees by branch
SELECT 
    branchname,
    COUNT(*) as employee_count
FROM employees
GROUP BY branchname
ORDER BY employee_count DESC;
GO

-- 6. Count employees by role
SELECT 
    r.name as role_name,
    COUNT(er.employee_id) as employee_count
FROM roles r
LEFT JOIN employee_roles er ON r.id = er.role_id
GROUP BY r.name
ORDER BY employee_count DESC;
GO
