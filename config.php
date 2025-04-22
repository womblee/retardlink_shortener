<?php

define('DB_HOST', 'localhost');
define('DB_USER', 'username'); // Change to your MySQL username
define('DB_PASS', 'password'); // Change to your MySQL password
define('DB_NAME', 'retard_link');

function getDatabaseConnection()
{
    try {
        $pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", 
            DB_USER, 
            DB_PASS, 
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, // Optional, sets error mode to exception
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC // Optional, sets default fetch mode to associative array
            ]
        );
        return $pdo;
    } catch (PDOException $e) {
        throw new Exception("Database connection failed: " . $e->getMessage());
    }
}

function getEncryptionKey($seed = '7b9e4b2c8f2d6f3a5c5c7d9e2f4a1b8c5d5e7f9a0b2c4d6e8f0a3c4e6b8f0a3') {
    return hash('sha256', $seed, true);
}


?>