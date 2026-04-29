<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

include 'db_config.php';
// ... rest of your existing login logic
require_once 'db_config.php';

$data = json_decode(file_get_contents("php://input"), true);

$required = ['username', 'email', 'password', 'confirm_password'];
foreach ($required as $field) {
    if (!isset($data[$field])) {
        echo json_encode(["status" => "error", "message" => "Missing field: $field"]);
        exit;
    }
}

$username = $data['username'];
$email = $data['email'];
$password = $data['password'];
$confirm = $data['confirm_password'];

if ($password !== $confirm) {
    echo json_encode(["status" => "error", "message" => "Passwords do not match"]);
    exit;
}

$hashed = password_hash($password, PASSWORD_DEFAULT);

$stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
$stmt->bind_param("sss", $username, $email, $hashed);

if ($stmt->execute()) {
    echo json_encode(["status" => "success", "message" => "User registered successfully"]);
} else {
    // Duplicate email or other error
    echo json_encode(["status" => "error", "message" => "Email already exists or registration failed"]);
}

$stmt->close();
$conn->close();
