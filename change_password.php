<?php
require_once 'db_config.php';

$headers = getallheaders();
$auth = isset($headers['Authorization']) ? $headers['Authorization'] : '';
if (!preg_match('/Bearer\s(\S+)/', $auth, $matches)) {
    echo json_encode(["status" => "error", "message" => "Unauthorized"]);
    exit;
}

$data = json_decode(file_get_contents("php://input"), true);
if (!isset($data['id']) || !isset($data['current_password']) || !isset($data['new_password'])) {
    echo json_encode(["status" => "error", "message" => "Missing fields"]);
    exit;
}

$id = intval($data['id']);
$current = $data['current_password'];
$new = $data['new_password'];

// Fetch current hashed password
$stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

if (!$user || !password_verify($current, $user['password'])) {
    echo json_encode(["status" => "error", "message" => "Current password is incorrect"]);
    exit;
}

$newHash = password_hash($new, PASSWORD_DEFAULT);
$update = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
$update->bind_param("si", $newHash, $id);
if ($update->execute()) {
    echo json_encode(["status" => "success", "message" => "Password changed"]);
} else {
    echo json_encode(["status" => "error", "message" => "Failed to update password"]);
}
$update->close();
$conn->close();
