<?php
require_once 'db_config.php';

// Verify token from Authorization header
$headers = getallheaders();
$auth = isset($headers['Authorization']) ? $headers['Authorization'] : '';
if (!preg_match('/Bearer\s(\S+)/', $auth, $matches)) {
    echo json_encode(["status" => "error", "message" => "Unauthorized"]);
    exit;
}
$token = $matches[1];
// For demo, just check token exists (in real app, validate against database)
if (empty($token)) {
    echo json_encode(["status" => "error", "message" => "Invalid token"]);
    exit;
}

if (!isset($_GET['id'])) {
    echo json_encode(["status" => "error", "message" => "User ID required"]);
    exit;
}
$id = intval($_GET['id']);

$stmt = $conn->prepare("SELECT id, username, email FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

if ($user = $result->fetch_assoc()) {
    echo json_encode(["status" => "success", "user" => $user]);
} else {
    echo json_encode(["status" => "error", "message" => "User not found"]);
}
$stmt->close();
$conn->close();
