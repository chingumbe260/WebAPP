<?php
require_once 'db_config.php';

$headers = getallheaders();
$auth = isset($headers['Authorization']) ? $headers['Authorization'] : '';
if (!preg_match('/Bearer\s(\S+)/', $auth, $matches)) {
    echo json_encode(["status" => "error", "message" => "Unauthorized"]);
    exit;
}

$data = json_decode(file_get_contents("php://input"), true);
if (!isset($data['id']) || !isset($data['username']) || !isset($data['email'])) {
    echo json_encode(["status" => "error", "message" => "Missing fields"]);
    exit;
}

$id = intval($data['id']);
$username = $data['username'];
$email = $data['email'];

// Check if email already exists for another user
$check = $conn->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
$check->bind_param("si", $email, $id);
$check->execute();
$check->store_result();
if ($check->num_rows > 0) {
    echo json_encode(["status" => "error", "message" => "Email already in use"]);
    $check->close();
    exit;
}
$check->close();

$stmt = $conn->prepare("UPDATE users SET username = ?, email = ? WHERE id = ?");
$stmt->bind_param("ssi", $username, $email, $id);
if ($stmt->execute()) {
    echo json_encode(["status" => "success", "message" => "Profile updated"]);
} else {
    echo json_encode(["status" => "error", "message" => "Update failed"]);
}
$stmt->close();
$conn->close();
