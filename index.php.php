<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Database Configuration
$host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'chat_app';

// Connect to MySQL
$conn = new mysqli($host 		sql208.infinityfree.com, $db_user 		if0_39876790, $db_pass SaMiShAh123, $db_name 	if0_39876790_sami);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Global variables
$user_id = $_SESSION['user_id'] ?? null;
$error = '';
$success = '';
$page = $_GET['page'] ?? 'home';

// --- Functions ---

function sanitize($input) {
    global $conn;
    return $conn->real_escape_string(htmlspecialchars($input));
}

function hash_password($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

function verify_password($password, $hash) {
    return password_verify($password, $hash);
}

function get_user_by_email($email) {
    global $conn;
    $email = sanitize($email);
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result->fetch_assoc();
}

function get_user_by_id($id) {
    global $conn;
    $id = sanitize($id);
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result->fetch_assoc();
}

function get_friends($user_id) {
    global $conn;
    $friends = [];
    $stmt = $conn->prepare("SELECT u.id, u.name FROM friends f JOIN users u ON f.friend_id = u.id WHERE f.user_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $friends[] = $row;
    }
    return $friends;
}

function get_messages($sender_id, $receiver_id) {
    global $conn;
    $messages = [];
    $stmt = $conn->prepare("
        SELECT * FROM messages 
        WHERE (sender_id = ? AND receiver_id = ?) 
        OR (sender_id = ? AND receiver_id = ?) 
        ORDER BY timestamp ASC
    ");
    $stmt->bind_param("iiii", $sender_id, $receiver_id, $receiver_id, $sender_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $messages[] = $row;
    }
    return $messages;
}

function add_friend_by_email($user_id, $friend_email) {
    global $conn;
    $friend = get_user_by_email($friend_email);
    if (!$friend) {
        return ['status' => 'error', 'message' => 'User not found.'];
    }
    if ($friend['id'] == $user_id) {
        return ['status' => 'error', 'message' => 'You cannot add yourself.'];
    }

    $stmt = $conn->prepare("SELECT * FROM friends WHERE user_id = ? AND friend_id = ?");
    $stmt->bind_param("ii", $user_id, $friend['id']);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        return ['status' => 'error', 'message' => 'User is already your friend.'];
    }

    $conn->begin_transaction();
    try {
        $stmt_add_1 = $conn->prepare("INSERT INTO friends (user_id, friend_id) VALUES (?, ?)");
        $stmt_add_1->bind_param("ii", $user_id, $friend['id']);
        $stmt_add_1->execute();
        
        $stmt_add_2 = $conn->prepare("INSERT INTO friends (user_id, friend_id) VALUES (?, ?)");
        $stmt_add_2->bind_param("ii", $friend['id'], $user_id);
        $stmt_add_2->execute();
        
        $conn->commit();
        return ['status' => 'success', 'message' => 'Friend added successfully!'];
    } catch (mysqli_sql_exception $exception) {
        $conn->rollback();
        return ['status' => 'error', 'message' => 'Failed to add friend.'];
    }
}

// --- Action Handlers ---

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action']) && $_POST['action'] === 'login') {
        $email = sanitize($_POST['email']);
        $password = sanitize($_POST['password']);

        $user = get_user_by_email($email);
        if ($user && verify_password($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            header("Location: " . $_SERVER['PHP_SELF']);
            exit();
        } else {
            $error = 'Invalid email or password.';
        }
    }

    if (isset($_POST['action']) && $_POST['action'] === 'signup') {
        $name = sanitize($_POST['name']);
        $email = sanitize($_POST['email']);
        $password = sanitize($_POST['password']);
        $hashed_password = hash_password($password);

        if (get_user_by_email($email)) {
            $error = 'Email already exists. Please login.';
        } else {
            $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $name, $email, $hashed_password);
            if ($stmt->execute()) {
                $success = 'Account created successfully! You can now log in.';
            } else {
                $error = 'Registration failed. Please try again.';
            }
        }
    }

    if (isset($_POST['action']) && $_POST['action'] === 'add_friend' && $user_id) {
        $friend_email = sanitize($_POST['friend_email']);
        $result = add_friend_by_email($user_id, $friend_email);
        if ($result['status'] === 'success') {
            $success = $result['message'];
        } else {
            $error = $result['message'];
        }
    }

    if (isset($_POST['action']) && $_POST['action'] === 'send_message' && $user_id) {
        $receiver_id = sanitize($_POST['receiver_id']);
        $message = sanitize($_POST['message']);

        if (!empty($message)) {
            $stmt = $conn->prepare("INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)");
            $stmt->bind_param("iis", $user_id, $receiver_id, $message);
            $stmt->execute();
            // This is a simplified approach. In a real app, use AJAX for real-time updates.
        }
    }
}

if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

if (isset($_GET['action']) && $_GET['action'] === 'get_messages' && $user_id) {
    header('Content-Type: application/json');
    $receiver_id = sanitize($_GET['receiver_id']);
    $messages = get_messages($user_id, $receiver_id);
    $formatted_messages = [];
    foreach ($messages as $msg) {
        $formatted_messages[] = [
            'sender_name' => $msg['sender_id'] == $user_id ? 'You' : get_user_by_id($msg['sender_id'])['name'],
            'message' => $msg['message'],
            'is_me' => $msg['sender_id'] == $user_id,
            'timestamp' => date('h:i A', strtotime($msg['timestamp']))
        ];
    }
    echo json_encode($formatted_messages);
    exit;
}

// --- View Logic ---

$current_user = $user_id ? get_user_by_id($user_id) : null;
$friends = $user_id ? get_friends($user_id) : [];

?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PHP Chat App</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .chat-container {
            height: 100vh;
            display: flex;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .sidebar {
            width: 300px;
            border-right: 1px solid #dee2e6;
            display: flex;
            flex-direction: column;
        }
        .sidebar-header {
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
        }
        .sidebar-friends {
            flex-grow: 1;
            overflow-y: auto;
        }
        .friend-item {
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        .friend-item:hover {
            background-color: #e9ecef;
        }
        .chat-main {
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            position: relative;
        }
        .chat-header {
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            align-items: center;
        }
        .chat-body {
            flex-grow: 1;
            padding: 20px;
            overflow-y: auto;
            background-color: #e5ddd5;
        }
        .message-bubble {
            padding: 8px 12px;
            border-radius: 15px;
            margin-bottom: 10px;
            max-width: 75%;
            word-wrap: break-word;
        }
        .message-me {
            background-color: #dcf8c6;
            align-self: flex-end;
            margin-left: auto;
        }
        .message-other {
            background-color: #fff;
            align-self: flex-start;
            margin-right: auto;
        }
        .chat-input {
            padding: 15px;
            border-top: 1px solid #dee2e6;
        }
        .empty-chat {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 100%;
            text-align: center;
        }
        @media (max-width: 768px) {
            .chat-container {
                flex-direction: column;
            }
            .sidebar {
                width: 100%;
                height: 50vh;
                border-right: none;
                border-bottom: 1px solid #dee2e6;
            }
        }
    </style>
</head>
<body>

<?php if (!$user_id): ?>

<div class="d-flex align-items-center justify-content-center vh-100 bg-light">
    <div class="card shadow-sm" style="width: 400px;">
        <div class="card-header bg-primary text-white text-center">
            <h3>PHP Chat App</h3>
        </div>
        <div class="card-body">
            <?php if ($error): ?>
                <div class="alert alert-danger"><?= $error ?></div>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="alert alert-success"><?= $success ?></div>
            <?php endif; ?>

            <ul class="nav nav-tabs nav-fill mb-3" id="myTab" role="tablist">
                <li class="nav-item">
                    <button class="nav-link active" id="login-tab" data-bs-toggle="tab" data-bs-target="#login" type="button">Login</button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" id="signup-tab" data-bs-toggle="tab" data-bs-target="#signup" type="button">Sign Up</button>
                </li>
            </ul>
            <div class="tab-content">
                <div class="tab-pane fade show active" id="login" role="tabpanel">
                    <form method="POST">
                        <input type="hidden" name="action" value="login">
                        <div class="mb-3">
                            <label for="loginEmail" class="form-label">Email address</label>
                            <input type="email" class="form-control" id="loginEmail" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="loginPassword" class="form-label">Password</label>
                            <input type="password" class="form-control" id="loginPassword" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                </div>
                <div class="tab-pane fade" id="signup" role="tabpanel">
                    <form method="POST">
                        <input type="hidden" name="action" value="signup">
                        <div class="mb-3">
                            <label for="signupName" class="form-label">Name</label>
                            <input type="text" class="form-control" id="signupName" name="name" required>
                        </div>
                        <div class="mb-3">
                            <label for="signupEmail" class="form-label">Email address</label>
                            <input type="email" class="form-control" id="signupEmail" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="signupPassword" class="form-label">Password</label>
                            <input type="password" class="form-control" id="signupPassword" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-success w-100">Sign Up</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<?php else: ?>

<div class="chat-container">
    <div class="sidebar">
        <div class="sidebar-header d-flex justify-content-between align-items-center">
            <h5><?= htmlspecialchars($current_user['name']) ?></h5>
            <div>
                <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#addFriendModal">
                    <i class="fas fa-user-plus"></i>
                </button>
                <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#inviteModal">
                    <i class="fas fa-share-alt"></i>
                </button>
                <a href="?action=logout" class="btn btn-sm btn-outline-danger">
                    <i class="fas fa-sign-out-alt"></i>
                </a>
            </div>
        </div>
        <div class="sidebar-friends">
            <?php if (empty($friends)): ?>
                <div class="p-3 text-center text-muted">No friends yet. Add one to start chatting!</div>
            <?php else: ?>
                <?php foreach ($friends as $friend): ?>
                    <div class="friend-item" data-id="<?= $friend['id'] ?>" data-name="<?= htmlspecialchars($friend['name']) ?>">
                        <?= htmlspecialchars($friend['name']) ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <div class="chat-main" id="chatMain">
        <div class="empty-chat">
            <i class="fas fa-comment-dots" style="font-size: 80px; color: #ccc;"></i>
            <h4 class="mt-3 text-muted">Select a friend to start chatting!</h4>
        </div>
        </div>
</div>

<div class="modal fade" id="addFriendModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Add a Friend</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="add_friend">
                <div class="modal-body">
                    <?php if ($error && strpos($error, 'Friend') !== false): ?>
                        <div class="alert alert-danger"><?= $error ?></div>
                    <?php endif; ?>
                    <?php if ($success && strpos($success, 'Friend') !== false): ?>
                        <div class="alert alert-success"><?= $success ?></div>
                    <?php endif; ?>
                    <div class="mb-3">
                        <label for="friendEmail" class="form-label">Friend's Email address</label>
                        <input type="email" class="form-control" id="friendEmail" name="friend_email" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="submit" class="btn btn-primary">Add Friend</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="inviteModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Share & Invite</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <p>Share this link to invite others to join:</p>
                <div class="input-group mb-3">
                    <input type="text" class="form-control" value="<?= $_SERVER['PHP_SELF'] ?>" id="inviteLink" readonly>
                    <button class="btn btn-outline-secondary" type="button" onclick="copyLink()">Copy</button>
                </div>
                <p class="text-muted">Or invite a friend by their email:</p>
                <form id="inviteForm">
                    <div class="mb-3">
                        <input type="email" class="form-control" placeholder="friend@example.com" id="inviteEmail" required>
                    </div>
                    <button type="button" class="btn btn-primary w-100" onclick="sendInvite()">Send Invite</button>
                </form>
            </div>
        </div>
    </div>
</div>

<?php endif; ?>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        const chatMain = document.getElementById('chatMain');
        const friendsList = document.querySelector('.sidebar-friends');
        let currentChatId = null;
        let fetchInterval = null;

        function renderChatWindow(friendId, friendName) {
            currentChatId = friendId;
            chatMain.innerHTML = `
                <div class="chat-header">
                    <img src="https://via.placeholder.com/40" class="rounded-circle me-3">
                    <h4>${friendName}</h4>
                </div>
                <div class="chat-body d-flex flex-column" id="chatBody">
                    </div>
                <div class="chat-input">
                    <form id="messageForm" class="d-flex">
                        <input type="hidden" name="action" value="send_message">
                        <input type="hidden" name="receiver_id" value="${friendId}">
                        <input type="text" class="form-control me-2" name="message" placeholder="Type a message..." required>
                        <button type="submit" class="btn btn-primary"><i class="fas fa-paper-plane"></i></button>
                    </form>
                </div>
            `;
            
            const messageForm = document.getElementById('messageForm');
            messageForm.addEventListener('submit', function(e) {
                e.preventDefault();
                const formData = new FormData(this);
                fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                }).then(response => {
                    if (response.ok) {
                        this.querySelector('input[name="message"]').value = '';
                        fetchMessages(currentChatId);
                    }
                });
            });

            fetchMessages(friendId);
            if (fetchInterval) clearInterval(fetchInterval);
            fetchInterval = setInterval(() => fetchMessages(friendId), 3000);
        }

        function fetchMessages(receiverId) {
            fetch(`?action=get_messages&receiver_id=${receiverId}`)
                .then(response => response.json())
                .then(messages => {
                    const chatBody = document.getElementById('chatBody');
                    if (!chatBody) return;
                    chatBody.innerHTML = '';
                    messages.forEach(msg => {
                        const bubble = document.createElement('div');
                        bubble.className = `message-bubble ${msg.is_me ? 'message-me' : 'message-other'}`;
                        bubble.innerHTML = `
                            <p class="mb-0">${msg.message}</p>
                            <small class="text-muted" style="font-size: 0.75em;">${msg.timestamp}</small>
                        `;
                        chatBody.appendChild(bubble);
                    });
                    chatBody.scrollTop = chatBody.scrollHeight;
                });
        }

        if (friendsList) {
            friendsList.addEventListener('click', function(e) {
                const friendItem = e.target.closest('.friend-item');
                if (friendItem) {
                    const friendId = friendItem.dataset.id;
                    const friendName = friendItem.dataset.name;
                    renderChatWindow(friendId, friendName);
                    
                    document.querySelectorAll('.friend-item').forEach(item => item.classList.remove('active'));
                    friendItem.classList.add('active');
                }
            });
        }

        function copyLink() {
            const inviteLink = document.getElementById('inviteLink');
            inviteLink.select();
            document.execCommand('copy');
            alert('Invite link copied to clipboard!');
        }

        function sendInvite() {
            const email = document.getElementById('inviteEmail').value;
            if (email) {
                alert(`Simulated: Invite sent to ${email}!`);
                document.getElementById('inviteForm').reset();
            }
        }
    });
</script>

</body>
</html>