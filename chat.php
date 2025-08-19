<?php
session_start();
include 'includes/db_connect.php';

// Check session and redirect if not logged in
if (!isset($_SESSION['user_id'])) {
    error_log("Session user_id not set, redirecting to login");
    header("Location: login.php");
    exit;
}

$user_id = (int)$_SESSION['user_id'];

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    error_log("CSRF Token generated: {$_SESSION['csrf_token']}");
}
$csrf_token = $_SESSION['csrf_token'];

// Helper function for profile pictures
function getProfilePicture($path) {
    $default = 'Uploads/default.jpg';
    $path = trim($path ?? '');
    return (file_exists($path) && !empty($path)) ? htmlspecialchars($path, ENT_QUOTES, 'UTF-8') : htmlspecialchars($default, ENT_QUOTES, 'UTF-8');
}

// Helper function for relative time
function timeAgo($datetime) {
    $timestamp = strtotime($datetime);
    if (!$timestamp) return 'Unknown time';
    $diff = time() - $timestamp;
    if ($diff < 60) return "$diff sec ago";
    if ($diff < 3600) return floor($diff / 60) . " min ago";
    if ($diff < 86400) return floor($diff / 3600) . " hr ago";
    return date('M d, Y H:i', $timestamp);
}

// Helper function for message time
function messageTime($datetime) {
    return date('H:i', strtotime($datetime));
}

// Message variable for feedback
$messages = [];

// Handle connection request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['connect_user_id']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for connection request, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Invalid request. Please try again.</p>";
    } else {
        $connect_user_id = (int)$_POST['connect_user_id'];
        try {
            $pdo->beginTransaction();
            $stmt = $pdo->prepare("SELECT id, first_name, last_name FROM users WHERE id = ?");
            $stmt->execute([$connect_user_id]);
            $connected_user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$connected_user) {
                $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>User not found.</p>";
            } elseif ($connected_user['id'] == $user_id) {
                $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>You cannot connect with yourself.</p>";
            } else {
                $checkStmt = $pdo->prepare("
                    SELECT id, status FROM connections WHERE 
                    (user_id_1 = ? AND user_id_2 = ?) OR 
                    (user_id_1 = ? AND user_id_2 = ?)
                ");
                $checkStmt->execute([$user_id, $connect_user_id, $connect_user_id, $user_id]);
                $existing = $checkStmt->fetch(PDO::FETCH_ASSOC);
                if ($existing) {
                    if ($existing['status'] === 'pending') {
                        $messages[] = "<p class='text-yellow-500 text-center bg-yellow-500/80 p-4 rounded-lg'>A connection request already exists.</p>";
                    } else {
                        $messages[] = "<p class='text-yellow-500 text-center bg-yellow-500/80 p-4 rounded-lg'>You are already connected.</p>";
                    }
                } else {
                    $stmt = $pdo->prepare("
                        INSERT INTO connections (user_id_1, user_id_2, status) 
                        VALUES (?, ?, 'pending')
                    ");
                    $stmt->execute([$user_id, $connect_user_id]);
                    $pdo->commit();
                    $messages[] = "<p class='text-green-500 text-center bg-green-500/80 p-4 rounded-lg'>Connection request sent to " . htmlspecialchars($connected_user['first_name'] . ' ' . $connected_user['last_name'], ENT_QUOTES, 'UTF-8') . "!</p>";
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                }
            }
            header("Location: chat.php" . ($selected_user_id ? "?user=$selected_user_id" : ""));
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log("Connection request error: " . $e->getMessage());
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error sending connection request: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        }
    }
}

// AJAX request for messages
if (isset($_GET['ajax'])) {
    $selected_user_id = filter_var($_GET['user'] ?? 0, FILTER_SANITIZE_NUMBER_INT);
    if ($selected_user_id <= 0) {
        error_log("Invalid selected_user_id for AJAX: $selected_user_id");
        echo '<p class="text-red-500 text-center bg-red-500/80 p-4 rounded-lg">Invalid user ID.</p>';
        exit;
    }
    try {
        $stmt = $pdo->prepare("
            SELECT m.*, u.first_name, u.last_name 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?) 
            ORDER BY m.sent_at
        ");
        $stmt->execute([$user_id, $selected_user_id, $selected_user_id, $user_id]);
        $chat_messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($chat_messages as $message) {
            $class = $message['sender_id'] == $user_id ? 'sent' : 'received';
            echo '<div class="message-bubble mb-3 p-3 ' . $class . '" role="listitem">';
            echo '<p class="text-white text-sm">' . htmlspecialchars($message['content'], ENT_QUOTES, 'UTF-8') . '</p>';
            echo '<div class="flex items-center justify-between">';
            echo '<p class="text-gray-400 text-xs">' . messageTime($message['sent_at']) . '</p>';
            if ($message['sender_id'] == $user_id) {
                echo '<span class="text-gray-400 text-xs"><i class="fas fa-check-double fa-xs"></i></span>';
            }
            echo '</div>';
            echo '</div>';
        }
    } catch (PDOException $e) {
        error_log("AJAX messages fetch error: " . $e->getMessage());
        echo '<p class="text-red-500 text-center bg-red-500/80 p-4 rounded-lg">Error loading messages: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</p>';
    }
    exit;
}

// Fetch connections for chat sidebar
try {
    $stmt = $pdo->prepare("
        SELECT u.id, u.first_name, u.last_name, u.profile_picture, m.content as last_message, m.sent_at as last_message_time,
               (SELECT COUNT(*) FROM messages m2 WHERE m2.sender_id = u.id AND m2.sent_at > NOW() - INTERVAL 5 MINUTE) as is_online
        FROM users u
        LEFT JOIN messages m ON m.id = (
            SELECT MAX(id)
            FROM messages
            WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id)
        )
        WHERE u.id IN (
            SELECT user_id_2 FROM connections WHERE user_id_1 = ? AND status = 'accepted'
            UNION
            SELECT user_id_1 FROM connections WHERE user_id_2 = ? AND status = 'accepted'
        )
        ORDER BY m.sent_at DESC
    ");
    $stmt->execute([$user_id, $user_id, $user_id, $user_id]);
    $connections = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Connections fetch error: " . $e->getMessage());
    $connections = [];
    $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error loading connections: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}

// Handle message sending
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['receiver_id']) && isset($_POST['content']) && isset($_POST['csrf_token']) && !isset($_POST['connect_user_id'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for message sending, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Invalid request. Please try again.</p>";
    } else {
        $receiver_id = filter_var($_POST['receiver_id'], FILTER_SANITIZE_NUMBER_INT);
        $content = filter_var(trim($_POST['content']), FILTER_SANITIZE_STRING);
        if (empty($content)) {
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Message content cannot be empty.</p>";
        } elseif ($receiver_id <= 0) {
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Invalid recipient.</p>";
        } else {
            try {
                $stmt = $pdo->prepare("INSERT INTO messages (sender_id, receiver_id, content, sent_at) VALUES (?, ?, ?, NOW())");
                $stmt->execute([$user_id, $receiver_id, $content]);
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                header("Location: chat.php?user=" . $receiver_id);
                exit;
            } catch (PDOException $e) {
                error_log("Message insert error: " . $e->getMessage());
                $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error sending message: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
            }
        }
    }
}

// Fetch messages for selected user
$selected_user_id = isset($_GET['user']) ? filter_var($_GET['user'], FILTER_SANITIZE_NUMBER_INT) : null;
$chat_messages = [];
$selected_user = null;
if ($selected_user_id) {
    try {
        $stmt = $pdo->prepare("
            SELECT m.*, u.first_name, u.last_name, u.profile_picture 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?) 
            ORDER BY m.sent_at
        ");
        $stmt->execute([$user_id, $selected_user_id, $selected_user_id, $user_id]);
        $chat_messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $stmt = $pdo->prepare("SELECT first_name, last_name, profile_picture FROM users WHERE id = ?");
        $stmt->execute([$selected_user_id]);
        $selected_user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$selected_user) {
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Selected user not found.</p>";
            $selected_user_id = null;
        }
    } catch (PDOException $e) {
        error_log("Messages fetch error: " . $e->getMessage());
        $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error loading messages: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
    }
}

// Fetch user profile data
try {
    $stmt = $pdo->prepare("SELECT first_name, last_name, headline, profile_picture FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        error_log("User ID $user_id not found in users table, logging out");
        session_destroy();
        header("Location: login.php");
        exit;
    }
    $_SESSION['first_name'] = $_SESSION['first_name'] ?? $user['first_name'];
    $_SESSION['last_name'] = $_SESSION['last_name'] ?? $user['last_name'];
    $_SESSION['headline'] = $_SESSION['headline'] ?? $user['headline'] ?? '';
    $_SESSION['profile_picture'] = $_SESSION['profile_picture'] ?? $user['profile_picture'] ?? 'Uploads/default.jpg';
} catch (PDOException $e) {
    error_log("User validation error: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error validating user: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Messages - LinkedIn Clone</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" />
    <style>
        /* Reset default styles and set solid background */
        html, body {
            margin: 0;
            padding: 0;
            background-color: #1f2937 !important;
            color: #ffffff;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            min-height: 100vh;
        }

        * {
            box-sizing: border-box;
        }

        /* Card styles */
        .card {
            background: linear-gradient(to bottom, #374151, #1f2937);
            color: white;
            border-radius: 1rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            padding: 1.5rem;
            border: 2px solid #4b5563;
            transition: transform 0.2s ease;
        }
        .card:hover {
            transform: scale(1.02);
        }

        /* Button styles */
        .btn-primary {
            background: #1e3a8a;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 9999px;
            display: inline-flex;
            align-items: center;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 500;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .btn-primary:hover {
            background: #1e40af;
            transform: scale(1.05);
        }

        /* Message bubble styles */
        .message-bubble {
            border-radius: 0.75rem;
            transition: background-color 0.3s;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        }
        .message-bubble.sent {
            margin-left: 20%;
            background: #1e3a8a;
            border-radius: 12px 12px 0 12px;
            max-width: 70%;
        }
        .message-bubble.received {
            margin-right: 20%;
            background: #4b5563;
            border-radius: 12px 12px 12px 0;
            max-width: 70%;
        }

        /* Chat sidebar */
        .chat-sidebar {
            background: linear-gradient(to bottom, #374151, #1f2937);
            border-right: 2px solid #4b5563;
        }

        /* Chat area */
        .chat-area {
            background: linear-gradient(to bottom, #374151, #1f2937);
        }

        /* Typography */
        h2 {
            font-family: serif;
            font-size: 1.5rem;
            font-weight: 700;
            letter-spacing: -0.025em;
        }
        h3 {
            font-family: serif;
            font-size: 1.25rem;
            font-weight: 600;
        }

        /* Animations */
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        /* Layout */
        .chat-container {
            margin-top: 64px;
            min-height: calc(100vh - 64px);
        }
        .navbar {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 1000;
            background: linear-gradient(to bottom, #374151, #1f2937);
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
            height: 64px;
        }
        #chatBox {
            background: #17253c;
            border-radius: 0.5rem;
        }
        .profile-img {
            object-fit: cover;
            border: 2px solid #4b5563;
        }

        /* Responsive design */
        @media (max-width: 768px) {
            html, body {
                background-color: #1f2937 !important;
            }
            .message-bubble.sent, .message-bubble.received {
                max-width: 80%;
            }
            .chat-sidebar {
                width: 100%;
                max-height: 40vh;
                overflow-y: auto;
            }
            .chat-area {
                width: 100%;
            }
            .chat-container {
                margin-top: 80px;
            }
            .navbar {
                height: 80px;
            }
            .profile-img {
                width: 36px;
                height: 36px;
            }
            .btn-primary {
                padding: 0.5rem 1rem;
                font-size: 0.875rem;
            }
            .card {
                padding: 1rem;
            }
        }
    </style>
</head>
<body class="antialiased">
    <!-- Navbar -->
    <nav class="navbar">
        <?php 
        try {
            include 'includes/header.php'; 
        } catch (Exception $e) {
            error_log("Error including header.php: " . $e->getMessage());
            echo '<p class="text-red-500 text-center bg-red-500/80 p-4 rounded-lg">Error loading header: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</p>';
        }
        ?>
    </nav>

    <!-- Main Content -->
    <div class="chat-container max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <!-- Main Content (Chat) -->
        <div class="w-full">
            <?php if (!empty($messages)): ?>
                <div class="mb-8">
                    <?php foreach ($messages as $msg): ?>
                        <div class="card p-4 mb-4 animate__animated animate__fadeIn"><?php echo $msg; ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <div class="card animate__animated animate__fadeIn flex flex-col md:flex-row h-[calc(100vh-96px)]" role="main">
                <!-- Chat Sidebar -->
                <div class="w-full md:w-1/3 chat-sidebar md:border-r border-gray-600">
                    <h2 class="text-lg font-semibold p-4 border-b border-gray-600">Conversations</h2>
                    <?php if (empty($connections)): ?>
                        <p class="text-gray-200 text-sm p-4">No connections to message.</p>
                    <?php else: ?>
                        <div role="list">
                            <?php foreach ($connections as $connection): ?>
                                <a href="chat.php?user=<?php echo (int)$connection['id']; ?>" class="flex items-center p-4 hover:bg-gray-600 <?php echo $selected_user_id == $connection['id'] ? 'bg-gray-600' : ''; ?>" role="listitem" aria-label="Chat with <?php echo htmlspecialchars($connection['first_name'] . ' ' . $connection['last_name'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <div class="relative">
                                        <img src="<?php echo getProfilePicture($connection['profile_picture']); ?>" class="w-12 h-12 rounded-full mr-4 profile-img" alt="Profile Picture" onerror="this.src='Uploads/default.jpg'; console.error('Failed to load profile picture for user <?php echo (int)$connection['id']; ?>');">
                                        <?php if ($connection['is_online']): ?>
                                            <span class="absolute bottom-0 right-0 w-3 h-3 bg-green-500 rounded-full border-2 border-gray-600" title="Online"></span>
                                        <?php endif; ?>
                                    </div>
                                    <div class="flex-1">
                                        <p class="font-medium text-gray-200"><?php echo htmlspecialchars($connection['first_name'] . ' ' . $connection['last_name'], ENT_QUOTES, 'UTF-8'); ?></p>
                                        <?php if ($connection['last_message']): ?>
                                            <p class="text-gray-400 text-sm truncate"><?php echo htmlspecialchars(substr($connection['last_message'], 0, 30) . (strlen($connection['last_message']) > 30 ? '...' : ''), ENT_QUOTES, 'UTF-8'); ?></p>
                                        <?php endif; ?>
                                    </div>
                                    <?php if ($connection['last_message_time']): ?>
                                        <p class="text-gray-400 text-sm"><?php echo timeAgo($connection['last_message_time']); ?></p>
                                    <?php endif; ?>
                                </a>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
                <!-- Chat Area -->
                <div class="w-full md:w-2/3 chat-area flex flex-col">
                    <?php if ($selected_user_id && $selected_user): ?>
                        <div class="p-4 border-b border-gray-600 flex items-center">
                            <img src="<?php echo getProfilePicture($selected_user['profile_picture']); ?>" class="w-12 h-12 rounded-full mr-3 profile-img" alt="Selected User Profile Picture" onerror="this.src='Uploads/default.jpg'; console.error('Failed to load selected user profile picture');">
                            <h3 class="text-base font-medium text-white"><?php echo htmlspecialchars($selected_user['first_name'] . ' ' . $selected_user['last_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                        </div>
                        <div class="flex-1 p-4 overflow-y-auto" id="chatBox" role="list" aria-live="polite">
                            <?php foreach ($chat_messages as $message): ?>
                                <div class="message-bubble mb-4 p-3 <?php echo $message['sender_id'] == $user_id ? 'sent' : 'received'; ?> animate__animated animate__fadeIn" role="listitem">
                                    <p class="text-white text-sm"><?php echo htmlspecialchars($message['content'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <div class="flex items-center justify-between mt-1">
                                        <p class="text-gray-400 text-xs"><?php echo messageTime($message['sent_at']); ?></p>
                                        <?php if ($message['sender_id'] == $user_id): ?>
                                            <span class="text-gray-400 text-xs"><i class="fas fa-check-double fa-xs"></i></span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <form method="POST" class="p-4 border-t border-gray-600" id="message-form">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="hidden" name="receiver_id" value="<?php echo (int)$selected_user_id; ?>">
                            <div class="flex items-center gap-3">
                                <textarea name="content" class="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-gray-700 text-white text-sm resize-none" placeholder="Type a message..." rows="3" required aria-label="Message input"></textarea>
                                <button type="submit" class="btn-primary relative px-5 py-3" aria-label="Send message">
                                    <i class="fas fa-paper-plane mr-2"></i>
                                    <span id="send-button-text">Send</span>
                                    <svg id="send-spinner" class="hidden animate-spin h-5 w-5 text-white absolute right-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                </button>
                            </div>
                        </form>
                    <?php else: ?>
                        <div class="flex-1 flex items-center justify-center">
                            <p class="text-gray-200 text-sm">Select a conversation to start messaging.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <?php 
    try {
        include 'includes/footer.php'; 
    } catch (Exception $e) {
        error_log("Error including footer.php: " . $e->getMessage());
        echo '<p class="text-red-500 text-center bg-red-500/80 p-4 rounded-lg">Error loading footer: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</p>';
    }
    ?>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            try {
                // Smooth scroll to bottom of chat box
                const chatBox = document.getElementById('chatBox');
                if (chatBox && <?php echo json_encode($selected_user_id); ?>) {
                    chatBox.scrollTop = chatBox.scrollHeight;
                    console.log('Chat box scrolled to bottom');

                    // AJAX for real-time message updates
                    setInterval(() => {
                        try {
                            const userId = <?php echo json_encode((int)$selected_user_id); ?>;
                            if (!userId) {
                                console.warn('No selected user ID for AJAX polling');
                                return;
                            }
                            fetch(`chat.php?ajax=true&user=${userId}`, {
                                headers: { 'X-Requested-With': 'XMLHttpRequest' }
                            })
                                .then(response => {
                                    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                                    return response.text();
                                })
                                .then(data => {
                                    chatBox.innerHTML = data;
                                    chatBox.scrollTop = chatBox.scrollHeight;
                                    console.log('Messages updated via AJAX');
                                })
                                .catch(error => {
                                    console.error('Error fetching messages:', error);
                                    chatBox.innerHTML += '<p class="text-red-500 text-center bg-red-500/80 p-4 rounded-lg">Failed to load messages: ' + error.message + '</p>';
                                });
                        } catch (e) {
                            console.error('AJAX interval error:', e);
                        }
                    }, 5000);
                } else {
                    console.log('No chat box or selected user, skipping AJAX');
                }

                // Loading spinner for message form
                const messageForm = document.getElementById('message-form');
                if (messageForm) {
                    messageForm.addEventListener('submit', () => {
                        try {
                            const buttonText = document.getElementById('send-button-text');
                            const spinner = document.getElementById('send-spinner');
                            if (buttonText && spinner) {
                                buttonText.classList.add('opacity-0');
                                spinner.classList.remove('hidden');
                                console.log('Message form submitted, showing spinner');
                            }
                        } catch (e) {
                            console.error('Message form submit error:', e);
                        }
                    });
                } else {
                    console.warn('Message form not found');
                }

                // Auto-resize textarea
                const textarea = document.querySelector('textarea');
                if (textarea) {
                    textarea.addEventListener('input', () => {
                        try {
                            textarea.style.height = 'auto';
                            textarea.style.height = `${textarea.scrollHeight}px`;
                            console.log('Textarea resized');
                        } catch (e) {
                            console.error('Textarea resize error:', e);
                        }
                    });
                } else {
                    console.warn('Textarea not found');
                }

                // Keyboard navigation for chat sidebar
                const chatLinks = document.querySelectorAll('.chat-sidebar a');
                if (chatLinks.length > 0) {
                    chatLinks.forEach((link, index) => {
                        link.addEventListener('keydown', (e) => {
                            try {
                                if (e.key === 'ArrowDown') {
                                    e.preventDefault();
                                    const next = chatLinks[index + 1] || chatLinks[0];
                                    next.focus();
                                    console.log('Navigated to next chat link');
                                }
                                if (e.key === 'ArrowUp') {
                                    e.preventDefault();
                                    const prev = chatLinks[index - 1] || chatLinks[chatLinks.length - 1];
                                    prev.focus();
                                    console.log('Navigated to previous chat link');
                                }
                            } catch (e) {
                                console.error('Keyboard navigation error:', e);
                            }
                        });
                    });
                } else {
                    console.log('No chat links found for keyboard navigation');
                }
            } catch (e) {
                console.error('DOMContentLoaded error:', e);
                document.body.innerHTML += '<p class="text-red-500 text-center bg-red-500/80 p-4 rounded-lg">Error initializing page: ' + e.message + '. Check console for details.</p>';
            }
        });
    </script>
    <script src="js/scripts.js" onerror="console.warn('Failed to load js/scripts.js')"></script>
</body>
</html>