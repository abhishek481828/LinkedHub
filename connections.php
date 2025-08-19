<?php
session_start();
include 'includes/db_connect.php';
include 'includes/header.php';

if (!isset($_SESSION['user_id'])) {
    error_log("Session user_id not set, redirecting to login");
    header("Location: login.php");
    exit;
}

$user_id = (int)$_SESSION['user_id'];
error_log("Processing connections for user_id: $user_id");

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

// Message variable for feedback
$messages = [];

// Send connection request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['connect_email']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for user_id: $user_id, Sent: " . ($_POST['csrf_token'] ?? 'none') . ", Expected: {$_SESSION['csrf_token']}");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $email = filter_var(trim($_POST['connect_email'] ?? ''), FILTER_SANITIZE_EMAIL);
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $messages[] = "<p class='text-red-500 text-center'>Please enter a valid email address.</p>";
        } else {
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("SELECT id, first_name, last_name FROM users WHERE email = ?");
                $stmt->execute([$email]);
                $connected_user = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$connected_user) {
                    $messages[] = "<p class='text-red-500 text-center'>No user found with that email.</p>";
                } elseif ($connected_user['id'] == $user_id) {
                    $messages[] = "<p class='text-red-500 text-center'>You cannot connect with yourself.</p>";
                } else {
                    // Check for existing connection
                    $checkStmt = $pdo->prepare("
                        SELECT id, status FROM connections WHERE 
                        (user_id_1 = ? AND user_id_2 = ?) OR 
                        (user_id_1 = ? AND user_id_2 = ?)
                    ");
                    $checkStmt->execute([$user_id, $connected_user['id'], $connected_user['id'], $user_id]);
                    $existing = $checkStmt->fetch(PDO::FETCH_ASSOC);
                    if ($existing) {
                        if ($existing['status'] === 'pending') {
                            $messages[] = "<p class='text-yellow-500 text-center'>A connection request already exists.</p>";
                        } else {
                            $messages[] = "<p class='text-yellow-500 text-center'>You are already connected.</p>";
                        }
                    } else {
                        // Insert new connection request
                        $stmt = $pdo->prepare("
                            INSERT INTO connections (user_id_1, user_id_2, status) 
                            VALUES (?, ?, 'pending')
                        ");
                        $stmt->execute([$user_id, $connected_user['id']]);
                        $pdo->commit();
                        $messages[] = "<p class='text-green-500 text-center'>Connection request sent to " . htmlspecialchars($connected_user['first_name'] . ' ' . $connected_user['last_name'], ENT_QUOTES, 'UTF-8') . "!</p>";
                        // Regenerate CSRF token
                        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                        error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                    }
                }
            } catch (PDOException $e) {
                $pdo->rollBack();
                error_log("Connection request error: " . $e->getMessage());
                $messages[] = "<p class='text-red-500 text-center'>Error sending connection request: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
            }
        }
    }
}

// Accept connection request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['accept_connection_id']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for accept action, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $connection_id = (int)$_POST['accept_connection_id'];
        try {
            $pdo->beginTransaction();
            $stmt = $pdo->prepare("
                SELECT user_id_1 FROM connections 
                WHERE id = ? AND user_id_2 = ? AND status = 'pending'
            ");
            $stmt->execute([$connection_id, $user_id]);
            $connection = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($connection) {
                // Update existing connection to accepted
                $stmt = $pdo->prepare("
                    UPDATE connections 
                    SET status = 'accepted' 
                    WHERE id = ?
                ");
                $stmt->execute([$connection_id]);
                // Create reciprocal connection
                $stmt = $pdo->prepare("
                    INSERT INTO connections (user_id_1, user_id_2, status) 
                    VALUES (?, ?, 'accepted')
                ");
                $stmt->execute([$user_id, $connection['user_id_1']]);
                $pdo->commit();
                $messages[] = "<p class='text-green-500 text-center'>Connection accepted!</p>";
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
            } else {
                $messages[] = "<p class='text-red-500 text-center'>Invalid or unauthorized request.</p>";
            }
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log("Accept connection error: " . $e->getMessage());
            $messages[] = "<p class='text-red-500 text-center'>Error accepting connection: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        }
    }
}

// Reject connection request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reject_connection_id']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for reject action, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $connection_id = (int)$_POST['reject_connection_id'];
        try {
            $pdo->beginTransaction();
            $stmt = $pdo->prepare("
                DELETE FROM connections 
                WHERE id = ? AND user_id_2 = ?
            ");
            $stmt->execute([$connection_id, $user_id]);
            if ($stmt->rowCount() > 0) {
                $pdo->commit();
                $messages[] = "<p class='text-green-500 text-center'>Connection request rejected.</p>";
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
            } else {
                $pdo->rollBack();
                $messages[] = "<p class='text-red-500 text-center'>Invalid or unauthorized request.</p>";
            }
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log("Reject connection error: " . $e->getMessage());
            $messages[] = "<p class='text-red-500 text-center'>Error rejecting connection: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        }
    }
}

// Fetch pending requests (where current user is user_id_2)
try {
    $stmt = $pdo->prepare("
        SELECT c.id, u.id AS user_id, u.first_name, u.last_name, u.profile_picture, u.headline 
        FROM connections c 
        JOIN users u ON c.user_id_1 = u.id 
        WHERE c.user_id_2 = ? AND c.status = 'pending'
        ORDER BY c.id DESC
    ");
    $stmt->execute([$user_id]);
    $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Pending requests fetch error: " . $e->getMessage());
    $requests = [];
    $messages[] = "<p class='text-red-500 text-center'>Error loading pending requests: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}

// Fetch accepted connections (both directions)
try {
    $stmt = $pdo->prepare("
        SELECT u.id, u.first_name, u.last_name, u.profile_picture, u.headline 
        FROM connections c 
        JOIN users u ON c.user_id_2 = u.id 
        WHERE c.user_id_1 = ? AND c.status = 'accepted'
        UNION
        SELECT u.id, u.first_name, u.last_name, u.profile_picture, u.headline 
        FROM connections c 
        JOIN users u ON c.user_id_1 = u.id 
        WHERE c.user_id_2 = ? AND c.status = 'accepted'
        ORDER BY first_name, last_name
    ");
    $stmt->execute([$user_id, $user_id]);
    $connections = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Connections fetch error: " . $e->getMessage());
    $connections = [];
    $messages[] = "<p class='text-red-500 text-center'>Error loading connections: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}

// Fetch suggested connections (same as index.php)
$suggested_connections = [];
try {
    $stmt = $pdo->prepare("
        SELECT DISTINCT u.id, u.first_name, u.last_name, u.profile_picture, u.headline
        FROM users u
        WHERE u.id != ? AND u.id NOT IN (
            SELECT user_id_2 FROM connections WHERE user_id_1 = ? AND status = 'accepted'
            UNION
            SELECT user_id_1 FROM connections WHERE user_id_2 = ? AND status = 'accepted'
        ) AND u.id IN (
            SELECT c2.user_id_2
            FROM connections c1
            JOIN connections c2 ON c1.user_id_2 = c2.user_id_1
            WHERE c1.user_id_1 = ? AND c1.status = 'accepted' AND c2.status = 'accepted'
            UNION
            SELECT c2.user_id_1
            FROM connections c1
            JOIN connections c2 ON c1.user_id_2 = c2.user_id_2
            WHERE c1.user_id_1 = ? AND c1.status = 'accepted' AND c2.status = 'accepted'
        )
        LIMIT 3
    ");
    $stmt->execute([$user_id, $user_id, $user_id, $user_id, $user_id]);
    $suggested_connections = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Suggested connections fetch error: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center'>Unable to load suggested connections: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}

// Fetch recent messages (same as index.php)
$messages_data = [];
try {
    $stmt = $pdo->prepare("
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.sent_at,
               u.first_name, u.last_name, u.profile_picture,
               (SELECT COUNT(*) FROM messages m2 WHERE m2.sender_id = u.id AND m2.sent_at > NOW() - INTERVAL 5 MINUTE) as is_online
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.receiver_id = ? OR m.sender_id = ?
        ORDER BY m.sent_at DESC
        LIMIT 5
    ");
    $stmt->execute([$user_id, $user_id]);
    $messages_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Message fetch error: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center'>Unable to load messages: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}

// Fetch user profile data (for left sidebar)
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
    $messages[] = "<p class='text-red-500 text-center'>Error validating user: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Network - LinkedIn Clone</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" />
    <style>
        .card { background: linear-gradient(to bottom, #374151, #1f2937); border-radius: 0.5rem; border: 2px solid #4b5563; padding: 1.5rem; color: white; }
        .btn-primary { background: #1e3a8a; color: white; padding: 0.5rem 1rem; border-radius: 0.375rem; display: inline-flex; align-items: center; transition: background-color 0.3s, transform 0.2s; }
        .btn-primary:hover { background: #1e40af; transform: scale(1.05); }
        .btn-secondary { background: #4b5563; color: white; padding: 0.5rem 1rem; border-radius: 0.375rem; transition: background-color 0.3s, transform 0.2s; }
        .btn-secondary:hover { background: #6b7280; transform: scale(1.05); }
        .btn-danger { background: #ef4444; color: white; padding: 0.5rem 1rem; border-radius: 0.375rem; transition: background-color 0.3s, transform 0.2s; }
        .btn-danger:hover { background: #dc2626; transform: scale(1.05); }
        .connection-card { background: #4b5563; border-radius: 0.5rem; transition: background-color 0.3s, transform 0.3s; }
        .connection-card:hover { background: #6b7280; transform: scale(1.02); }
        .scrollable-feed { max-height: calc(100vh - 8rem); overflow-y: auto; }
        .scrollable-feed::-webkit-scrollbar { width: 8px; }
        .scrollable-feed::-webkit-scrollbar-track { background: #1f2937; }
        .scrollable-feed::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 4px; }
        .scrollable-feed::-webkit-scrollbar-thumb:hover { background: #6b7280; }
        .fade-in { animation: fadeIn 0.5s ease-in; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    </style>
</head>
<body class="bg-gray-800 font-sans">
    <!-- Mobile Sidebar Toggle -->
    <button id="sidebar-toggle" class="md:hidden fixed top-16 left-4 z-50 bg-blue-900 text-white p-2 rounded-full">
        <i class="fas fa-bars"></i>
    </button>

    <div class="flex max-w-7xl mx-auto gap-6 py-6 px-4 sm:px-6 lg:px-8 min-h-screen">
        <!-- Left Sidebar (Profile) -->
        <div class="w-full md:w-1/4 hidden md:block">
            <div class="card sticky top-4 fade-in">
                <div class="flex items-center mb-4">
                    <a href="profile.php">
                        <img src="<?php echo getProfilePicture($_SESSION['profile_picture']); ?>" class="w-12 h-12 rounded-full mr-3 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                    </a>
                    <div>
                        <a href="profile.php" class="font-semibold text-blue-400 hover:underline"><?php echo htmlspecialchars($_SESSION['first_name'] . ' ' . $_SESSION['last_name'], ENT_QUOTES, 'UTF-8'); ?></a>
                        <p class="text-gray-200 text-sm"><?php echo htmlspecialchars($_SESSION['headline'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                </div>
                <a href="profile.php" class="btn-primary block mb-2 text-center"><i class="fas fa-user mr-2"></i>View Profile</a>
                <a href="connections.php" class="btn-secondary block text-center"><i class="fas fa-users mr-2"></i>My Network</a>
            </div>
        </div>

        <!-- Main Content -->
        <div class="w-full md:w-1/2">
            <div class="scrollable-feed pr-2">
                <div class="card mb-6 fade-in">
                    <h2 class="text-xl font-semibold mb-4">My Network</h2>
                    <?php if (!empty($messages)): ?>
                        <div class="mb-4">
                            <?php foreach ($messages as $msg): ?>
                                <?php echo $msg; ?>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <!-- Connect with Someone -->
                    <div class="mb-6">
                        <h3 class="text-lg font-semibold mb-4 text-white">Connect with Someone</h3>
                        <form method="POST" class="space-y-4" id="connect-form">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                            <div>
                                <label for="connect_email" class="block text-gray-200 font-medium mb-2">Enter Email</label>
                                <input type="email" name="connect_email" id="connect_email" class="w-full p-3 border rounded-lg bg-gray-700 text-white border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="user@example.com" required>
                            </div>
                            <button type="submit" class="btn-primary w-full py-2 relative">
                                <i class="fas fa-user-plus mr-2"></i>
                                <span id="connect-button-text">Send Connection Request</span>
                                <svg id="connect-spinner" class="hidden animate-spin h-5 w-5 text-white absolute right-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                            </button>
                        </form>
                    </div>

                    <!-- Pending Connection Requests -->
                    <div class="mb-6">
                        <h3 class="text-lg font-semibold mb-4 text-white">Pending Connection Requests</h3>
                        <?php if (empty($requests)): ?>
                            <p class="text-gray-200">No pending requests.</p>
                        <?php else: ?>
                            <?php foreach ($requests as $request): ?>
                                <div class="connection-card mb-4 p-4">
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center">
                                            <a href="view_profile.php?user_id=<?php echo (int)$request['user_id']; ?>">
                                                <img src="<?php echo getProfilePicture($request['profile_picture']); ?>" class="w-10 h-10 rounded-full mr-3 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                                            </a>
                                            <div>
                                                <a href="view_profile.php?user_id=<?php echo (int)$request['user_id']; ?>" class="font-semibold text-blue-400 hover:underline">
                                                    <?php echo htmlspecialchars($request['first_name'] . ' ' . $request['last_name'], ENT_QUOTES, 'UTF-8'); ?>
                                                </a>
                                                <p class="text-gray-200 text-sm"><?php echo htmlspecialchars($request['headline'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
                                            </div>
                                        </div>
                                        <div class="space-x-2">
                                            <form method="POST" class="inline-block" id="accept-form-<?php echo (int)$request['id']; ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                                <input type="hidden" name="accept_connection_id" value="<?php echo (int)$request['id']; ?>">
                                                <button type="submit" class="btn-primary px-3 py-1 text-sm relative">
                                                    <i class="fas fa-check mr-2"></i>
                                                    <span class="accept-button-text">Accept</span>
                                                    <svg class="hidden animate-spin h-5 w-5 text-white absolute right-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                                    </svg>
                                                </button>
                                            </form>
                                            <form method="POST" class="inline-block" id="reject-form-<?php echo (int)$request['id']; ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                                <input type="hidden" name="reject_connection_id" value="<?php echo (int)$request['id']; ?>">
                                                <button type="submit" class="btn-danger px-3 py-1 text-sm relative" onclick="return confirm('Are you sure you want to reject this connection request?');">
                                                    <i class="fas fa-times mr-2"></i>
                                                    <span class="reject-button-text">Reject</span>
                                                    <svg class="hidden animate-spin h-5 w-5 text-white absolute right-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                                    </svg>
                                                </button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>

                    <!-- Your Connections -->
                    <div>
                        <h3 class="text-lg font-semibold mb-4 text-white">Your Connections</h3>
                        <?php if (empty($connections)): ?>
                            <p class="text-gray-200">No connections yet. Start connecting!</p>
                        <?php else: ?>
                            <?php foreach ($connections as $connection): ?>
                                <div class="connection-card mb-4 p-4">
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center">
                                            <a href="view_profile.php?user_id=<?php echo (int)$connection['id']; ?>">
                                                <img src="<?php echo getProfilePicture($connection['profile_picture']); ?>" class="w-10 h-10 rounded-full mr-3 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                                            </a>
                                            <div>
                                                <a href="view_profile.php?user_id=<?php echo (int)$connection['id']; ?>" class="font-semibold text-blue-400 hover:underline">
                                                    <?php echo htmlspecialchars($connection['first_name'] . ' ' . $connection['last_name'], ENT_QUOTES, 'UTF-8'); ?>
                                                </a>
                                                <p class="text-gray-200 text-sm"><?php echo htmlspecialchars($connection['headline'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
                                            </div>
                                        </div>
                                        <a href="chat.php?user=<?php echo (int)$connection['id']; ?>" class="btn-primary px-3 py-1 text-sm">
                                            <i class="fas fa-paper-plane mr-2"></i>Message
                                        </a>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Right Sidebar -->
        <div class="w-full md:w-1/4 hidden md:block">
            <!-- Suggested Connections -->
            <div class="card mb-6 sticky top-4 fade-in">
                <h2 class="text-xl font-semibold mb-4">People You May Know</h2>
                <?php if (empty($suggested_connections)): ?>
                    <p class="text-gray-200">No suggestions available.</p>
                <?php else: ?>
                    <?php foreach ($suggested_connections as $conn): ?>
                        <div class="flex items-center justify-between mb-4">
                            <div class="flex items-center">
                                <a href="view_profile.php?user_id=<?php echo (int)$conn['id']; ?>">
                                    <img src="<?php echo getProfilePicture($conn['profile_picture']); ?>" class="w-10 h-10 rounded-full mr-3 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                                </a>
                                <div>
                                    <a href="view_profile.php?user_id=<?php echo (int)$conn['id']; ?>" class="font-semibold text-blue-400 hover:underline"><?php echo htmlspecialchars(($conn['first_name'] ?? '') . ' ' . ($conn['last_name'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></a>
                                    <p class="text-gray-200 text-sm"><?php echo htmlspecialchars($conn['headline'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
                                </div>
                            </div>
                            <form method="POST" action="connections.php">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                <input type="hidden" name="connect_id" value="<?php echo (int)$conn['id']; ?>">
                                <button type="submit" class="btn-secondary text-sm px-3 py-1"><i class="fas fa-user-plus mr-2"></i>Connect</button>
                            </form>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <!-- Messages -->
            <div class="card fade-in">
                <h2 class="text-xl font-semibold mb-4">Messages</h2>
                <?php if (empty($messages_data)): ?>
                    <p class="text-gray-200">No recent messages. Start a conversation!</p>
                <?php else: ?>
                    <?php foreach ($messages_data as $msg): ?>
                        <div class="connection-card mb-4 p-4">
                            <div class="flex items-center mb-2">
                                <a href="view_profile.php?user_id=<?php echo (int)$msg['sender_id']; ?>">
                                    <img src="<?php echo getProfilePicture($msg['profile_picture']); ?>" class="w-10 h-10 rounded-full mr-3 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                                </a>
                                <div class="flex items-center">
                                    <a href="view_profile.php?user_id=<?php echo (int)$msg['sender_id']; ?>" class="font-semibold text-blue-400 hover:underline"><?php echo htmlspecialchars(($msg['first_name'] ?? '') . ' ' . ($msg['last_name'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></a>
                                    <?php if ($msg['is_online'] ?? 0): ?>
                                        <span class="ml-2 w-2 h-2 bg-green-500 rounded-full" title="Online"></span>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <p class="text-gray-200"><?php echo htmlspecialchars(substr($msg['content'] ?? '', 0, 50) . (strlen($msg['content'] ?? '') > 50 ? '...' : ''), ENT_QUOTES, 'UTF-8'); ?></p>
                            <p class="text-gray-400 text-sm"><?php echo date('M d, Y H:i', strtotime($msg['sent_at'] ?? 'now')); ?></p>
                            <a href="chat.php?user=<?php echo (int)$msg['sender_id']; ?>" class="btn-primary mt-2 inline-block px-3 py-1 text-sm">
                                <i class="fas fa-paper-plane mr-2"></i>Reply
                            </a>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
                <a href="chat.php" class="btn-primary mt-4 block text-center"><i class="fas fa-comments mr-2"></i>View All Messages</a>
            </div>
        </div>
    </div>

    <script>
        // Loading spinners for form submissions
        document.addEventListener('DOMContentLoaded', () => {
            const connectForm = document.getElementById('connect-form');
            if (connectForm) {
                connectForm.addEventListener('submit', () => {
                    const buttonText = document.getElementById('connect-button-text');
                    const spinner = document.getElementById('connect-spinner');
                    if (buttonText && spinner) {
                        buttonText.classList.add('opacity-0');
                        spinner.classList.remove('hidden');
                    }
                });
            }

            document.querySelectorAll('form[id^="accept-form-"]').forEach(form => {
                form.addEventListener('submit', () => {
                    const button = form.querySelector('button');
                    const buttonText = button.querySelector('.accept-button-text');
                    const spinner = button.querySelector('.animate-spin');
                    if (buttonText && spinner) {
                        buttonText.classList.add('opacity-0');
                        spinner.classList.remove('hidden');
                    }
                });
            });

            document.querySelectorAll('form[id^="reject-form-"]').forEach(form => {
                form.addEventListener('submit', (e) => {
                    if (!confirm('Are you sure you want to reject this connection request?')) {
                        e.preventDefault();
                        return;
                    }
                    const button = form.querySelector('button');
                    const buttonText = button.querySelector('.reject-button-text');
                    const spinner = button.querySelector('.animate-spin');
                    if (buttonText && spinner) {
                        buttonText.classList.add('opacity-0');
                        spinner.classList.remove('hidden');
                    }
                });
            });

            // Mobile Sidebar Toggle
            const toggleButton = document.getElementById('sidebar-toggle');
            const leftSidebar = document.querySelector('.md\\:w-1\\/4');
            const rightSidebar = document.querySelector('.md\\:w-1\\/4:last-child');
            if (toggleButton && leftSidebar && rightSidebar) {
                toggleButton.addEventListener('click', () => {
                    leftSidebar.classList.toggle('hidden');
                    rightSidebar.classList.toggle('hidden');
                });
            }
        });
    </script>
    <?php include 'includes/footer.php'; ?>
</body>
</html>