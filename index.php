<?php
// Enable error reporting (disable in production)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Start session
session_start();

// Include dependencies
try {
    require_once 'includes/db_connect.php';
} catch (Exception $e) {
    error_log("Failed to include db_connect.php: " . $e->getMessage());
    die("<div class='text-red-500 text-center p-4'>Unable to connect to the database. Please check your configuration and try again.</div>");
}

require_once 'includes/header.php';

// Check session
if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
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

// Message queue for feedback
$messages = [];

// Helper function for profile pictures
function getProfilePicture($path = null) {
    $default = 'Uploads/default.jpg';
    $path = trim($path ?? '');
    return (file_exists($path) && !empty($path)) ? htmlspecialchars($path, ENT_QUOTES, 'UTF-8') : htmlspecialchars($default, ENT_QUOTES, 'UTF-8');
}

// Initialize session variables
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

// Handle connection request from suggested connections
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['connect_user_id']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for connection request, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $connect_user_id = (int)$_POST['connect_user_id'];
        try {
            $pdo->beginTransaction();
            // Check if the target user exists
            $stmt = $pdo->prepare("SELECT id, first_name, last_name FROM users WHERE id = ?");
            $stmt->execute([$connect_user_id]);
            $connected_user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$connected_user) {
                $messages[] = "<p class='text-red-500 text-center'>User not found.</p>";
            } elseif ($connected_user['id'] == $user_id) {
                $messages[] = "<p class='text-red-500 text-center'>You cannot connect with yourself.</p>";
            } else {
                // Check for existing connection
                $checkStmt = $pdo->prepare("
                    SELECT id, status FROM connections WHERE 
                    (user_id_1 = ? AND user_id_2 = ?) OR 
                    (user_id_1 = ? AND user_id_2 = ?)
                ");
                $checkStmt->execute([$user_id, $connect_user_id, $connect_user_id, $user_id]);
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
                    $stmt->execute([$user_id, $connect_user_id]);
                    $pdo->commit();
                    $messages[] = "<p class='text-green-500 text-center'>Connection request sent to " . htmlspecialchars($connected_user['first_name'] . ' ' . $connected_user['last_name'], ENT_QUOTES, 'UTF-8') . "!</p>";
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                }
            }
            header("Location: index.php");
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log("Connection request error: " . $e->getMessage());
            $messages[] = "<p class='text-red-500 text-center'>Error sending connection request: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        }
    }
}

// Handle post submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['content']) && !isset($_POST['comment_post_id']) && !isset($_POST['reaction_post_id']) && !isset($_POST['share_post_id']) && !isset($_POST['delete_post_id']) && !isset($_POST['connect_user_id']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for post submission, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $content = htmlspecialchars(trim($_POST['content'] ?? ''), ENT_QUOTES, 'UTF-8');
        $image = null;
        $video = null;
        $post_type = 'text'; // Default post type

        // Handle file uploads (image and video)
        $target_dir = "Uploads/";
        if (!is_dir($target_dir) && !mkdir($target_dir, 0755, true)) {
            error_log("Failed to create uploads directory");
            $messages[] = "<p class='text-red-500 text-center'>Unable to create upload directory.</p>";
        } elseif (!is_writable($target_dir)) {
            error_log("Uploads directory not writable");
            $messages[] = "<p class='text-red-500 text-center'>Upload directory is not writable.</p>";
        } else {
            // Process image upload
            if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
                $file_ext = strtolower(pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION));
                $allowed_exts = ['jpg', 'jpeg', 'png', 'gif'];
                $allowed_mime = ['image/jpeg', 'image/png', 'image/gif'];
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime = finfo_file($finfo, $_FILES['image']['tmp_name']);
                finfo_close($finfo);
                $max_size = 5 * 1024 * 1024; // 5MB

                $image_info = getimagesize($_FILES['image']['tmp_name']);
                if ($image_info === false) {
                    error_log("Uploaded image is not a valid image");
                    $messages[] = "<p class='text-red-500 text-center'>Uploaded image is not a valid image.</p>";
                } elseif (!in_array($file_ext, $allowed_exts) || !in_array($mime, $allowed_mime)) {
                    error_log("Invalid image file: ext=$file_ext, mime=$mime");
                    $messages[] = "<p class='text-red-500 text-center'>Invalid image file. Allowed: jpg, jpeg, png, gif.</p>";
                } elseif ($_FILES['image']['size'] > $max_size) {
                    error_log("Image file too large: size={$_FILES['image']['size']}");
                    $messages[] = "<p class='text-red-500 text-center'>Image file too large. Max size: 5MB.</p>";
                } else {
                    $target_file = $target_dir . uniqid() . '.' . $file_ext;
                    if (move_uploaded_file($_FILES['image']['tmp_name'], $target_file)) {
                        $image = $target_file;
                        $post_type = 'image'; // Update post type if only image is uploaded
                    } else {
                        error_log("Failed to upload image: " . $_FILES['image']['name']);
                        $messages[] = "<p class='text-red-500 text-center'>Failed to upload image.</p>";
                    }
                }
            } elseif (isset($_FILES['image']) && $_FILES['image']['error'] !== UPLOAD_ERR_NO_FILE) {
                error_log("Image upload error: " . $_FILES['image']['error']);
                $messages[] = "<p class='text-red-500 text-center'>Error uploading image (Code: {$_FILES['image']['error']}).</p>";
            }

            // Process video upload
            if (isset($_FILES['video']) && $_FILES['video']['error'] === UPLOAD_ERR_OK) {
                $file_ext = strtolower(pathinfo($_FILES['video']['name'], PATHINFO_EXTENSION));
                $allowed_exts = ['mp4', 'mov'];
                $allowed_mime = ['video/mp4', 'video/quicktime'];
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime = finfo_file($finfo, $_FILES['video']['tmp_name']);
                finfo_close($finfo);
                $max_size = 5 * 1024 * 1024; // 5MB

                if (!in_array($file_ext, $allowed_exts) || !in_array($mime, $allowed_mime)) {
                    error_log("Invalid video file: ext=$file_ext, mime=$mime");
                    $messages[] = "<p class='text-red-500 text-center'>Invalid video file. Allowed: mp4, mov.</p>";
                } elseif ($_FILES['video']['size'] > $max_size) {
                    error_log("Video file too large: size={$_FILES['video']['size']}");
                    $messages[] = "<p class='text-red-500 text-center'>Video file too large. Max size: 5MB.</p>";
                } else {
                    $target_file = $target_dir . uniqid() . '.' . $file_ext;
                    if (move_uploaded_file($_FILES['video']['tmp_name'], $target_file)) {
                        $video = $target_file;
                        $post_type = $image ? 'media' : 'video'; // 'media' if both, 'video' if only video
                    } else {
                        error_log("Failed to upload video: " . $_FILES['video']['name']);
                        $messages[] = "<p class='text-red-500 text-center'>Failed to upload video.</p>";
                    }
                }
            } elseif (isset($_FILES['video']) && $_FILES['video']['error'] !== UPLOAD_ERR_NO_FILE) {
                error_log("Video upload error: " . $_FILES['video']['error']);
                $messages[] = "<p class='text-red-500 text-center'>Error uploading video (Code: {$_FILES['video']['error']}).</p>";
            }
        }

        if ($content && empty($messages)) {
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("INSERT INTO posts (user_id, content, image, video, post_type, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
                $stmt->execute([$user_id, $content, $image, $video, $post_type]);
                $pdo->commit();
                $messages[] = "<p class='text-green-500 text-center'>Posted successfully!</p>";
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                header("Location: index.php");
                exit;
            } catch (PDOException $e) {
                $pdo->rollBack();
                error_log("Post insert error: " . $e->getMessage());
                $messages[] = "<p class='text-red-500 text-center'>Error posting content: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
            }
        } elseif (empty($messages)) {
            $messages[] = "<p class='text-red-500 text-center'>Content is required.</p>";
        }
    }
}

// Handle post deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_post_id']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for post deletion, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $post_id = (int)$_POST['delete_post_id'];
        try {
            $stmt = $pdo->prepare("SELECT user_id FROM posts WHERE id = ?");
            $stmt->execute([$post_id]);
            $post = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($post && $post['user_id'] == $user_id) {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("DELETE FROM reactions WHERE post_id = ?");
                $stmt->execute([$post_id]);
                $stmt = $pdo->prepare("DELETE FROM comments WHERE post_id = ?");
                $stmt->execute([$post_id]);
                $stmt = $pdo->prepare("DELETE FROM shares WHERE post_id = ?");
                $stmt->execute([$post_id]);
                $stmt = $pdo->prepare("DELETE FROM posts WHERE id = ? AND user_id = ?");
                $stmt->execute([$post_id, $user_id]);
                $pdo->commit();
                $messages[] = "<p class='text-green-500 text-center'>Post deleted successfully.</p>";
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
            } else {
                $messages[] = "<p class='text-red-500 text-center'>You are not authorized to delete this post.</p>";
            }
            header("Location: index.php");
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log("Post deletion error: " . $e->getMessage());
            $messages[] = "<p class='text-red-500 text-center'>Error deleting post: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        }
    }
}

// Handle reaction action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reaction_post_id']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for reaction, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $post_id = (int)$_POST['reaction_post_id'];
        $reaction_type = in_array($_POST['reaction_type'] ?? 'like', ['like', 'celebrate', 'insightful', 'support']) ? $_POST['reaction_type'] : 'like';
        try {
            $stmt = $pdo->prepare("SELECT id FROM reactions WHERE post_id = ? AND user_id = ? AND reaction_type = ?");
            $stmt->execute([$post_id, $user_id, $reaction_type]);
            if ($stmt->fetch()) {
                $stmt = $pdo->prepare("DELETE FROM reactions WHERE post_id = ? AND user_id = ? AND reaction_type = ?");
                $stmt->execute([$post_id, $user_id, $reaction_type]);
                $messages[] = "<p class='text-green-500 text-center'>Reaction removed.</p>";
            } else {
                $stmt = $pdo->prepare("DELETE FROM reactions WHERE post_id = ? AND user_id = ?");
                $stmt->execute([$post_id, $user_id]);
                $stmt = $pdo->prepare("INSERT INTO reactions (post_id, user_id, reaction_type, created_at) VALUES (?, ?, ?, NOW())");
                $stmt->execute([$post_id, $user_id, $reaction_type]);
                $messages[] = "<p class='text-green-500 text-center'>Reaction added.</p>";
            }
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
            header("Location: index.php");
            exit;
        } catch (PDOException $e) {
            error_log("Reaction action error: " . $e->getMessage());
            $messages[] = "<p class='text-red-500 text-center'>Error adding reaction: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        }
    }
}

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment_post_id']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for comment, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $post_id = (int)$_POST['comment_post_id'];
        $comment_content = htmlspecialchars(trim($_POST['comment_content'] ?? ''), ENT_QUOTES, 'UTF-8');
        if ($comment_content) {
            try {
                $stmt = $pdo->prepare("INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())");
                $stmt->execute([$post_id, $user_id, $comment_content]);
                $messages[] = "<p class='text-green-500 text-center'>Comment added successfully.</p>";
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                header("Location: index.php");
                exit;
            } catch (PDOException $e) {
                error_log("Comment insert error: " . $e->getMessage());
                $messages[] = "<p class='text-red-500 text-center'>Error adding comment: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
            }
        } else {
            $messages[] = "<p class='text-red-500 text-center'>Comment cannot be empty.</p>";
        }
    }
}

// Handle share action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['share_post_id']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for share, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $post_id = (int)$_POST['share_post_id'];
        try {
            $stmt = $pdo->prepare("SELECT id FROM shares WHERE post_id = ? AND user_id = ?");
            $stmt->execute([$post_id, $user_id]);
            if (!$stmt->fetch()) {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("INSERT INTO shares (post_id, user_id, created_at) VALUES (?, ?, NOW())");
                $stmt->execute([$post_id, $user_id]);
                $stmt = $pdo->prepare("SELECT p.content, p.image, p.video, p.post_type, u.first_name, u.last_name FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?");
                $stmt->execute([$post_id]);
                $original_post = $stmt->fetch(PDO::FETCH_ASSOC);
                $share_content = "Shared a post by " . ($original_post['first_name'] ?? '') . " " . ($original_post['last_name'] ?? '') . ": " . ($original_post['content'] ?? '');
                $stmt = $pdo->prepare("INSERT INTO posts (user_id, content, image, video, post_type, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
                $stmt->execute([$user_id, $share_content, $original_post['image'], $original_post['video'], $original_post['post_type']]);
                $pdo->commit();
                $messages[] = "<p class='text-green-500 text-center'>Post shared successfully.</p>";
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
            } else {
                $messages[] = "<p class='text-yellow-500 text-center'>You already shared this post.</p>";
            }
            header("Location: index.php");
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log("Share action error: " . $e->getMessage());
            $messages[] = "<p class='text-red-500 text-center'>Error sharing post: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        }
    }
}

// Fetch posts with reaction, comment, and share counts
$posts = [];
$comments = [];
try {
    $stmt = $pdo->prepare("
        SELECT p.id, p.user_id, p.content, p.image, p.video, p.post_type, p.created_at,
               u.first_name, u.last_name, u.profile_picture,
               (SELECT COUNT(*) FROM reactions r WHERE r.post_id = p.id) as reaction_count,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count,
               (SELECT COUNT(*) FROM shares s WHERE s.post_id = p.id) as share_count,
               (SELECT reaction_type FROM reactions r WHERE r.post_id = p.id AND r.user_id = ? LIMIT 1) as user_reaction
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    ");
    $stmt->execute([$user_id]);
    $posts = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("
        SELECT c.id, c.post_id, c.user_id, c.content, c.created_at,
               u.first_name, u.last_name, u.profile_picture
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id IN (SELECT id FROM posts)
        ORDER BY c.created_at DESC
        LIMIT 100
    ");
    $stmt->execute();
    $comments = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Post or comment fetch error: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center'>Unable to load posts or comments: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}

// Fetch suggested connections
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

// Fetch recent messages (3 latest conversations)
$messages_data = [];
try {
    $stmt = $pdo->prepare("
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.sent_at,
               u.first_name, u.last_name, u.profile_picture,
               (SELECT COUNT(*) FROM messages m2 WHERE m2.sender_id = u.id AND m2.sent_at > NOW() - INTERVAL 5 MINUTE) as is_online
        FROM (
            SELECT m2.id, m2.sender_id, m2.receiver_id, m2.content, m2.sent_at
            FROM messages m2
            WHERE (m2.sender_id = ? OR m2.receiver_id = ?)
            AND m2.sent_at = (
                SELECT MAX(m3.sent_at)
                FROM messages m3
                WHERE (m3.sender_id = m2.sender_id AND m3.receiver_id = m2.receiver_id)
                   OR (m3.sender_id = m2.receiver_id AND m3.receiver_id = m2.sender_id)
            )
            ORDER BY m2.sent_at DESC
            LIMIT 3
        ) m
        JOIN users u ON u.id = (CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END)
        ORDER BY m.sent_at DESC
    ");
    $stmt->execute([$user_id, $user_id, $user_id]);
    $messages_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Message fetch error: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center'>Unable to load messages: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkedIn Clone</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        .media-tab { transition: background-color 0.3s, color 0.3s; }
        .media-tab.active { background-color: #1e3a8a; color: white; }
        .media-tab:hover { background-color: #1e40af; }
        .preview-container img, .preview-container video { max-height: 200px; object-fit: contain; }
        .card { background: linear-gradient(to bottom, #374151, #1f2937); border-radius: 0.5rem; border: 2px solid #4b5563; padding: 1.5rem; color: white; }
        .btn-primary { background: #1e3a8a; color: white; padding: 0.5rem 1rem; border-radius: 0.375rem; display: inline-flex; align-items: center; transition: background-color 0.3s, transform 0.2s; }
        .btn-primary:hover { background: #1e40af; transform: scale(1.05); }
        .btn-secondary { background: #4b5563; color: white; padding: 0.5rem 1rem; border-radius: 0.375rem; transition: background-color 0.3s, transform 0.2s; }
        .btn-secondary:hover { background: #6b7280; transform: scale(1.05); }
        .post-card { background: linear-gradient(to bottom, #4b5563, #374151); border-radius: 0.5rem; transition: transform 0.3s; }
        .post-card:hover { transform: scale(1.02); }
        .comment-card { background: #4b5563; border-radius: 0.5rem; transition: background-color 0.3s; }
        .comment-card:hover { background: #6b7280; }
        .message-card { background: #4b5563; border-radius: 0.5rem; transition: background-color 0.3s; }
        .message-card:hover { background: #6b7280; }
        .group:hover .group-hover\\:block { display: block; }
        .scrollable-feed { max-height: calc(100vh - 8rem); overflow-y: auto; }
        .scrollable-feed::-webkit-scrollbar { width: 8px; }
        .scrollable-feed::-webkit-scrollbar-track { background: #1f2937; }
        .scrollable-feed::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 4px; }
        .scrollable-feed::-webkit-scrollbar-thumb:hover { background: #6b7280; }
    </style>
</head>
<body class="bg-gray-800 font-sans">
    <div class="flex max-w-7xl mx-auto gap-6 py-6 px-4 sm:px-6 lg:px-8 min-h-screen">
        <!-- Left Sidebar (Profile) -->
        <div class="w-full md:w-1/4 md:block">
            <div class="card sticky top-4">
                <div class="flex items-center mb-4">
                    <a href="profile.php">
                        <img src="<?php echo getProfilePicture($_SESSION['profile_picture']); ?>" class="w-12 h-12 rounded-full mr-3 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                    </a>
                    <div>
                        <a href="profile.php" class="font-semibold text-blue-400 hover:underline"><?php echo htmlspecialchars($_SESSION['first_name'] . ' ' . $_SESSION['last_name'], ENT_QUOTES, 'UTF-8'); ?></a>
                        <p class="text-gray-200 text-sm"><?php echo htmlspecialchars($_SESSION['headline'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                </div>
                <a href="profile.php" class="btn-primary block mb-2 text-center">View Profile</a>
                <a href="connections.php" class="btn-secondary block text-center">My Network</a>
            </div>
        </div>

        <!-- Main Content -->
        <div class="w-full md:w-1/2">
            <div class="scrollable-feed pr-2">
                <!-- Post Form -->
                <div class="card mb-6">
                    <h2 class="text-xl font-semibold mb-4">Share an update</h2>
                    <?php if (!empty($messages)): ?>
                        <div class="mb-4">
                            <?php foreach ($messages as $msg): ?>
                                <?php echo $msg; ?>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    <form method="POST" enctype="multipart/form-data" id="post-form" class="relative">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                        <div class="mb-4">
                            <textarea name="content" class="w-full p-3 border rounded-lg bg-gray-700 text-white border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" rows="4" placeholder="What's on your mind?" required></textarea>
                        </div>
                        <!-- Media Tabs -->
                        <div class="flex space-x-2 mb-4">
                            <button type="button" class="media-tab px-4 py-2 rounded-lg bg-gray-600 text-white active" data-tab="text">Text</button>
                            <button type="button" class="media-tab px-4 py-2 rounded-lg bg-gray-600 text-white" data-tab="image">Image</button>
                            <button type="button" class="media-tab px-4 py-2 rounded-lg bg-gray-600 text-white" data-tab="video">Video</button>
                        </div>
                        <!-- Media Inputs -->
                        <div id="media-inputs">
                            <div class="media-content text-content">
                                <p class="text-gray-200 text-sm">Enter your post content above.</p>
                            </div>
                            <div class="media-content image-content hidden">
                                <label for="image" class="block text-gray-200 font-medium mb-2">Upload Image (optional)</label>
                                <input type="file" name="image" id="image" accept="image/jpeg,image/png,image/gif" class="w-full p-3 border rounded-lg bg-gray-700 text-white border-gray-600">
                                <div class="preview-container mt-2 hidden">
                                    <img id="image-preview" src="#" alt="Image Preview" class="rounded-lg">
                                </div>
                            </div>
                            <div class="media-content video-content hidden">
                                <label for="video" class="block text-gray-200 font-medium mb-2">Upload Video (optional)</label>
                                <input type="file" name="video" id="video" accept="video/mp4,video/mov" class="w-full p-3 border rounded-lg bg-gray-700 text-white border-gray-600">
                                <div class="preview-container mt-2 hidden">
                                    <video id="video-preview" controls class="rounded-lg">
                                        <source src="#" type="video/mp4">
                                        Your browser does not support the video tag.
                                    </video>
                                </div>
                            </div>
                        </div>
                        <button type="submit" class="btn-primary relative">
                            <span id="post-button-text">Post</span>
                            <svg id="post-spinner" class="hidden animate-spin h-5 w-5 text-white absolute right-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                        </button>
                    </form>
                </div>

                <!-- Post Feed -->
                <div class="card mb-6">
                    <h2 class="text-xl font-semibold mb-4">Recent Posts</h2>
                    <?php if (empty($posts)): ?>
                        <p class="text-gray-200">No posts yet. Share something!</p>
                    <?php else: ?>
                        <?php foreach ($posts as $post): ?>
                            <div class="post-card mb-6 p-4">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center">
                                        <a href="view_profile.php?user_id=<?php echo (int)$post['user_id']; ?>">
                                            <img src="<?php echo getProfilePicture($post['profile_picture']); ?>" class="w-10 h-10 rounded-full mr-3 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                                        </a>
                                        <div>
                                            <a href="view_profile.php?user_id=<?php echo (int)$post['user_id']; ?>" class="font-semibold text-blue-400 hover:underline"><?php echo htmlspecialchars(($post['first_name'] ?? '') . ' ' . ($post['last_name'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></a>
                                            <p class="text-gray-200 text-sm"><?php echo date('M d, Y H:i', strtotime($post['created_at'] ?? 'now')); ?></p>
                                        </div>
                                    </div>
                                    <?php if ($post['user_id'] == $user_id): ?>
                                        <form method="POST" class="inline-block">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                            <input type="hidden" name="delete_post_id" value="<?php echo (int)$post['id']; ?>">
                                            <button type="submit" class="text-red-500 hover:text-red-700 text-sm">Delete</button>
                                        </form>
                                    <?php endif; ?>
                                </div>
                                <p class="mb-2 text-gray-200"><?php echo htmlspecialchars($post['content'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
                                <?php if (!empty($post['image']) && file_exists($post['image'])): ?>
                                    <img src="<?php echo htmlspecialchars($post['image'], ENT_QUOTES, 'UTF-8'); ?>" class="w-full max-h-96 rounded-lg mb-2 object-cover" alt="Post Image">
                                <?php endif; ?>
                                <?php if (!empty($post['video']) && file_exists($post['video'])): ?>
                                    <video controls class="w-full max-h-96 rounded-lg mb-2">
                                        <source src="<?php echo htmlspecialchars($post['video'], ENT_QUOTES, 'UTF-8'); ?>" type="video/mp4">
                                        Your browser does not support the video tag.
                                    </video>
                                <?php endif; ?>
                                <div class="flex justify-between text-gray-200 text-sm mb-2">
                                    <span><?php echo (int)($post['reaction_count'] ?? 0); ?> Reactions</span>
                                    <span><?php echo (int)($post['comment_count'] ?? 0); ?> Comments</span>
                                    <span><?php echo (int)($post['share_count'] ?? 0); ?> Shares</span>
                                </div>
                                <div class="flex space-x-2 mb-2 relative">
                                    <div class="relative group">
                                        <button class="btn-secondary flex items-center space-x-1 <?php echo ($post['user_reaction'] ?? '') ? 'bg-blue-500 text-white' : ''; ?>">
                                            <span><?php echo htmlspecialchars(ucfirst($post['user_reaction'] ?? 'React'), ENT_QUOTES, 'UTF-8'); ?></span>
                                        </button>
                                        <div class="absolute hidden group-hover:block bg-gray-700 border border-gray-600 rounded-lg shadow-lg p-2 z-10 -left-2">
                                            <?php
                                            $reactions = ['like' => 'Like', 'celebrate' => 'Celebrate', 'insightful' => 'Insightful', 'support' => 'Support'];
                                            foreach ($reactions as $type => $label):
                                            ?>
                                                <form method="POST" class="inline-block">
                                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                                    <input type="hidden" name="reaction_post_id" value="<?php echo (int)$post['id']; ?>">
                                                    <input type="hidden" name="reaction_type" value="<?php echo $type; ?>">
                                                    <button type="submit" class="block px-2 py-1 hover:bg-gray-600 w-full text-left text-white"><?php echo $label; ?></button>
                                                </form>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                    <button onclick="toggleComments(<?php echo (int)$post['id']; ?>)" class="btn-secondary">Comment</button>
                                    <form method="POST">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="share_post_id" value="<?php echo (int)$post['id']; ?>">
                                        <button type="submit" class="btn-secondary">Repost</button>
                                    </form>
                                </div>
                                <div id="comments-<?php echo (int)$post['id']; ?>" class="hidden mt-2 transition-all duration-300">
                                    <form method="POST" class="mb-4 relative">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="comment_post_id" value="<?php echo (int)$post['id']; ?>">
                                        <textarea name="comment_content" class="w-full p-2 border rounded-lg bg-gray-700 text-white border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" rows="2" placeholder="Write a comment..." required></textarea>
                                        <button type="submit" class="btn-primary mt-1 relative">
                                            <span id="comment-button-text-<?php echo (int)$post['id']; ?>">Comment</span>
                                            <svg id="comment-spinner-<?php echo (int)$post['id']; ?>" class="hidden animate-spin h-5 w-5 text-white absolute right-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                            </svg>
                                        </button>
                                    </form>
                                    <?php foreach ($comments as $comment): ?>
                                        <?php if ($comment['post_id'] == $post['id']): ?>
                                            <div class="comment-card mb-2 p-2">
                                                <div class="flex items-center mb-1">
                                                    <a href="view_profile.php?user_id=<?php echo (int)$comment['user_id']; ?>">
                                                        <img src="<?php echo getProfilePicture($comment['profile_picture'] ?? null); ?>" class="w-8 h-8 rounded-full mr-2 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                                                    </a>
                                                    <a href="view_profile.php?user_id=<?php echo (int)$comment['user_id']; ?>" class="font-semibold text-blue-400 hover:underline"><?php echo htmlspecialchars(($comment['first_name'] ?? '') . ' ' . ($comment['last_name'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></a>
                                                </div>
                                                <p class="text-gray-200"><?php echo htmlspecialchars($comment['content'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
                                                <p class="text-gray-400 text-sm"><?php echo date('M d, Y H:i', strtotime($comment['created_at'] ?? 'now')); ?></p>
                                            </div>
                                        <?php endif; ?>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Right Sidebar -->
        <div class="w-full md:w-1/4 md:block">
            <!-- Suggested Connections -->
            <div class="card mb-6 sticky top-4">
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
                            <form method="POST" action="index.php" id="connect-form-<?php echo (int)$conn['id']; ?>">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                <input type="hidden" name="connect_user_id" value="<?php echo (int)$conn['id']; ?>">
                                <button type="submit" class="btn-secondary text-sm px-3 py-1 relative">
                                    <i class="fas fa-user-plus mr-2"></i>
                                    <span class="connect-button-text">Connect</span>
                                    <svg class="hidden animate-spin h-5 w-5 text-white absolute right-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                </button>
                            </form>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <!-- Messages -->
            <div class="card">
                <h2 class="text-xl font-semibold mb-4">Messages</h2>
                <?php if (empty($messages_data)): ?>
                    <p class="text-gray-200">No recent messages. Start a conversation!</p>
                    <a href="chat.php" class="btn-primary mt-4 block text-center">Go to Messaging</a>
                <?php else: ?>
                    <?php foreach ($messages_data as $msg): ?>
                        <a href="chat.php?recipient_id=<?php echo (int)($msg['sender_id'] == $user_id ? $msg['receiver_id'] : $msg['sender_id']); ?>" class="block">
                            <div class="message-card mb-2 p-2">
                                <div class="flex items-center mb-1">
                                    <img src="<?php echo getProfilePicture($msg['profile_picture']); ?>" class="w-8 h-8 rounded-full mr-2 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                                    <div class="flex items-center">
                                        <span class="font-semibold text-blue-400"><?php echo htmlspecialchars(($msg['first_name'] ?? '') . ' ' . ($msg['last_name'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></span>
                                        <?php if ($msg['is_online'] ?? 0): ?>
                                            <span class="ml-2 w-2 h-2 bg-green-500 rounded-full" title="Online"></span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <p class="text-gray-200"><?php echo htmlspecialchars(substr($msg['content'] ?? '', 0, 50) . (strlen($msg['content'] ?? '') > 50 ? '...' : ''), ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="text-gray-400 text-sm"><?php echo date('M d, Y H:i', strtotime($msg['sent_at'] ?? 'now')); ?></p>
                            </div>
                        </a>
                    <?php endforeach; ?>
                    <a href="chat.php" class="btn-primary mt-4 block text-center">View All Messages</a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        // Media Tabs
        const tabs = document.querySelectorAll('.media-tab');
        const contents = document.querySelectorAll('.media-content');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                contents.forEach(c => c.classList.add('hidden'));
                document.querySelector(`.${tab.dataset.tab}-content`).classList.remove('hidden');
            });
        });

        // Media Preview
        const imageInput = document.getElementById('image');
        const videoInput = document.getElementById('video');
        const imagePreview = document.getElementById('image-preview');
        const videoPreview = document.getElementById('video-preview');

        if (imageInput && imagePreview) {
            imageInput.addEventListener('change', function() {
                const file = this.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        imagePreview.src = e.target.result;
                        imagePreview.parentElement.classList.remove('hidden');
                    };
                    reader.readAsDataURL(file);
                }
            });
        }

        if (videoInput && videoPreview) {
            videoInput.addEventListener('change', function() {
                const file = this.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        videoPreview.src = e.target.result;
                        videoPreview.parentElement.classList.remove('hidden');
                    };
                    reader.readAsDataURL(file);
                }
            });
        }

        // Toggle Comments
        function toggleComments(postId) {
            const commentSection = document.getElementById(`comments-${postId}`);
            if (commentSection) {
                commentSection.classList.toggle('hidden');
            }
        }

        // Loading spinner for form submissions
        document.addEventListener('DOMContentLoaded', () => {
            const postForm = document.getElementById('post-form');
            if (postForm) {
                postForm.addEventListener('submit', () => {
                    const buttonText = document.getElementById('post-button-text');
                    const spinner = document.getElementById('post-spinner');
                    if (buttonText && spinner) {
                        buttonText.classList.add('opacity-0');
                        spinner.classList.remove('hidden');
                    }
                });
            }

            document.querySelectorAll('form[id^="comments-"]').forEach(form => {
                form.addEventListener('submit', () => {
                    const postId = form.querySelector('input[name="comment_post_id"]').value;
                    const buttonText = document.getElementById(`comment-button-text-${postId}`);
                    const spinner = document.getElementById(`comment-spinner-${postId}`);
                    if (buttonText && spinner) {
                        buttonText.classList.add('opacity-0');
                        spinner.classList.remove('hidden');
                    }
                });
            });

            // Loading spinner for connect forms
            document.querySelectorAll('form[id^="connect-form-"]').forEach(form => {
                form.addEventListener('submit', () => {
                    const button = form.querySelector('button');
                    const buttonText = button.querySelector('.connect-button-text');
                    const spinner = button.querySelector('.animate-spin');
                    if (buttonText && spinner) {
                        buttonText.classList.add('opacity-0');
                        spinner.classList.remove('hidden');
                    }
                });
            });
        });
    </script>
    <?php include 'includes/footer.php'; ?>
</body>
</html>