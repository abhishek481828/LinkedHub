<?php
session_start();
require_once 'includes/db_connect.php';
require_once 'includes/header.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    error_log("Session user_id not set, redirecting to login");
    header("Location: login.php");
    exit;
}

$user_id = (int)$_SESSION['user_id'];
error_log("Processing profile for user_id: $user_id");

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    error_log("CSRF Token generated: {$_SESSION['csrf_token']}");
}
$csrf_token = $_SESSION['csrf_token'];

// Message queue for feedback
$messages = [];

// Helper function for profile pictures
function getProfilePicture($path) {
    $default = 'Uploads/default.jpg';
    $path = trim($path ?? '');
    if (empty($path) || !file_exists($path)) {
        error_log("Profile picture not found: $path, using default");
        return htmlspecialchars($default, ENT_QUOTES, 'UTF-8');
    }
    return htmlspecialchars($path, ENT_QUOTES, 'UTF-8');
}

// Fetch user data
try {
    $stmt = $pdo->prepare("SELECT id, first_name, last_name, headline, about, profile_picture, github_username FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        error_log("User not found for ID: $user_id");
        $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>User not found. Please log in again.</p>";
        session_destroy();
        header("Location: login.php");
        exit;
    }
    // Update session variables
    $_SESSION['first_name'] = $user['first_name'];
    $_SESSION['last_name'] = $user['last_name'];
    $_SESSION['headline'] = $user['headline'] ?? '';
    $_SESSION['profile_picture'] = $user['profile_picture'] ?? 'Uploads/default.jpg';
    $_SESSION['github_username'] = $user['github_username'] ?? '';
} catch (PDOException $e) {
    error_log("User fetch error: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Database error: Unable to fetch user data. Please try again later.</p>";
    include 'includes/footer.php';
    exit;
}

// Update profile
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['headline']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for user_id: $user_id, Sent: " . ($_POST['csrf_token'] ?? 'none') . ", Expected: {$_SESSION['csrf_token']}");
        $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Invalid request. Please try again.</p>";
    } else {
        $headline = filter_var(trim($_POST['headline'] ?? ''), FILTER_SANITIZE_STRING);
        $about = filter_var(trim($_POST['about'] ?? ''), FILTER_SANITIZE_STRING);
        $github_username = filter_var(trim($_POST['github_username'] ?? ''), FILTER_SANITIZE_STRING);
        $profile_picture = $user['profile_picture'] ?? 'Uploads/default.jpg';

        // Handle profile picture upload
        if (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] === UPLOAD_ERR_OK) {
            $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
            $max_size = 5 * 1024 * 1024; // 5MB
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $file_type = finfo_file($finfo, $_FILES['profile_picture']['tmp_name']);
            finfo_close($finfo);
            $file_size = $_FILES['profile_picture']['size'];

            $image_info = getimagesize($_FILES['profile_picture']['tmp_name']);
            if ($image_info === false) {
                error_log("Uploaded file is not a valid image for user_id: $user_id");
                $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Uploaded file is not a valid image.</p>";
            } elseif (!in_array($file_type, $allowed_types) || $file_size > $max_size) {
                error_log("Invalid file type or size for profile picture: type=$file_type, size=$file_size, user_id: $user_id");
                $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Invalid file type or size (max 5MB, JPEG/PNG/GIF).</p>";
            } else {
                $target_dir = "Uploads/";
                if (!is_dir($target_dir)) {
                    if (!mkdir($target_dir, 0755, true)) {
                        error_log("Failed to create uploads directory for user_id: $user_id");
                        $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Unable to create upload directory.</p>";
                    }
                }
                if (is_dir($target_dir) && is_writable($target_dir)) {
                    $file_ext = strtolower(pathinfo($_FILES['profile_picture']['name'], PATHINFO_EXTENSION));
                    $target_file = $target_dir . uniqid('profile_') . '.' . $file_ext;
                    if (move_uploaded_file($_FILES['profile_picture']['tmp_name'], $target_file)) {
                        $profile_picture = $target_file;
                        error_log("Profile picture uploaded successfully: $target_file for user_id: $user_id");
                    } else {
                        error_log("Failed to move uploaded profile picture for user_id: $user_id");
                        $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Failed to upload profile picture.</p>";
                    }
                } else {
                    error_log("Uploads directory not writable for user_id: $user_id");
                    $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Upload directory is not writable.</p>";
                }
            }
        }

        try {
            $stmt = $pdo->prepare("UPDATE users SET headline = ?, about = ?, profile_picture = ?, github_username = ? WHERE id = ?");
            $stmt->execute([$headline, $about, $profile_picture, $github_username, $user_id]);
            // Update session variables
            $_SESSION['headline'] = $headline;
            $_SESSION['about'] = $about;
            $_SESSION['profile_picture'] = $profile_picture;
            $_SESSION['github_username'] = $github_username;
            // Regenerate CSRF token
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
            $messages[] = "<p class='text-green-500 text-center bg-green-500/80 p-4 rounded-lg'>Profile updated successfully.</p>";
            // Ensure no output before header
            ob_start();
            header("Location: profile.php");
            ob_end_flush();
            exit;
        } catch (PDOException $e) {
            error_log("Profile update error for user_id: $user_id: " . $e->getMessage());
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error saving profile: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        }
    }
}

// Add education
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['school']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for education, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Invalid request. Please try again.</p>";
    } else {
        $school = filter_var(trim($_POST['school'] ?? ''), FILTER_SANITIZE_STRING);
        $degree = filter_var(trim($_POST['degree'] ?? ''), FILTER_SANITIZE_STRING);
        $field = filter_var(trim($_POST['field'] ?? ''), FILTER_SANITIZE_STRING);
        $start_year = filter_var(trim($_POST['start_year'] ?? ''), FILTER_SANITIZE_NUMBER_INT);
        $end_year = filter_var(trim($_POST['end_year'] ?? ''), FILTER_SANITIZE_NUMBER_INT);

        if (empty($school) || empty($degree) || empty($field) || empty($start_year) || empty($end_year)) {
            error_log("Missing education fields for user_id: $user_id");
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>All education fields are required.</p>";
        } elseif ($start_year < 1900 || $end_year > (date('Y') + 10) || $end_year < $start_year) {
            error_log("Invalid education years for user_id: $user_id, start_year: $start_year, end_year: $end_year");
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Invalid start or end year.</p>";
        } else {
            try {
                $stmt = $pdo->prepare("INSERT INTO education (user_id, school, degree, field, start_year, end_year) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$user_id, $school, $degree, $field, $start_year, $end_year]);
                // Regenerate CSRF token
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                $messages[] = "<p class='text-green-500 text-center bg-green-500/80 p-4 rounded-lg'>Education added successfully.</p>";
                ob_start();
                header("Location: profile.php");
                ob_end_flush();
                exit;
            } catch (PDOException $e) {
                error_log("Education insert error for user_id: $user_id: " . $e->getMessage());
                $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error adding education: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
            }
        }
    }
}

// Add experience
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['company']) && isset($_POST['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for experience, user_id: $user_id");
        $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Invalid request. Please try again.</p>";
    } else {
        $company = filter_var(trim($_POST['company'] ?? ''), FILTER_SANITIZE_STRING);
        $title = filter_var(trim($_POST['title'] ?? ''), FILTER_SANITIZE_STRING);
        $location = filter_var(trim($_POST['location'] ?? ''), FILTER_SANITIZE_STRING);
        $start_date = trim($_POST['start_date'] ?? '');
        $end_date = !empty(trim($_POST['end_date'] ?? '')) ? trim($_POST['end_date']) : null;
        $description = filter_var(trim($_POST['description'] ?? ''), FILTER_SANITIZE_STRING);

        if (empty($company) || empty($title) || empty($location) || empty($start_date) || empty($description)) {
            error_log("Missing experience fields for user_id: $user_id");
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Required experience fields are missing.</p>";
        } elseif (strtotime($start_date) === false || ($end_date && strtotime($end_date) === false)) {
            error_log("Invalid date format for experience for user_id: $user_id, start_date: $start_date, end_date: $end_date");
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Invalid date format.</p>";
        } elseif ($end_date && strtotime($end_date) < strtotime($start_date)) {
            error_log("End date before start date for experience for user_id: $user_id");
            $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>End date cannot be before start date.</p>";
        } else {
            try {
                $stmt = $pdo->prepare("INSERT INTO experience (user_id, company, title, location, start_date, end_date, description) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$user_id, $company, $title, $location, $start_date, $end_date, $description]);
                // Regenerate CSRF token
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                $messages[] = "<p class='text-green-500 text-center bg-green-500/80 p-4 rounded-lg'>Experience added successfully.</p>";
                ob_start();
                header("Location: profile.php");
                ob_end_flush();
                exit;
            } catch (PDOException $e) {
                error_log("Experience insert error for user_id: $user_id: " . $e->getMessage());
                $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error adding experience: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
            }
        }
    }
}

// Fetch education, experience, posts
$education = [];
$experience = [];
$posts = [];

try {
    $edu_stmt = $pdo->prepare("SELECT * FROM education WHERE user_id = ? ORDER BY start_year DESC");
    $edu_stmt->execute([$user_id]);
    $education = $edu_stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Education fetch error for user_id: $user_id: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error loading education: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}

try {
    $exp_stmt = $pdo->prepare("SELECT * FROM experience WHERE user_id = ? ORDER BY start_date DESC");
    $exp_stmt->execute([$user_id]);
    $experience = $exp_stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Experience fetch error for user_id: $user_id: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error loading experience: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}

try {
    $post_stmt = $pdo->prepare("
        SELECT p.id, p.content, p.image, p.video, p.post_type, p.created_at,
               (SELECT COUNT(*) FROM reactions r WHERE r.post_id = p.id) as reaction_count,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count,
               (SELECT COUNT(*) FROM shares s WHERE s.post_id = p.id) as share_count
        FROM posts p
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
    ");
    $post_stmt->execute([$user_id]);
    $posts = $post_stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Posts fetch error for user_id: $user_id: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center bg-red-500/80 p-4 rounded-lg'>Error loading posts: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile - LinkedIn Clone</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" />
    <style>
        html, body {
            margin: 0;
            padding: 0;
            background: linear-gradient(to bottom, #374151, #1f2937) !important;
            background-color: #1f2937 !important;
            color: #ffffff;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            min-height: 100vh;
        }
        .card {
            background: linear-gradient(to bottom, #374151, #1f2937);
            color: white;
            border-radius: 1rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            padding: 1.5rem;
            border: 2px solid #4b5563;
        }
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
        .post-card {
            background: linear-gradient(to bottom, #4b5563, #374151);
            border-radius: 1rem;
            border: 2px solid #4b5563;
            transition: transform 0.2s;
        }
        .post-card:hover {
            transform: scale(1.02);
        }
        h2, h3 {
            font-family: serif;
            font-weight: 700;
            letter-spacing: -0.025em;
        }
        h2 {
            font-size: 1.5rem;
        }
        h3 {
            font-size: 1.25rem;
        }
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        .preview-container img {
            max-height: 200px;
            max-width: 100%;
            object-fit: contain;
            border-radius: 0.5rem;
        }
        .profile-img {
            object-fit: cover;
            border: 2px solid #4b5563;
        }
        @media (max-width: 640px) {
            .card {
                padding: 1rem;
            }
            .btn-primary {
                padding: 0.5rem 1rem;
                font-size: 0.875rem;
            }
            .profile-img {
                width: 60px;
                height: 60px;
            }
            input, textarea {
                font-size: 0.875rem;
                padding: 0.75rem;
            }
        }
    </style>
</head>
<body>
    <div class="max-w-4xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <!-- Profile Section -->
        <div class="card mb-8 animate__animated animate__fadeIn">
            <h2 class="mb-6">My Profile</h2>
            <?php if (!empty($messages)): ?>
                <div class="mb-6 space-y-4">
                    <?php foreach ($messages as $msg): ?>
                        <?php echo $msg; ?>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <div class="flex items-center mb-6">
                <img src="<?php echo getProfilePicture($user['profile_picture'] ?? 'Uploads/default.jpg'); ?>" class="w-20 h-20 rounded-full mr-4 profile-img" alt="Profile Picture" onerror="this.src='Uploads/default.jpg'; console.error('Failed to load profile picture for user_id: <?php echo $user_id; ?>');">
                <div>
                    <h3 class="font-medium text-blue-400"><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p class="text-gray-200"><?php echo htmlspecialchars($user['headline'] ?: 'Add a headline', ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
            </div>
            <div class="mb-6">
                <a href="repositories.php" class="btn-primary"><i class="fas fa-code mr-2"></i>Repositories</a>
            </div>
            <form method="POST" enctype="multipart/form-data" id="profile-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                <div class="mb-4">
                    <label for="headline" class="block text-gray-200 font-medium mb-2">Headline</label>
                    <input type="text" name="headline" id="headline" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" value="<?php echo htmlspecialchars($user['headline'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" maxlength="255">
                </div>
                <div class="mb-4">
                    <label for="about" class="block text-gray-200 font-medium mb-2">About</label>
                    <textarea name="about" id="about" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" rows="5"><?php echo htmlspecialchars($user['about'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>
                </div>
                <div class="mb-4">
                    <label for="github_username" class="block text-gray-200 font-medium mb-2">GitHub Username</label>
                    <input type="text" name="github_username" id="github_username" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" value="<?php echo htmlspecialchars($user['github_username'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" placeholder="e.g., octocat" maxlength="100">
                </div>
                <div class="mb-4">
                    <label for="profile_picture" class="block text-gray-200 font-medium mb-2">Profile Picture</label>
                    <input type="file" name="profile_picture" id="profile_picture" accept="image/jpeg,image/png,image/gif" class="w-full p-4 border rounded-lg bg-gray-700 text-white">
                    <div class="preview-container mt-3 hidden">
                        <img id="image-preview" src="#" alt="Image Preview" class="rounded-lg">
                    </div>
                </div>
                <button type="submit" class="btn-primary relative">
                    <i class="fas fa-save mr-2"></i>
                    <span id="profile-button-text">Save Profile</span>
                    <svg id="profile-spinner" class="hidden animate-spin h-5 w-5 text-white absolute right-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                </button>
            </form>
        </div>

        <!-- Education Section -->
        <div class="card mb-8 animate__animated animate__fadeIn">
            <h2 class="mb-6">Education</h2>
            <?php if (empty($education)): ?>
                <p class="text-gray-200">No education added yet.</p>
            <?php else: ?>
                <?php foreach ($education as $edu): ?>
                    <div class="mb-6">
                        <p class="font-semibold text-gray-100"><?php echo htmlspecialchars($edu['school'], ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-200"><?php echo htmlspecialchars($edu['degree'] . ', ' . $edu['field'], ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-400 text-sm"><?php echo htmlspecialchars($edu['start_year'] . ' - ' . $edu['end_year'], ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
            <form method="POST" class="mt-4" id="education-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                <div class="mb-4">
                    <label for="school" class="block text-gray-200 font-medium mb-2">School</label>
                    <input type="text" name="school" id="school" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required maxlength="100">
                </div>
                <div class="mb-4">
                    <label for="degree" class="block text-gray-200 font-medium mb-2">Degree</label>
                    <input type="text" name="degree" id="degree" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required maxlength="100">
                </div>
                <div class="mb-4">
                    <label for="field" class="block text-gray-200 font-medium mb-2">Field of Study</label>
                    <input type="text" name="field" id="field" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required maxlength="100">
                </div>
                <div class="flex space-x-4 mb-4">
                    <div class="w-1/2">
                        <label for="start_year" class="block text-gray-200 font-medium mb-2">Start Year</label>
                        <input type="number" name="start_year" id="start_year" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required min="1900" max="<?php echo date('Y'); ?>">
                    </div>
                    <div class="w-1/2">
                        <label for="end_year" class="block text-gray-200 font-medium mb-2">End Year</label>
                        <input type="number" name="end_year" id="end_year" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required min="1900" max="<?php echo date('Y') + 10; ?>">
                    </div>
                </div>
                <button type="submit" class="btn-primary relative">
                    <i class="fas fa-plus mr-2"></i>
                    <span id="education-button-text">Add Education</span>
                    <svg id="education-spinner" class="hidden animate-spin h-5 w-5 text-white absolute right-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                </button>
            </form>
        </div>

        <!-- Experience Section -->
        <div class="card mb-8 animate__animated animate__fadeIn">
            <h2 class="mb-6">Experience</h2>
            <?php if (empty($experience)): ?>
                <p class="text-gray-200">No experience added yet.</p>
            <?php else: ?>
                <?php foreach ($experience as $exp): ?>
                    <div class="mb-6">
                        <p class="font-semibold text-gray-100"><?php echo htmlspecialchars($exp['title'], ENT_QUOTES, 'UTF-8'); ?> at <?php echo htmlspecialchars($exp['company'], ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-400 text-sm"><?php echo htmlspecialchars($exp['start_date'] . ' - ' . ($exp['end_date'] ?: 'Present'), ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-400 text-sm"><?php echo htmlspecialchars($exp['location'], ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-200"><?php echo htmlspecialchars($exp['description'], ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
            <form method="POST" class="mt-4" id="experience-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                <div class="mb-4">
                    <label for="company" class="block text-gray-200 font-medium mb-2">Company</label>
                    <input type="text" name="company" id="company" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required maxlength="100">
                </div>
                <div class="mb-4">
                    <label for="title" class="block text-gray-200 font-medium mb-2">Title</label>
                    <input type="text" name="title" id="title" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required maxlength="100">
                </div>
                <div class="mb-4">
                    <label for="location" class="block text-gray-200 font-medium mb-2">Location</label>
                    <input type="text" name="location" id="location" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required maxlength="100">
                </div>
                <div class="flex space-x-4 mb-4">
                    <div class="w-1/2">
                        <label for="start_date" class="block text-gray-200 font-medium mb-2">Start Date</label>
                        <input type="date" name="start_date" id="start_date" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="w-1/2">
                        <label for="end_date" class="block text-gray-200 font-medium mb-2">End Date (Leave blank if current)</label>
                        <input type="date" name="end_date" id="end_date" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                </div>
                <div class="mb-4">
                    <label for="description" class="block text-gray-200 font-medium mb-2">Description</label>
                    <textarea name="description" id="description" class="w-full p-4 border rounded-lg bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" rows="5" required></textarea>
                </div>
                <button type="submit" class="btn-primary relative">
                    <i class="fas fa-plus mr-2"></i>
                    <span id="experience-button-text">Add Experience</span>
                    <svg id="experience-spinner" class="hidden animate-spin h-5 w-5 text-white absolute right-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                </button>
            </form>
        </div>

        <!-- Posts Section -->
        <div class="card animate__animated animate__fadeIn">
            <h2 class="mb-6">My Posts</h2>
            <?php if (empty($posts)): ?>
                <p class="text-gray-200">No posts yet.</p>
            <?php else: ?>
                <?php foreach ($posts as $post): ?>
                    <div class="post-card mb-8 p-4">
                        <div class="flex items-center mb-4">
                            <img src="<?php echo getProfilePicture($user['profile_picture']); ?>" class="w-12 h-12 rounded-full mr-4 profile-img" alt="Profile Picture" onerror="this.src='Uploads/default.jpg'; console.error('Failed to load profile picture for post_id: <?php echo $post['id']; ?>');">
                            <div>
                                <p class="font-medium text-blue-400"><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="text-gray-400 text-sm"><?php echo date('M d, Y H:i', strtotime($post['created_at'] ?? 'now')); ?></p>
                            </div>
                        </div>
                        <p class="mb-4 text-gray-100"><?php echo htmlspecialchars($post['content'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
                        <?php if (!empty($post['image']) && file_exists($post['image'])): ?>
                            <img src="<?php echo htmlspecialchars($post['image'], ENT_QUOTES, 'UTF-8'); ?>" class="w-full max-h-96 rounded-lg mb-4 object-cover" alt="Post Image" onerror="console.error('Failed to load post image for post_id: <?php echo $post['id']; ?>');">
                        <?php endif; ?>
                        <?php if (!empty($post['video']) && file_exists($post['video'])): ?>
                            <video controls class="w-full max-h-96 rounded-lg mb-4">
                                <source src="<?php echo htmlspecialchars($post['video'], ENT_QUOTES, 'UTF-8'); ?>" type="video/mp4">
                                Your browser does not support the video tag.
                            </video>
                        <?php endif; ?>
                        <div class="flex justify-between text-gray-200 text-sm mb-4">
                            <span><?php echo (int)($post['reaction_count'] ?? 0); ?> Reactions</span>
                            <span><?php echo (int)($post['comment_count'] ?? 0); ?> Comments</span>
                            <span><?php echo (int)($post['share_count'] ?? 0); ?> Shares</span>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            try {
                // Profile Picture Preview
                const imageInput = document.getElementById('profile_picture');
                const imagePreview = document.getElementById('image-preview');
                if (imageInput && imagePreview) {
                    imageInput.addEventListener('change', function() {
                        try {
                            const file = this.files[0];
                            if (file) {
                                const reader = new FileReader();
                                reader.onload = function(e) {
                                    imagePreview.src = e.target.result;
                                    imagePreview.parentElement.classList.remove('hidden');
                                    console.log('Profile picture preview updated');
                                };
                                reader.onerror = function(e) {
                                    console.error('Error reading profile picture file:', e);
                                    alert('Failed to preview image.');
                                };
                                reader.readAsDataURL(file);
                            } else {
                                console.warn('No file selected for profile picture');
                            }
                        } catch (e) {
                            console.error('Profile picture preview error:', e);
                        }
                    });
                } else {
                    console.warn('Profile picture input or preview element missing');
                }

                // Form Submission Spinners
                const profileForm = document.getElementById('profile-form');
                if (profileForm) {
                    profileForm.addEventListener('submit', () => {
                        try {
                            const buttonText = document.getElementById('profile-button-text');
                            const spinner = document.getElementById('profile-spinner');
                            if (buttonText && spinner) {
                                buttonText.classList.add('opacity-0');
                                spinner.classList.remove('hidden');
                                console.log('Profile form submitted, showing spinner');
                            }
                        } catch (e) {
                            console.error('Profile form submit error:', e);
                        }
                    });
                } else {
                    console.warn('Profile form not found');
                }

                const educationForm = document.getElementById('education-form');
                if (educationForm) {
                    educationForm.addEventListener('submit', () => {
                        try {
                            const buttonText = document.getElementById('education-button-text');
                            const spinner = document.getElementById('education-spinner');
                            if (buttonText && spinner) {
                                buttonText.classList.add('opacity-0');
                                spinner.classList.remove('hidden');
                                console.log('Education form submitted, showing spinner');
                            }
                        } catch (e) {
                            console.error('Education form submit error:', e);
                        }
                    });
                } else {
                    console.warn('Education form not found');
                }

                const experienceForm = document.getElementById('experience-form');
                if (experienceForm) {
                    experienceForm.addEventListener('submit', () => {
                        try {
                            const buttonText = document.getElementById('experience-button-text');
                            const spinner = document.getElementById('experience-spinner');
                            if (buttonText && spinner) {
                                buttonText.classList.add('opacity-0');
                                spinner.classList.remove('hidden');
                                console.log('Experience form submitted, showing spinner');
                            }
                        } catch (e) {
                            console.error('Experience form submit error:', e);
                        }
                    });
                } else {
                    console.warn('Experience form not found');
                }
            } catch (e) {
                console.error('DOMContentLoaded error:', e);
                document.body.insertAdjacentHTML('beforeend', '<p class="text-red-500 text-center bg-red-500/80 p-4 rounded-lg">Error initializing page: ' + e.message + '</p>');
            }
        });
    </script>
    <?php 
    try {
        include 'includes/footer.php'; 
    } catch (Exception $e) {
        error_log("Error including footer.php: " . $e->getMessage());
        echo '<p class="text-red-500 text-center bg-red-500/80 p-4 rounded-lg">Error loading footer: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</p>';
    }
    ?>
</body>
</html>