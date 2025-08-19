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
$view_user_id = filter_var($_GET['user_id'] ?? 0, FILTER_SANITIZE_NUMBER_INT);

if ($view_user_id <= 0) {
    error_log("Invalid user ID provided: $view_user_id");
    echo "<p class='text-red-500 text-center'>Invalid user ID.</p>";
    include 'includes/footer.php';
    exit;
}

// Fetch user data
try {
    $stmt = $pdo->prepare("SELECT first_name, last_name, headline, profile_picture, about, github_username FROM users WHERE id = ?");
    $stmt->execute([$view_user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        error_log("User not found for ID: $view_user_id");
        echo "<p class='text-red-500 text-center'>User not found.</p>";
        include 'includes/footer.php';
        exit;
    }
} catch (PDOException $e) {
    error_log("User fetch error: " . $e->getMessage());
    echo "<p class='text-red-500 text-center'>Error loading profile.</p>";
    include 'includes/footer.php';
    exit;
}

// Fetch education, experience, and projects
$education = [];
$experience = [];
$projects = [];
try {
    $edu_stmt = $pdo->prepare("SELECT * FROM education WHERE user_id = ? ORDER BY start_year DESC");
    $edu_stmt->execute([$view_user_id]);
    $education = $edu_stmt->fetchAll(PDO::FETCH_ASSOC);

    $exp_stmt = $pdo->prepare("SELECT * FROM experience WHERE user_id = ? ORDER BY start_date DESC");
    $exp_stmt->execute([$view_user_id]);
    $experience = $exp_stmt->fetchAll(PDO::FETCH_ASSOC);

    $proj_stmt = $pdo->prepare("SELECT id, name, description, language, project_url, file_path, created_at FROM projects WHERE user_id = ? ORDER BY created_at DESC");
    $proj_stmt->execute([$view_user_id]);
    $projects = $proj_stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Profile details fetch error: " . $e->getMessage());
    echo "<p class='text-red-500 text-center'>Error loading profile details.</p>";
}

// Helper function for profile pictures
function getProfilePicture($path) {
    $default = 'Uploads/default.jpg';
    $path = trim($path ?? '');
    return (file_exists($path) && !empty($path)) ? htmlspecialchars($path, ENT_QUOTES, 'UTF-8') : htmlspecialchars($default, ENT_QUOTES, 'UTF-8');
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name'], ENT_QUOTES, 'UTF-8'); ?>'s Profile</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" />
    <style>
    .card {
        background: linear-gradient(to bottom, #374151, #1f2937);
        color: white;
        border-radius: 1rem;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
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
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        cursor: pointer;
    }

    .btn-primary:hover {
        background: #1e40af;
        transform: scale(1.05);
    }

    .repo-card {
        background: linear-gradient(to bottom, #4b5563, #374151);
        border-radius: 0.75rem;
        border: 1px solid #4b5563;
        padding: 0.75rem;
        margin-bottom: 0.5rem;
        transition: transform 0.2s;
    }

    .repo-card:hover {
        transform: scale(1.02);
    }

    h2, h3 {
        font-family: 'Georgia', serif;
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

    .repo-description {
        display: -webkit-box;
        /* -webkit-line-clamp: 2; */
        -webkit-box-orient: vertical;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    .repo-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 0.75rem;
    }

    .repo-meta span {
        display: flex;
        align-items: center;
    }

    .repo-meta svg,
    .repo-meta i {
        margin-right: 0.25rem;
    }
</style>

</head>
<body class="bg-gray-800 font-sans">
    <!-- Mobile Sidebar Toggle -->
    <button id="sidebar-toggle" class="sm:hidden fixed top-16 left-4 z-50 bg-blue-900 text-white p-2 rounded-full">
        <i class="fas fa-bars"></i>
    </button>

    <div class="max-w-4xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <!-- Profile Section -->
        <div class="card mb-8 animate__animated animate__fadeIn">
            <h2 class="mb-6">Profile</h2>
            <div class="flex items-center mb-6">
                <img src="<?php echo getProfilePicture($user['profile_picture']); ?>" class="w-20 h-20 rounded-full mr-4 object-cover" alt="Profile" onerror="this.src='Uploads/default.jpg'">
                <div>
                    <h3 class="font-medium text-blue-400 text-lg"><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p class="text-gray-200 text-sm"><?php echo htmlspecialchars($user['headline'] ?: 'No headline', ENT_QUOTES, 'UTF-8'); ?></p>
                    <?php if ($user['github_username']): ?>
                        <a href="https://github.com/<?php echo htmlspecialchars($user['github_username'], ENT_QUOTES, 'UTF-8'); ?>" class="text-blue-400 text-sm hover:underline" target="_blank"><i class="fab fa-github mr-1"></i>GitHub</a>
                    <?php endif; ?>
                </div>
            </div>
            <p class="text-gray-200 text-sm sm:text-base"><?php echo htmlspecialchars($user['about'] ?: 'No about info', ENT_QUOTES, 'UTF-8'); ?></p>
            <?php if ($user_id !== (int)$view_user_id): ?>
                <a href="repositories.php?user_id=<?php echo (int)$view_user_id; ?>" class="btn-primary mt-4"><i class="fas fa-code mr-2"></i>View Repositories</a>
            <?php endif; ?>
        </div>

        <!-- Education Section -->
        <div class="card mb-8 animate__animated animate__fadeIn">
            <h3 class="mb-4 text-gray-100">Education</h3>
            <?php if (empty($education)): ?>
                <p class="text-gray-200 text-sm sm:text-base">No education added.</p>
            <?php else: ?>
                <?php foreach ($education as $edu): ?>
                    <div class="mb-6">
                        <p class="font-semibold text-gray-100"><?php echo htmlspecialchars($edu['school'], ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-200 text-sm"><?php echo htmlspecialchars($edu['degree'] . ', ' . $edu['field'], ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-400 text-sm"><?php echo htmlspecialchars($edu['start_year'] . ' - ' . $edu['end_year'], ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Experience Section -->
        <div class="card mb-8 animate__animated animate__fadeIn">
            <h3 class="mb-4 text-gray-100">Experience</h3>
            <?php if (empty($experience)): ?>
                <p class="text-gray-200 text-sm sm:text-base">No experience added.</p>
            <?php else: ?>
                <?php foreach ($experience as $exp): ?>
                    <div class="mb-6">
                        <p class="font-semibold text-gray-100"><?php echo htmlspecialchars($exp['title'] . ' at ' . $exp['company'], ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-400 text-sm"><?php echo htmlspecialchars($exp['start_date'] . ' - ' . ($exp['end_date'] ?: 'Present'), ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-400 text-sm"><?php echo htmlspecialchars($exp['location'], ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="text-gray-200 text-sm"><?php echo htmlspecialchars($exp['description'], ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Projects Section -->
        <div class="card animate__animated animate__fadeIn">
            <h3 class="mb-4 text-gray-100">Projects</h3>
            <?php if (empty($projects)): ?>
                <p class="text-gray-200 text-sm sm:text-base">No projects added.</p>
            <?php else: ?>
                <?php foreach ($projects as $project): ?>
                    <div class="project-card">
                        <div class="flex items-center mb-2">
                            <a href="project_details.php?id=<?php echo (int)$project['id']; ?>" class="font-medium text-blue-400 text-sm"><?php echo htmlspecialchars($project['name'], ENT_QUOTES, 'UTF-8'); ?></a>
                        </div>
                        <p class="project-description text-gray-100 text-sm mb-2"><?php echo htmlspecialchars($project['description'] ?: 'No description', ENT_QUOTES, 'UTF-8'); ?></p>
                        <?php if (!empty($project['file_path']) && file_exists($project['file_path'])): ?>
                            <p class="mb-2">
                                <a href="<?php echo htmlspecialchars($project['file_path'], ENT_QUOTES, 'UTF-8'); ?>" download class="text-blue-400 text-sm hover:underline">
                                    <i class="fas fa-download mr-1"></i>Download Project File
                                </a>
                            </p>
                        <?php endif; ?>
                        <div class="project-meta text-gray-400 text-xs">
                            <?php if (!empty($project['language'])): ?>
                                <span><?php echo htmlspecialchars($project['language'], ENT_QUOTES, 'UTF-8'); ?></span>
                            <?php endif; ?>
                            <?php if (!empty($project['project_url'])): ?>
                                <span><a href="<?php echo htmlspecialchars($project['project_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" class="text-blue-400 hover:underline">View Project</a></span>
                            <?php endif; ?>
                            <span>Added <?php echo date('M d, Y', strtotime($project['created_at'] ?? 'now')); ?></span>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <script>
        // Mobile Sidebar Toggle
        document.addEventListener('DOMContentLoaded', () => {
            const toggleButton = document.getElementById('sidebar-toggle');
            if (toggleButton) {
                toggleButton.addEventListener('click', () => {
                    console.log('Sidebar toggle clicked');
                });
            }
        });
    </script>
    <?php include 'includes/footer.php'; ?>
</body>
</html>