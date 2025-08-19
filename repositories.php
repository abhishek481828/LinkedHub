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
error_log("Processing repositories for user_id: $user_id");

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    error_log("CSRF Token generated: {$_SESSION['csrf_token']}");
}
$csrf_token = $_SESSION['csrf_token'];

// Message queue for feedback
$messages = [];

// Fetch user data
try {
    $stmt = $pdo->prepare("SELECT github_username FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        error_log("User not found for ID: $user_id");
        $messages[] = "<p class='text-red-500 text-center'>User not found.</p>";
        include 'includes/footer.php';
        exit;
    }
} catch (PDOException $e) {
    error_log("Database error: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center'>Database error. Please try again later.</p>";
    include 'includes/footer.php';
    exit;
}

// Add project
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['project_name']) && isset($_POST['csrf_token'])) {
    error_log("POST data: " . json_encode($_POST));
    
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed for user_id: $user_id, Sent: " . ($_POST['csrf_token'] ?? 'none') . ", Expected: {$_SESSION['csrf_token']}");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $name = filter_var(trim($_POST['project_name'] ?? ''), FILTER_SANITIZE_STRING);
        $description = filter_var(trim($_POST['project_description'] ?? ''), FILTER_SANITIZE_STRING);
        $language = filter_var(trim($_POST['project_language'] ?? ''), FILTER_SANITIZE_STRING);
        $project_url = filter_var(trim($_POST['project_url'] ?? ''), FILTER_SANITIZE_URL) ?: null;
        $file_path = null;

        // Handle project file upload
        if (isset($_FILES['project_file']) && $_FILES['project_file']['error'] === UPLOAD_ERR_OK) {
            $allowed_exts = ['zip', 'pdf', 'txt', 'php', 'js', 'py', 'html', 'css'];
            $max_size = 10 * 1024 * 1024; // 10MB
            $file_ext = strtolower(pathinfo($_FILES['project_file']['name'], PATHINFO_EXTENSION));
            $file_size = $_FILES['project_file']['size'];

            if (!in_array($file_ext, $allowed_exts)) {
                error_log("Invalid file extension: $file_ext");
                $messages[] = "<p class='text-red-500 text-center'>Invalid file type. Allowed: " . implode(', ', $allowed_exts) . ".</p>";
            } elseif ($file_size > $max_size) {
                error_log("File too large: $file_size bytes");
                $messages[] = "<p class='text-red-500 text-center'>File size exceeds 10MB limit.</p>";
            } else {
                $target_dir = "Uploads/projects/";
                if (!is_dir($target_dir) && !mkdir($target_dir, 0755, true)) {
                    error_log("Failed to create projects upload directory");
                    $messages[] = "<p class='text-red-500 text-center'>Unable to create upload directory.</p>";
                } elseif (!is_writable($target_dir)) {
                    error_log("Projects upload directory not writable");
                    $messages[] = "<p class='text-red-500 text-center'>Upload directory is not writable.</p>";
                } else {
                    $target_file = $target_dir . uniqid() . '.' . $file_ext;
                    if (move_uploaded_file($_FILES['project_file']['tmp_name'], $target_file)) {
                        $file_path = $target_file;
                    } else {
                        error_log("Failed to move uploaded project file");
                        $messages[] = "<p class='text-red-500 text-center'>Failed to upload project file.</p>";
                    }
                }
            }
        }

        // Validate inputs
        if (empty($name)) {
            $messages[] = "<p class='text-red-500 text-center'>Project name is required.</p>";
        } elseif (empty($messages)) {
            try {
                $check_stmt = $pdo->query("SHOW COLUMNS FROM projects LIKE 'file_path'");
                $file_path_exists = $check_stmt->rowCount() > 0;

                if ($file_path_exists) {
                    $stmt = $pdo->prepare("INSERT INTO projects (user_id, name, description, language, project_url, file_path, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
                    $stmt->execute([$user_id, $name, $description, $language, $project_url, $file_path]);
                } else {
                    $stmt = $pdo->prepare("INSERT INTO projects (user_id, name, description, language, project_url, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
                    $stmt->execute([$user_id, $name, $description, $language, $project_url]);
                }
                $messages[] = "<p class='text-green-500 text-center'>Project added successfully!</p>";
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                header("Location: repositories.php");
                exit;
            } catch (PDOException $e) {
                error_log("Project insert error: " . $e->getMessage());
                $messages[] = "<p class='text-red-500 text-center'>Error adding project: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
            }
        }
    }
}

// Fetch user projects
try {
    $check_stmt = $pdo->query("SHOW COLUMNS FROM projects LIKE 'created_at'");
    $column_exists = $check_stmt->rowCount() > 0;

    $order_by = $column_exists ? 'created_at' : 'id';
    $proj_stmt = $pdo->prepare("SELECT * FROM projects WHERE user_id = ? ORDER BY $order_by DESC");
    $proj_stmt->execute([$user_id]);
    $projects = $proj_stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Project fetch error: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center'>Error loading projects: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
    $projects = [];
}

// Fetch GitHub repositories
$repos = [];
$github_error = '';
if (!empty($user['github_username'])) {
    $cache_key = 'github_repos_' . $user['github_username'];
    if (!isset($_SESSION[$cache_key]) || (time() - ($_SESSION[$cache_key . '_time'] ?? 0)) > 3600) {
        $url = "https://api.github.com/users/" . urlencode($user['github_username']) . "/repos?per_page=100";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'LinkedInClone/1.0');
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/vnd.github.v3+json']);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);

        if ($http_code == 200) {
            $repos = json_decode($response, true);
            $_SESSION[$cache_key] = $repos;
            $_SESSION[$cache_key . '_time'] = time();
        } else {
            error_log("GitHub API error: HTTP $http_code, Error: $curl_error, Response: $response");
            $github_error = "Unable to fetch GitHub repositories (HTTP $http_code). Please check your username or try again later.";
            $repos = [];
        }
    } else {
        $repos = $_SESSION[$cache_key];
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Repositories</title>
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
        <div class="card animate__animated animate__fadeIn">
            <h2 class="mb-6">Repositories</h2>
            <?php if (!empty($messages)): ?>
                <div class="mb-6">
                    <?php foreach ($messages as $msg): ?>
                        <?php echo $msg; ?>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <!-- Add Project Form -->
            <div class="mb-8">
                <h3 class="mb-4 text-gray-100">Add a Project</h3>
                <form method="POST" enctype="multipart/form-data" id="project-form">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                    <div class="mb-4">
                        <label for="project_name" class="block text-gray-200 font-medium mb-2">Project Name</label>
                        <input type="text" name="project_name" id="project_name" class="w-full p-4 border rounded-lg bg-gray-700 text-white text-sm sm:text-base" required>
                    </div>
                    <div class="mb-4">
                        <label for="project_description" class="block text-gray-200 font-medium mb-2">Description</label>
                        <textarea name="project_description" id="project_description" class="w-full p-4 border rounded-lg bg-gray-700 text-white text-sm sm:text-base" rows="4"></textarea>
                    </div>
                    <div class="mb-4">
                        <label for="project_language" class="block text-gray-200 font-medium mb-2">Language</label>
                        <input type="text" name="project_language" id="project_language" class="w-full p-4 border rounded-lg bg-gray-700 text-white text-sm sm:text-base" placeholder="e.g., PHP">
                    </div>
                    <div class="mb-4">
                        <label for="project_url" class="block text-gray-200 font-medium mb-2">Project URL (Optional)</label>
                        <input type="url" name="project_url" id="project_url" class="w-full p-4 border rounded-lg bg-gray-700 text-white text-sm sm:text-base" placeholder="e.g., https://github.com/your/repo">
                    </div>
                    <div class="mb-4">
                        <label for="project_file" class="block text-gray-200 font-medium mb-2">Project File (Optional, e.g., ZIP, code)</label>
                        <input type="file" name="project_file" id="project_file" class="w-full p-4 border rounded-lg bg-gray-700 text-white text-sm sm:text-base" accept=".zip,.pdf,.txt,.php,.js,.py,.html,.css">
                    </div>
                    <button type="submit" class="btn-primary relative">
                        <i class="fas fa-plus mr-2"></i>
                        <span id="project-button-text">Add Project</span>
                        <svg id="project-spinner" class="hidden animate-spin h-5 w-5 text-white absolute right-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                    </button>
                </form>
            </div>

            <!-- User Projects -->
            <h3 class="mb-4 text-gray-100">Your Projects</h3>
            <?php if (empty($projects) && empty($repos)): ?>
                <p class="text-gray-200 text-sm sm:text-base">No projects or GitHub repositories found. Add a project or update your GitHub username.</p>
                <a href="profile.php" class="btn-primary mt-4"><i class="fas fa-user mr-2"></i>Go to Profile</a>
            <?php else: ?>
                <?php foreach ($projects as $project): ?>
                    <div class="repo-card">
                        <div class="flex items-center mb-2">
                            <a href="project_details.php?id=<?php echo (int)$project['id']; ?>" class="font-medium text-blue-400 text-sm"><?php echo htmlspecialchars($project['name'], ENT_QUOTES, 'UTF-8'); ?></a>
                        </div>
                        <p class="repo-description text-gray-100 text-sm mb-2"><?php echo htmlspecialchars($project['description'] ?: 'No description', ENT_QUOTES, 'UTF-8'); ?></p>
                        <?php if (!empty($project['file_path']) && file_exists($project['file_path'])): ?>
                            <p class="mb-2">
                                <a href="<?php echo htmlspecialchars($project['file_path'], ENT_QUOTES, 'UTF-8'); ?>" download class="text-blue-400 text-sm hover:underline">
                                    <i class="fas fa-download mr-1"></i>Download Project File
                                </a>
                            </p>
                        <?php endif; ?>
                        <div class="repo-meta text-gray-400 text-xs">
                            <?php if (!empty($project['language'])): ?>
                                <span><?php echo htmlspecialchars($project['language'], ENT_QUOTES, 'UTF-8'); ?></span>
                            <?php endif; ?>
                            <?php if (!empty($project['project_url'])): ?>
                                <span><a href="<?php echo htmlspecialchars($project['project_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" class="text-blue-400 hover:underline">View Project</a></span>
                            <?php endif; ?>
                            <span>Added <?php echo date('M d, Y', strtotime($project[$column_exists ? 'created_at' : 'id'])); ?></span>
                        </div>
                    </div>
                <?php endforeach; ?>

                <!-- GitHub Repositories -->
                <?php if (!empty($user['github_username'])): ?>
                    <h3 class="mb-4 mt-6 text-gray-100">GitHub Repositories</h3>
                    <?php if ($github_error): ?>
                        <p class="text-red-500 text-sm"><?php echo htmlspecialchars($github_error, ENT_QUOTES, 'UTF-8'); ?></p>
                        <a href="profile.php" class="btn-primary mt-4"><i class="fas fa-user mr-2"></i>Update Username</a>
                    <?php elseif (empty($repos)): ?>
                        <p class="text-gray-200 text-sm sm:text-base">No GitHub repositories found. Check your username.</p>
                        <a href="profile.php" class="btn-primary mt-4"><i class="fas fa-user mr-2"></i>Update Username</a>
                    <?php else: ?>
                        <?php foreach ($repos as $repo): ?>
                            <div class="repo-card">
                                <div class="flex items-center mb-2">
                                    <a href="<?php echo htmlspecialchars($repo['html_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" class="font-medium text-blue-400 text-sm"><?php echo htmlspecialchars($repo['name'], ENT_QUOTES, 'UTF-8'); ?></a>
                                </div>
                                <p class="repo-description text-gray-100 text-sm mb-2"><?php echo htmlspecialchars($repo['description'] ?: 'No description', ENT_QUOTES, 'UTF-8'); ?></p>
                                <div class="repo-meta text-gray-400 text-xs">
                                    <?php if (!empty($repo['language'])): ?>
                                        <span><?php echo htmlspecialchars($repo['language'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php endif; ?>
                                    <span class="flex items-center">
                                        <i class="fas fa-star mr-1"></i><?php echo (int)($repo['stargazers_count'] ?? 0); ?>
                                    </span>
                                    <span class="flex items-center">
                                        <i class="fas fa-code-branch mr-1"></i><?php echo (int)($repo['forks_count'] ?? 0); ?>
                                    </span>
                                    <span>Updated <?php echo date('M d, Y', strtotime($repo['updated_at'] ?? 'now')); ?></span>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>

    <script>
        // Form Submission Spinner
        document.addEventListener('DOMContentLoaded', () => {
            const projectForm = document.getElementById('project-form');
            if (projectForm) {
                projectForm.addEventListener('submit', () => {
                    const buttonText = document.getElementById('project-button-text');
                    const spinner = document.getElementById('project-spinner');
                    if (buttonText && spinner) {
                        buttonText.classList.add('opacity-0');
                        spinner.classList.remove('hidden');
                    }
                });
            }

            // Mobile Sidebar Toggle
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