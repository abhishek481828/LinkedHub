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

// Get project ID from URL
$project_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($project_id <= 0) {
    error_log("Invalid project ID: $project_id");
    header("Location: repositories.php");
    exit;
}

// Fetch project details
try {
    $stmt = $pdo->prepare("SELECT * FROM projects WHERE id = ? AND user_id = ?");
    $stmt->execute([$project_id, (int)$_SESSION['user_id']]);
    $project = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$project) {
        error_log("Project not found for ID: $project_id, user_id: {$_SESSION['user_id']}");
        $messages[] = "<p class='text-red-500 text-center'>Project not found or you don't have access.</p>";
        include 'includes/footer.php';
        exit;
    }
} catch (PDOException $e) {
    error_log("Database error: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center'>Error loading project: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
    include 'includes/footer.php';
    exit;
}

// Determine how to open the project
$open_project_action = '';
$open_project_label = 'Open Project';
$open_project_disabled = false;

if (!empty($project['project_url'])) {
    // If project_url exists, redirect to it
    $open_project_action = htmlspecialchars($project['project_url'], ENT_QUOTES, 'UTF-8');
} elseif (!empty($project['file_path']) && file_exists($project['file_path'])) {
    // If file_path exists, serve the file based on its type
    $file_ext = strtolower(pathinfo($project['file_path'], PATHINFO_EXTENSION));
    $viewable_extensions = ['html', 'txt', 'pdf', 'php', 'js', 'css', 'py'];
    
    if (in_array($file_ext, $viewable_extensions)) {
        // For viewable files, link to the file path or a viewer script
        $open_project_action = htmlspecialchars($project['file_path'], ENT_QUOTES, 'UTF-8');
        if ($file_ext === 'pdf') {
            $open_project_label = 'View PDF';
        } elseif ($file_ext === 'html' || $file_ext === 'php') {
            $open_project_label = 'View Page';
        } else {
            $open_project_label = 'View File';
        }
    } else {
        // For non-viewable files (e.g., zip), link to download
        $open_project_action = htmlspecialchars($project['file_path'], ENT_QUOTES, 'UTF-8');
        $open_project_label = 'Download Project';
    }
} else {
    // No URL or file available
    $open_project_disabled = true;
    $open_project_label = 'No Project Available';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Project Details - <?php echo htmlspecialchars($project['name'], ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" />
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
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
        }
        .btn-primary:hover:not(.disabled) {
            background: #1e40af;
            transform: scale(1.05);
        }
        .btn-primary.disabled {
            background: #6b7280;
            cursor: not-allowed;
        }
    </style>
</head>
<body class="bg-gray-800 font-sans">
    <div class="max-w-4xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <div class="card">
            <h2 class="mb-6 text-2xl">Project: <?php echo htmlspecialchars($project['name'], ENT_QUOTES, 'UTF-8'); ?></h2>
            <?php if (!empty($messages)): ?>
                <div class="mb-6">
                    <?php foreach ($messages as $msg): ?>
                        <?php echo $msg; ?>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <div class="mb-4">
                <h3 class="text-lg font-medium text-gray-100">Description</h3>
                <p class="text-gray-200"><?php echo htmlspecialchars($project['description'] ?: 'No description', ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
            <div class="mb-4">
                <h3 class="text-lg font-medium text-gray-100">Language</h3>
                <p class="text-gray-200"><?php echo htmlspecialchars($project['language'] ?: 'Not specified', ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
            <?php if (!empty($project['project_url'])): ?>
                <div class="mb-4">
                    <h3 class="text-lg font-medium text-gray-100">Project URL</h3>
                    <a href="<?php echo htmlspecialchars($project['project_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" class="text-blue-400 hover:underline"><?php echo htmlspecialchars($project['project_url'], ENT_QUOTES, 'UTF-8'); ?></a>
                </div>
            <?php endif; ?>
            <?php if (!empty($project['file_path']) && file_exists($project['file_path'])): ?>
                <div class="mb-4">
                    <h3 class="text-lg font-medium text-gray-100">Project File</h3>
                    <a href="<?php echo htmlspecialchars($project['file_path'], ENT_QUOTES, 'UTF-8'); ?>" download class="text-blue-400 hover:underline">
                        <i class="fas fa-download mr-1"></i>Download File
                    </a>
                </div>
            <?php endif; ?>
            <div class="mb-4">
                <h3 class="text-lg font-medium text-gray-100">Added On</h3>
                <p class="text-gray-200"><?php echo date('M d, Y', strtotime($project['created_at'] ?? 'now')); ?></p>
            </div>
            <div class="flex space-x-4">
                <a href="repositories.php" class="btn-primary"><i class="fas fa-arrow-left mr-2"></i>Back to Repositories</a>
                <?php if ($open_project_action): ?>
                    <a href="<?php echo $open_project_action; ?>" 
                       class="btn-primary" 
                       <?php echo !empty($project['project_url']) ? 'target="_blank"' : ''; ?>>
                        <i class="fas fa-external-link-alt mr-2"></i><?php echo $open_project_label; ?>
                    </a>
                <?php else: ?>
                    <span class="btn-primary disabled"><i class="fas fa-ban mr-2"></i><?php echo $open_project_label; ?></span>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php include 'includes/footer.php'; ?>
</body>
</html>