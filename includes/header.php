<?php
// Start session only if not already active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkedHub</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="css/styles.css">
    <style>
        nav.navbar {
            background-color: #1f2937 !important; /* Gray-800 for professional look */
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        nav.navbar.fallback {
            background-color: #374151 !important; /* Fallback gray-700 */
        }
        .nav-link {
            color: #e5e7eb; /* Gray-200 */
            transition: color 0.2s;
            padding: 0 12px;
        }
        .nav-link:hover {
            color: #ffffff; /* White */
        }
        .nav-icon {
            margin-right: 0;
        }
        .container {
            background-color: #111827; /* Gray-900 */
            max-width: 1536px; /* max-w-8xl */
            margin-left: auto;
            margin-right: auto;
        }
    </style>
</head>
<body class="bg-gray-800 font-sans">
    <nav class="navbar shadow-md sticky top-0 z-10">
        <div class="container px-4 py-3 flex items-center justify-between">
            <a href="index.php" class="text-2xl font-bold text-gray-200"><i class="fas fa-briefcase nav-icon"></i>LinkedHub</a>
            <div class="flex items-center space-x-8">
                <?php if (isset($_SESSION['user_id'])): ?>
                    <a href="index.php" class="nav-link"><i class="fas fa-home nav-icon"></i></a>
                    <a href="connections.php" class="nav-link"><i class="fas fa-users nav-icon"></i></a>
                    <a href="chat.php" class="nav-link"><i class="fas fa-comments nav-icon"></i></a>
                    <a href="repositories.php" class="nav-link"><i class="fas fa-folder-open nav-icon"></i></a>
                    <a href="profile.php" class="nav-link"><i class="fas fa-user nav-icon"></i></a>
                    <a href="logout.php" class="nav-link"><i class="fas fa-sign-out-alt nav-icon"></i></a>
                <?php else: ?>
                    <a href="login.php" class="nav-link"><i class="fas fa-sign-in-alt nav-icon"></i></a>
                    <a href="register.php" class="nav-link"><i class="fas fa-user-plus nav-icon"></i></a>
                <?php endif; ?>
            </div>
        </div>
    </nav>
    <div class="container px-4 py-6">