<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
$messages = [];

// Include database connection
try {
    require_once 'includes/db_connect.php';
} catch (Exception $e) {
    error_log("Failed to include db_connect.php: " . $e->getMessage());
    $messages[] = "<p class='text-red-500 text-center'>Server error: Unable to connect to database.</p>";
}

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    error_log("CSRF Token generated: {$_SESSION['csrf_token']}");
}
$csrf_token = $_SESSION['csrf_token'];

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
        $password = $_POST['password'] ?? '';

        if (empty($email) || empty($password)) {
            $messages[] = "<p class='text-red-500 text-center'>Email and password are required.</p>";
        } else {
            try {
                $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
                $stmt->execute([$email]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($user && password_verify($password, $user['password'])) {
                    // Regenerate session ID to prevent session fixation
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $user['id'];
                    error_log("Login successful for user_id: {$user['id']}, email: $email");
                    // Regenerate CSRF token
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    header("Location: index.php");
                    exit;
                } else {
                    error_log("Login failed for email: $email");
                    $messages[] = "<p class='text-red-500 text-center'>Invalid email or password.</p>";
                }
            } catch (PDOException $e) {
                error_log("Database error during login: " . $e->getMessage());
                $messages[] = "<p class='text-red-500 text-center'>Database error. Please try again later.</p>";
            }
        }
    }
}

// Include header
// try {
//     require_once 'includes/header.php';
// } catch (Exception $e) {
//     error_log("Failed to include header.php: " . $e->getMessage());
//     $messages[] = "<p class='text-red-500 text-center'>Server error: Unable to load header.</p>";
// }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" />
    <style>
        body {
            background: linear-gradient(to bottom, #1f2937, #111827);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: linear-gradient(to bottom, #374151, #1f2937);
            color: white;
            border-radius: 1rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            padding: 2rem;
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
            font-weight: 500;
        }
        .btn-primary:hover {
            background: #1e40af;
            transform: scale(1.05);
        }
        .input-field {
            background: #4b5563;
            color: white;
            border: 1px solid #6b7280;
            padding: 0.75rem;
            border-radius: 0.5rem;
            width: 100%;
            transition: border-color 0.3s;
        }
        .input-field:focus {
            outline: none;
            border-color: #1e40af;
            box-shadow: 0 0 0 3px rgba(30, 64, 175, 0.2);
        }
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body class="font-sans">
    <div class="max-w-md mx-auto p-4">
        <div class="card animate__animated animate__fadeIn">
            <h2 class="text-3xl font-bold text-center mb-6 text-gray-100">Sign In</h2>
            <?php if (!empty($messages)): ?>
                <div class="mb-6">
                    <?php foreach ($messages as $msg): ?>
                        <?php echo $msg; ?>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <form method="POST" id="login-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                <div class="mb-4">
                    <label for="email" class="block text-gray-200 font-medium mb-2">Email</label>
                    <input type="email" name="email" id="email" class="input-field" required placeholder="you@example.com">
                </div>
                <div class="mb-6">
                    <label for="password" class="block text-gray-200 font-medium mb-2">Password</label>
                    <input type="password" name="password" id="password" class="input-field" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn-primary w-full relative">
                    <i class="fas fa-sign-in-alt mr-2"></i>
                    <span id="login-button-text">Sign In</span>
                    <svg id="login-spinner" class="hidden animate-spin h-5 w-5 text-white absolute right-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                </button>
            </form>
            <div class="mt-4 text-center">
                <a href="forgot_password.php" class="text-blue-400 hover:underline text-sm">Forgot Password?</a>
            </div>
            <div class="mt-2 text-center">
                <p class="text-gray-200 text-sm">Don't have an account? <a href="signup.php" class="text-blue-400 hover:underline">Sign Up</a></p>
            </div>
        </div>
    </div>

    <script>
        // Form submission spinner
        document.addEventListener('DOMContentLoaded', () => {
            const loginForm = document.getElementById('login-form');
            if (loginForm) {
                loginForm.addEventListener('submit', () => {
                    const buttonText = document.getElementById('login-button-text');
                    const spinner = document.getElementById('login-spinner');
                    if (buttonText && spinner) {
                        buttonText.classList.add('opacity-0');
                        spinner.classList.remove('hidden');
                    }
                });
            }
        });
    </script>

    <?php
    try {
        require_once 'includes/footer.php';
    } catch (Exception $e) {
        error_log("Failed to include footer.php: " . $e->getMessage());
        echo "<footer class='text-gray-200 text-center py-4'>© 2025 Your Project</footer>";
    }
    ?>
</body>
</html>