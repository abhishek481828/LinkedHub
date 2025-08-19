<?php
ob_start(); // Start output buffering
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
$messages = [];

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

// Handle signup form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed");
        $messages[] = "<p class='text-red-500 text-center'>Invalid request. Please try again.</p>";
    } else {
        $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
        $password = $_POST['password'] ?? '';
        $first_name = htmlspecialchars(strip_tags(trim($_POST['first_name'] ?? '')), ENT_QUOTES, 'UTF-8');
        $last_name = htmlspecialchars(strip_tags(trim($_POST['last_name'] ?? '')), ENT_QUOTES, 'UTF-8');
        $profile_picture = '';

        // Validate inputs
        if (empty($email) || empty($password) || empty($first_name) || empty($last_name)) {
            $messages[] = "<p class='text-red-500 text-center'>All fields are required.</p>";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $messages[] = "<p class='text-red-500 text-center'>Invalid email format.</p>";
        } elseif (strlen($password) < 8) {
            $messages[] = "<p class='text-red-500 text-center'>Password must be at least 8 characters long.</p>";
        } else {
            // Handle profile picture upload
            $target_dir = "Uploads/profiles/";
            if (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] === UPLOAD_ERR_OK) {
                $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                $max_size = 2 * 1024 * 1024; // 2MB
                $file_type = $_FILES['profile_picture']['type'];
                $file_size = $_FILES['profile_picture']['size'];
                $file_ext = strtolower(pathinfo($_FILES['profile_picture']['name'], PATHINFO_EXTENSION));
                $file_name = uniqid('profile_') . '.' . $file_ext;
                $target_file = $target_dir . $file_name;

                if (!is_dir($target_dir) && !mkdir($target_dir, 0755, true)) {
                    error_log("Failed to create directory: $target_dir");
                    $messages[] = "<p class='text-red-500 text-center'>Server error: Unable to create upload directory.</p>";
                } elseif (!in_array($file_type, $allowed_types)) {
                    $messages[] = "<p class='text-red-500 text-center'>Only JPEG, PNG, or GIF files are allowed.</p>";
                } elseif ($file_size > $max_size) {
                    $messages[] = "<p class='text-red-500 text-center'>Profile picture must be less than 2MB.</p>";
                } elseif (!move_uploaded_file($_FILES['profile_picture']['tmp_name'], $target_file)) {
                    error_log("Failed to upload profile picture: " . $_FILES['profile_picture']['name']);
                    $messages[] = "<p class='text-red-500 text-center'>Failed to upload profile picture.</p>";
                } else {
                    $profile_picture = $target_file;
                }
            } elseif (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] !== UPLOAD_ERR_NO_FILE) {
                error_log("Profile picture upload error: " . $_FILES['profile_picture']['error']);
                $messages[] = "<p class='text-red-500 text-center'>Error uploading profile picture (Code: {$_FILES['profile_picture']['error']}).</p>";
            }

            // Proceed if no validation errors
            if (empty($messages)) {
                try {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
                    $stmt->execute([$email]);
                    if ($stmt->fetchColumn() > 0) {
                        $messages[] = "<p class='text-red-500 text-center'>Email already registered.</p>";
                    } else {
                        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                        $stmt = $pdo->prepare("
                            INSERT INTO users (email, password, first_name, last_name, profile_picture, created_at) 
                            VALUES (?, ?, ?, ?, ?, NOW())
                        ");
                        $stmt->execute([$email, $hashed_password, $first_name, $last_name, $profile_picture]);
                        error_log("User registered: email=$email, first_name=$first_name");

                        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                        error_log("CSRF Token regenerated: {$_SESSION['csrf_token']}");
                        header("Location: login.php");
                        ob_end_flush();
                        exit;
                    }
                } catch (PDOException $e) {
                    error_log("Database error during signup: " . $e->getMessage());
                    $messages[] = "<p class='text-red-500 text-center'>Database error: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
                }
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - LinkedIn Clone</title>
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
        .file-input {
            background: #4b5563;
            color: white;
            border: 1px solid #6b7280;
            padding: 0.5rem;
            border-radius: 0.5rem;
            width: 100%;
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
            <h2 class="text-3xl font-bold text-center mb-6 text-gray-100">Join LinkedIn Clone</h2>
            <?php if (!empty($messages)): ?>
                <div class="mb-6">
                    <?php foreach ($messages as $msg): ?>
                        <?php echo $msg; ?>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <form method="POST" enctype="multipart/form-data" id="signup-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                <div class="mb-4">
                    <label for="email" class="block text-gray-200 font-medium mb-2">Email</label>
                    <input type="email" name="email" id="email" class="input-field" required placeholder="you@example.com">
                </div>
                <div class="mb-4">
                    <label for="first_name" class="block text-gray-200 font-medium mb-2">First Name</label>
                    <input type="text" name="first_name" id="first_name" class="input-field" required placeholder="John">
                </div>
                <div class="mb-4">
                    <label for="last_name" class="block text-gray-200 font-medium mb-2">Last Name</label>
                    <input type="text" name="last_name" id="last_name" class="input-field" required placeholder="Doe">
                </div>
                <div class="mb-4">
                    <label for="password" class="block text-gray-200 font-medium mb-2">Password</label>
                    <input type="password" name="password" id="password" class="input-field" required placeholder="••••••••">
                </div>
                <div class="mb-6">
                    <label for="profile_picture" class="block text-gray-200 font-medium mb-2">Profile Picture (Optional, JPEG/PNG/GIF, <2MB)</label>
                    <input type="file" name="profile_picture" id="profile_picture" class="file-input" accept="image/jpeg,image/png,image/gif">
                </div>
                <button type="submit" class="btn-primary w-full relative">
                    <i class="fas fa-user-plus mr-2"></i>
                    <span id="signup-button-text">Join Now</span>
                    <svg id="signup-spinner" class="hidden animate-spin h-5 w-5 text-white absolute right-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                </button>
            </form>
            <div class="mt-4 text-center">
                <p class="text-gray-200 text-sm">Already have an account? <a href="login.php" class="text-blue-400 hover:underline">Sign In</a></p>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const signupForm = document.getElementById('signup-form');
            if (signupForm) {
                signupForm.addEventListener('submit', () => {
                    const buttonText = document.getElementById('signup-button-text');
                    const spinner = document.getElementById('signup-spinner');
                    if (buttonText && spinner) {
                        buttonText.classList.add('opacity-0');
                        spinner.classList.remove('hidden');
                    }
                });
            }
        });
    </script>

</body>
</html>
<?php ob_end_flush(); ?>