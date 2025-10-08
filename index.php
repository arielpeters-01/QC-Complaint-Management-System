<?php
session_start();

// Database configuration - Fixed database name
define('DB_SERVER','localhost');
define('DB_USERNAME','root');
define('DB_PASSWORD','');
define('DB_NAME','qc_complaint_management_system'); // Removed spaces
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD);

// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}

// Create database if it doesn't exist
$create_db = "CREATE DATABASE IF NOT EXISTS " . DB_NAME;
if(!mysqli_query($link, $create_db)) {
    die("ERROR: Could not create database. " . mysqli_error($link));
}

// Select database
mysqli_select_db($link, DB_NAME);

// Create tables if they don't exist
$create_users_table = "
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('staff', 'admin') DEFAULT 'staff',
    phone VARCHAR(20) DEFAULT NULL,
    position VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)";

$create_complaints_table = "
CREATE TABLE IF NOT EXISTS complaints (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    attachment VARCHAR(255) DEFAULT NULL,
    status ENUM('pending', 'in-progress', 'resolved') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)";

$create_comments_table = "
CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    complaint_id INT NOT NULL,
    user_id INT NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)";

// Execute table creation queries
if(!mysqli_query($link, $create_users_table)) {
    die("ERROR: Could not create users table. " . mysqli_error($link));
}

if(!mysqli_query($link, $create_complaints_table)) {
    die("ERROR: Could not create complaints table. " . mysqli_error($link));
}

if(!mysqli_query($link, $create_comments_table)) {
    die("ERROR: Could not create comments table. " . mysqli_error($link));
}

// Create default admin user if not exists
$admin_check = "SELECT id FROM users WHERE email = 'admin@qcexpress.com'";
$admin_result = mysqli_query($link, $admin_check);
if(mysqli_num_rows($admin_result) == 0) {
    $admin_password = password_hash('admin123', PASSWORD_DEFAULT);
    $create_admin = "INSERT INTO users (full_name, email, username, password, role) VALUES ('System Administrator', 'admin@qcexpress.com', 'admin', ?, 'admin')";
    $stmt = mysqli_prepare($link, $create_admin);
    mysqli_stmt_bind_param($stmt, "s", $admin_password);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
    header('Content-Type: application/json');
    
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';
    
    switch($action) {
        case 'register':
            handleRegistration($link, $input);
            break;
        case 'login':
            handleLogin($link, $input);
            break;
        case 'logout':
            handleLogout();
            break;
        case 'get_profile':
            getUserProfile($link);
            break;
        case 'update_profile':
            updateProfile($link, $input);
            break;
        case 'check_session':
            checkSession();
            break;
        case 'submit_complaint':
            submitComplaint($link, $input);
            break;
        case 'get_complaints':
            getComplaints($link, $input);
            break;
        case 'get_complaint_details':
            getComplaintDetails($link, $input);
            break;
        case 'add_comment':
            addComment($link, $input);
            break;
        case 'update_complaint_status':
            updateComplaintStatus($link, $input);
            break;
        case 'get_dashboard_stats':
            getDashboardStats($link);
            break;
        case 'get_admin_complaints':
            getAdminComplaints($link, $input);
            break;
        default:
            echo json_encode(['success' => false, 'message' => 'Invalid action']);
    }
    exit;
}

// Registration function
function handleRegistration($link, $input) {
    $full_name = trim($input['full_name'] ?? '');
    $email = trim($input['email'] ?? '');
    $username = trim($input['username'] ?? '');
    $password = $input['password'] ?? '';
    $confirm_password = $input['confirm_password'] ?? '';
    $phone = trim($input['phone'] ?? '');
    $position = trim($input['position'] ?? '');

    
    if(empty($full_name) || empty($email) || empty($username) || empty($password) || empty($phone) || empty($position)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        return;
    }
    
    if($password !== $confirm_password) {
        echo json_encode(['success' => false, 'message' => 'Passwords do not match']);
        return;
    }
    
    if(strlen($password) < 6) {
        echo json_encode(['success' => false, 'message' => 'Password must be at least 6 characters long']);
        return;
    }
    
    if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => 'Invalid email format']);
        return;
    }

    if($phone && !preg_match('/^\+?[0-9]{7,15}$/', $phone)) {
        echo json_encode(['success' => false, 'message' => 'Invalid phone number format']);
        return;
    }

    if($position && strlen($position) > 100) {
        echo json_encode(['success' => false, 'message' => 'Position is too long']);
        return;
    }
    
    // Check if email already exists
    $check_email = "SELECT id FROM users WHERE email = ?";
    if($stmt = mysqli_prepare($link, $check_email)) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        
        if(mysqli_stmt_num_rows($stmt) > 0) {
            echo json_encode(['success' => false, 'message' => 'Email already registered']);
            mysqli_stmt_close($stmt);
            return;
        }
        mysqli_stmt_close($stmt);
    }
    
    // Check if username already exists
    $check_username = "SELECT id FROM users WHERE username = ?";
    if($stmt = mysqli_prepare($link, $check_username)) {
        mysqli_stmt_bind_param($stmt, "s", $username);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        
        if(mysqli_stmt_num_rows($stmt) > 0) {
            echo json_encode(['success' => false, 'message' => 'Username already taken']);
            mysqli_stmt_close($stmt);
            return;
        }
        mysqli_stmt_close($stmt);
    }
    
    // Hash password and insert user
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $sql = "INSERT INTO users (full_name, email, username, password, phone, position) VALUES (?, ?, ?, ?, ?, ?)";
    
    if($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "ssssss", $full_name, $email, $username, $hashed_password, $phone, $position);
        
        if(mysqli_stmt_execute($stmt)) {
            echo json_encode(['success' => true, 'message' => 'Registration successful']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Registration failed: ' . mysqli_error($link)]);
        }
        mysqli_stmt_close($stmt);
    }
}

// Login function
function handleLogin($link, $input) {
    $login_field = trim($input['username'] ?? '');
    $password = $input['password'] ?? '';
    
    if(empty($login_field) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Username/Email and password are required']);
        return;
    }
    
    $sql = "SELECT id, full_name, email, username, password, role, phone, position FROM users WHERE email = ? OR username = ?";
    if($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "ss", $login_field, $login_field);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        if($row = mysqli_fetch_assoc($result)) {
            if(password_verify($password, $row['password'])) {
                $_SESSION['user_id'] = $row['id'];
                $_SESSION['full_name'] = $row['full_name'];
                $_SESSION['email'] = $row['email'];
                $_SESSION['username'] = $row['username'];
                $_SESSION['role'] = $row['role'];
                $_SESSION['phone'] = $row['phone'];
                $_SESSION['position'] = $row['position'];
                $_SESSION['logged_in'] = true;
                
                echo json_encode([
                    'success' => true, 
                    'message' => 'Login successful',
                    'user' => [
                        'id' => $row['id'],
                        'full_name' => $row['full_name'],
                        'email' => $row['email'],
                        'username' => $row['username'],
                        'role' => $row['role'],
                        'phone' => $row['phone'],
                        'position' => $row['position']
                    ]
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Invalid password']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'User not found']);
        }
        mysqli_stmt_close($stmt);
    } else {
        echo json_encode(['success' => false, 'message' => 'Database error: ' . mysqli_error($link)]);
    }
}

// Logout function
function handleLogout() {
    session_unset();
    session_destroy();
    echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
}

// Get user profile
function getUserProfile($link) {
    if(!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'User not logged in']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $sql = "SELECT id, full_name, email, username, role, phone, position, created_at FROM users WHERE id = ?";
    
    if($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        if($row = mysqli_fetch_assoc($result)) {
            echo json_encode([
                'success' => true,
                'user' => [
                    'id' => $row['id'],
                    'full_name' => $row['full_name'],
                    'email' => $row['email'],
                    'username' => $row['username'],
                    'role' => $row['role'],
                    'phone' => $row['phone'],
                    'position' => $row['position'],
                    'member_since' => $row['created_at']
                ]
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'User not found']);
        }
        mysqli_stmt_close($stmt);
    }
}

// Update profile
function updateProfile($link, $input) {
    if(!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'User not logged in']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $full_name = trim($input['full_name'] ?? '');
    $email = trim($input['email'] ?? '');
    $username = trim($input['username'] ?? '');
    $phone = trim($input['phone'] ?? '');
    $position = trim($input['position'] ?? '');
    
    if(empty($full_name) || empty($email) || empty($username)) {
        echo json_encode(['success' => false, 'message' => 'Name, email and username are required']);
        return;
    }
    
    if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => 'Invalid email format']);
        return;
    }
    
    // Check if email exists for other users
    $check_email = "SELECT id FROM users WHERE email = ? AND id != ?";
    if($stmt = mysqli_prepare($link, $check_email)) {
        mysqli_stmt_bind_param($stmt, "si", $email, $user_id);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        
        if(mysqli_stmt_num_rows($stmt) > 0) {
            echo json_encode(['success' => false, 'message' => 'Email already taken by another user']);
            mysqli_stmt_close($stmt);
            return;
        }
        mysqli_stmt_close($stmt);
    }
    
    // Check if username exists for other users
    $check_username = "SELECT id FROM users WHERE username = ? AND id != ?";
    if($stmt = mysqli_prepare($link, $check_username)) {
        mysqli_stmt_bind_param($stmt, "si", $username, $user_id);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        
        if(mysqli_stmt_num_rows($stmt) > 0) {
            echo json_encode(['success' => false, 'message' => 'Username already taken by another user']);
            mysqli_stmt_close($stmt);
            return;
        }
        mysqli_stmt_close($stmt);
    }
    
    // Update user profile
    $sql = "UPDATE users SET full_name = ?, email = ?, username = ?, phone = ?, position = ? WHERE id = ?";
    if($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "sssssi", $full_name, $email, $username, $phone, $position, $user_id);
        
        if(mysqli_stmt_execute($stmt)) {
            $_SESSION['full_name'] = $full_name;
            $_SESSION['email'] = $email;
            $_SESSION['username'] = $username;
            $_SESSION['phone'] = $phone;
            $_SESSION['position'] = $position;
            
            echo json_encode([
                'success' => true, 
                'message' => 'Profile updated successfully',
                'user' => [
                    'full_name' => $full_name,
                    'email' => $email,
                    'username' => $username,
                    'phone' => $phone,
                    'position' => $position
                ]
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to update profile: ' . mysqli_error($link)]);
        }
        mysqli_stmt_close($stmt);
    }
}

// Submit complaint
function submitComplaint($link, $input) {
    if(!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'User not logged in']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $title = trim($input['title'] ?? '');
    $category = $input['category'] ?? '';
    $description = trim($input['description'] ?? '');
    $attachment = trim($input['attachment'] ?? '');
    
    if(empty($title) || empty($category) || empty($description)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        return;
    }
    
    $sql = "INSERT INTO complaints (user_id, title, category, description, attachment) VALUES (?, ?, ?, ?, ?)";
    if($stmt = mysqli_prepare($link, $sql)) {
        $attachment = empty($attachment) ? null : $attachment;
        mysqli_stmt_bind_param($stmt, "issss", $user_id, $title, $category, $description, $attachment);
        
        if(mysqli_stmt_execute($stmt)) {
            $complaint_id = mysqli_insert_id($link);
            echo json_encode([
                'success' => true, 
                'message' => 'Complaint submitted successfully',
                'complaint_id' => $complaint_id
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to submit complaint: ' . mysqli_error($link)]);
        }
        mysqli_stmt_close($stmt);
    }
}

// Get complaints
function getComplaints($link, $input) {
    if(!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'User not logged in']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $status_filter = $input['status'] ?? 'all';
    
    $sql = "SELECT c.*, u.full_name as user_name FROM complaints c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.user_id = ?";
    
    if($status_filter !== 'all') {
        $sql .= " AND c.status = ?";
    }
    
    $sql .= " ORDER BY c.created_at DESC";
    
    if($stmt = mysqli_prepare($link, $sql)) {
        if($status_filter !== 'all') {
            mysqli_stmt_bind_param($stmt, "is", $user_id, $status_filter);
        } else {
            mysqli_stmt_bind_param($stmt, "i", $user_id);
        }
        
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $complaints = [];
        
        while($row = mysqli_fetch_assoc($result)) {
            $complaints[] = $row;
        }
        
        echo json_encode(['success' => true, 'complaints' => $complaints]);
        mysqli_stmt_close($stmt);
    }
}

// Get complaint details
function getComplaintDetails($link, $input) {
    if(!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'User not logged in']);
        return;
    }
    
    $complaint_id = $input['complaint_id'] ?? 0;
    $user_id = $_SESSION['user_id'];
    $role = $_SESSION['role'];
    
    // Build query based on user role
    if($role === 'admin') {
        $sql = "SELECT c.*, u.full_name as user_name FROM complaints c 
                JOIN users u ON c.user_id = u.id 
                WHERE c.id = ?";
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, "i", $complaint_id);
    } else {
        $sql = "SELECT c.*, u.full_name as user_name FROM complaints c 
                JOIN users u ON c.user_id = u.id 
                WHERE c.id = ? AND c.user_id = ?";
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, "ii", $complaint_id, $user_id);
    }
    
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    if($complaint = mysqli_fetch_assoc($result)) {
        // Get comments
        $comments_sql = "SELECT cm.*, u.full_name as author_name FROM comments cm 
                        JOIN users u ON cm.user_id = u.id 
                        WHERE cm.complaint_id = ? 
                        ORDER BY cm.created_at ASC";
        $comments_stmt = mysqli_prepare($link, $comments_sql);
        mysqli_stmt_bind_param($comments_stmt, "i", $complaint_id);
        mysqli_stmt_execute($comments_stmt);
        $comments_result = mysqli_stmt_get_result($comments_stmt);
        
        $comments = [];
        while($comment = mysqli_fetch_assoc($comments_result)) {
            $comments[] = $comment;
        }
        
        $complaint['comments'] = $comments;
        echo json_encode(['success' => true, 'complaint' => $complaint]);
        
        mysqli_stmt_close($comments_stmt);
    } else {
        echo json_encode(['success' => false, 'message' => 'Complaint not found']);
    }
    
    mysqli_stmt_close($stmt);
}

// Add comment
function addComment($link, $input) {
    if(!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'User not logged in']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $complaint_id = $input['complaint_id'] ?? 0;
    $comment = trim($input['comment'] ?? '');
    
    if(empty($comment)) {
        echo json_encode(['success' => false, 'message' => 'Comment cannot be empty']);
        return;
    }
    
    $sql = "INSERT INTO comments (complaint_id, user_id, comment) VALUES (?, ?, ?)";
    if($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "iis", $complaint_id, $user_id, $comment);
        
        if(mysqli_stmt_execute($stmt)) {
            echo json_encode(['success' => true, 'message' => 'Comment added successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to add comment: ' . mysqli_error($link)]);
        }
        mysqli_stmt_close($stmt);
    }
}

// Update complaint status (admin only)
function updateComplaintStatus($link, $input) {
    if(!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
        echo json_encode(['success' => false, 'message' => 'Access denied']);
        return;
    }
    
    $complaint_id = $input['complaint_id'] ?? 0;
    $status = $input['status'] ?? '';
    
    if(!in_array($status, ['pending', 'in-progress', 'resolved'])) {
        echo json_encode(['success' => false, 'message' => 'Invalid status']);
        return;
    }
    
    $sql = "UPDATE complaints SET status = ? WHERE id = ?";
    if($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "si", $status, $complaint_id);
        
        if(mysqli_stmt_execute($stmt)) {
            // Add system comment
            $user_id = $_SESSION['user_id'];
            $comment = "Status updated to: " . ucfirst(str_replace('-', ' ', $status));
            $comment_sql = "INSERT INTO comments (complaint_id, user_id, comment) VALUES (?, ?, ?)";
            $comment_stmt = mysqli_prepare($link, $comment_sql);
            mysqli_stmt_bind_param($comment_stmt, "iis", $complaint_id, $user_id, $comment);
            mysqli_stmt_execute($comment_stmt);
            mysqli_stmt_close($comment_stmt);
            
            echo json_encode(['success' => true, 'message' => 'Status updated successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to update status: ' . mysqli_error($link)]);
        }
        mysqli_stmt_close($stmt);
    }
}

// Get dashboard statistics
function getDashboardStats($link) {
    if(!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'User not logged in']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $role = $_SESSION['role'];
    
    if($role === 'admin') {
        // Admin sees all complaints
        $sql = "SELECT status, COUNT(*) as count FROM complaints GROUP BY status";
        $stmt = mysqli_prepare($link, $sql);
    } else {
        // Staff sees only their complaints
        $sql = "SELECT status, COUNT(*) as count FROM complaints WHERE user_id = ? GROUP BY status";
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, "i", $user_id);
    }
    
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    $stats = ['pending' => 0, 'in-progress' => 0, 'resolved' => 0, 'total' => 0];
    
    while($row = mysqli_fetch_assoc($result)) {
        $stats[$row['status']] = $row['count'];
        $stats['total'] += $row['count'];
    }
    
    echo json_encode(['success' => true, 'stats' => $stats]);
    mysqli_stmt_close($stmt);
}

// Get admin complaints
function getAdminComplaints($link, $input) {
    if(!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
        echo json_encode(['success' => false, 'message' => 'Access denied']);
        return;
    }
    
    $status_filter = $input['status'] ?? 'all';
    
    $sql = "SELECT c.*, u.full_name as user_name, u.email as user_email FROM complaints c 
            JOIN users u ON c.user_id = u.id";
    
    if($status_filter !== 'all') {
        $sql .= " WHERE c.status = ?";
    }
    
    $sql .= " ORDER BY c.created_at DESC";
    
    if($stmt = mysqli_prepare($link, $sql)) {
        if($status_filter !== 'all') {
            mysqli_stmt_bind_param($stmt, "s", $status_filter);
        }
        
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $complaints = [];
        
        while($row = mysqli_fetch_assoc($result)) {
            $complaints[] = $row;
        }
        
        echo json_encode(['success' => true, 'complaints' => $complaints]);
        mysqli_stmt_close($stmt);
    }
}

// Check session
function checkSession() {
    if(isset($_SESSION['user_id']) && $_SESSION['logged_in'] === true) {
        echo json_encode([
            'success' => true,
            'logged_in' => true,
            'user' => [
                'id' => $_SESSION['user_id'],
                'full_name' => $_SESSION['full_name'],
                'email' => $_SESSION['email'],
                'username' => $_SESSION['username'],
                'role' => $_SESSION['role'],
                'phone' => $_SESSION['phone'],
                'position' => $_SESSION['position']
            ]
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'logged_in' => false,
            'message' => 'User not logged in'
        ]);
    }
}

mysqli_close($link);
?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Staff Complaint Management System</title>
    <link rel="stylesheet" href="style.css" />
  </head>
  <body>
    <!-- Navigation Bar -->
    <nav class="navbar hidden" id="main-navbar">
      <div class="logo">QC Express Complaints</div>
      <ul class="nav-links">
        <li><a onclick="showSection('dashboard')">Dashboard</a></li>
        <li><a onclick="showSection('file-complaint')" id="file-complaint-nav">File Complaint</a></li>
        <li><a onclick="showSection('complaint-list')">Complaints</a></li>
        <li><a onclick="showSection('profile')">Profile</a></li>
        <li><a onclick="logout()">Logout</a></li>
      </ul>
    </nav>

    <!-- Login Section -->
    <section id="login-section" class="auth-section">
      <div class="auth-container">
        <h2>Staff Login</h2>
        <form onsubmit="handleLogin(event)">
          <div class="form-group">
            <label for="login-username">Company Email or Username</label>
            <input type="text" id="login-username" required />
          </div>
          <div class="form-group">
            <label for="login-password">Password</label>
            <input type="password" id="login-password" required />
          </div>
          <button type="submit" class="btn" style="width: 100%">Login</button>
        </form>
        <p style="text-align: center; margin-top: 1rem">
          Don't have an account?
          <a href="javascript:void(0)" onclick="showSection('signup')" style="color: var(--primary-blue)">Sign Up</a>
        </p>
        <div style="text-align: center; margin-top: 1rem; padding: 1rem;">
          
          <button type="button" onclick="quickAdminLogin()" class="" style="width: 100%; margin-top: 0.5rem; border: none; background: none; ">
            Admin Login
          </button>
        </div>
      </div>
    </section>

    <!-- Signup Section -->
    <section id="signup-section" class="auth-section hidden">
      <div class="auth-container">
        <h2>Staff Registration</h2>
        <form onsubmit="handleSignup(event)">
          <div class="form-group">
            <label for="signup-name">Full Name</label>
            <input type="text" id="signup-name" required />
          </div>
          <div class="form-group">
            <label for="signup-email">Company Email</label>
            <input type="email" id="signup-email" required />
          </div>
          <div class="form-group">
            <label for="signup-username">Username</label>
            <input type="text" id="signup-username" required />
          </div>
          <div class="form-group">
            <label for="signup-password">Password</label>
            <input type="password" id="signup-password" required />
          </div>
          <div class="form-group">
            <label for="confirm-password">Confirm Password</label>
            <input type="password" id="confirm-password" required />
          </div>
          <div class="form-group">
            <label for="signup-phone">Phone Number (Optional)</label>
            <input type="tel" id="signup-phone" />
          </div>
          <div class="form-group">
            <label for="signup-position">Position (Optional)</label>
            <input type="text" id="signup-position" />
          </div>
         
<button type="submit" class="btn" style="width: 100%">Sign Up</button>
        </form>
        <p style="text-align: center; margin-top: 1rem">
          Already have an account?
          <a href="javascript:void(0)" onclick="showSection('login')" style="color: var(--primary-blue)">Login</a>
        </p>
      </div>
    </section>

    <!-- Dashboard Section -->
    <section id="dashboard-section" class="section hidden">
      <h1>Dashboard</h1>
      <div class="dashboard-welcome">
        <h3>Welcome back, <span id="user-name">Staff Member</span>!</h3>
        <p>Here's an overview of your complaint activity and company updates.</p>
      </div>

      <div class="status-cards">
        <div class="status-card pending">
          <h3 id="pending-count">0</h3>
          <p>Pending</p>
        </div>
        <div class="status-card in-progress">
          <h3 id="progress-count">0</h3>
          <p>In Progress</p>
        </div>
        <div class="status-card resolved">
          <h3 id="resolved-count">0</h3>
          <p>Resolved</p>
        </div>
      </div>

      <div class="dashboard-grid">
        <div class="dashboard-card">
          <h4>Quick Actions</h4>
          <button class="btn" onclick="showSection('file-complaint')" style="margin-right: 1rem" id="quick-file-btn">
            File New Complaint
          </button>
          <button class="btn btn-secondary" onclick="showSection('complaint-list')">
            View All Complaints
          </button>
        </div>

        <div class="dashboard-card">
          <h4>Summary Statistics</h4>
          <ul style="list-style: none; padding: 0">
            <li>Total Complaints: <strong id="total-complaints">0</strong></li>
            <li>Recent Activity: <strong id="recent-activity">Loading...</strong></li>
            <li>Account Type: <strong id="user-role">Staff</strong></li>
          </ul>
        </div>

        <div class="dashboard-card">
          <h4>Notifications</h4>
          <ul style="list-style: none; padding: 0; font-size: 14px">
            <li>• System maintenance scheduled for Friday 8pm</li>
            <li>• New complaint category added: Technical</li>
            <li>• Resolved complaints now show resolution time</li>
          </ul>
        </div>
      </div>

      <div class="dashboard-card">
        <h4>Recent Complaints</h4>
        <div id="recent-complaints">Loading recent complaints...</div>
      </div>
    </section>

    <!-- File Complaint Section -->
    <section id="file-complaint-section" class="section hidden">
      <h1>File New Complaint</h1>
      <div class="form-container">
        <form onsubmit="handleComplaintSubmission(event)">
          <div class="form-group">
            <label for="complaint-title">Complaint Title</label>
            <input type="text" id="complaint-title" required />
          </div>
          <div class="form-group">
            <label for="complaint-category">Category</label>
            <select id="complaint-category" required>
              <option value="">Select Category</option>
              <option value="Delivery">Delivery</option>
              <option value="Services">Services</option>
              <option value="Technical">Technical</option>
              <option value="Maintenance">Maintenance</option>
            </select>
          </div>
          <div class="form-group">
            <label for="complaint-description">Description</label>
            <textarea
              id="complaint-description"
              required
              placeholder="Please describe your complaint in detail..."
            ></textarea>
          </div>
          <div class="form-group">
            <label for="complaint-attachment">Attach Image (Optional)</label>
            <input type="file" id="complaint-attachment" accept="image/*" />
          </div>
          <button type="submit" class="btn">Submit Complaint</button>
        </form>
      </div>
    </section>

    <!-- Complaint List Section -->
    <section id="complaint-list-section" class="section hidden">
      <h1>All Complaints</h1>
      <div class="filters">
        <button class="filter-btn active" onclick="filterComplaints('all')">All</button>
        <button class="filter-btn" onclick="filterComplaints('pending')">Pending</button>
        <button class="filter-btn" onclick="filterComplaints('in-progress')">In Progress</button>
        <button class="filter-btn" onclick="filterComplaints('resolved')">Resolved</button>
      </div>
      <div id="complaint-list">Loading complaints...</div>
    </section>

    <!-- Complaint Details Section -->
    <section id="complaint-details-section" class="section hidden">
      <h1>Complaint Details</h1>
      <div id="complaint-info">Loading complaint details...</div>
      <div class="comments-section">
        <h3>Updates / Comments</h3>
        <div id="comments-list">Loading comments...</div>
        <div class="form-group" style="margin-top: 1rem">
          <label for="new-comment">Add a comment</label>
          <textarea id="new-comment" placeholder="Add a comment..."></textarea>
          <button class="btn" onclick="addComplaintComment()" style="margin-top: 0.5rem">
            Add Comment
          </button>
        </div>
      </div>
      <button class="btn btn-secondary" onclick="showSection('complaint-list')" style="margin-top: 1rem">
        Back to List
      </button>
    </section>

    <!-- Profile Section -->
    <section id="profile-section" class="section hidden">
      <h1>Profile</h1>
      <div class="form-container">
        <div style="text-align: center; margin-bottom: 2rem">
          <img
            id="profile-image"
            src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='50' fill='%23e5e7eb'/%3E%3Ctext x='50' y='55' text-anchor='middle' font-size='30' fill='%23374151'%3E👤%3C/text%3E%3C/svg%3E"
            alt="Profile"
            class="profile-pic"
          />
          <br />
          <input type="file" id="profile-pic-input" accept="image/*" style="display: none" />
          <button
            class="btn btn-secondary"
            onclick="document.getElementById('profile-pic-input').click()"
            style="margin-top: 1rem"
          >
            Change Photo
          </button>
        </div>

        <form onsubmit="handleProfileUpdate(event)">
          <div class="form-group">
            <label for="profile-name">Full Name</label>
            <input type="text" id="profile-name" />
          </div>
          <div class="form-group">
            <label for="profile-email">Email</label>
            <input type="email" id="profile-email" />
          </div>
          <div class="form-group">
            <label for="profile-username">Username</label>
            <input type="text" id="profile-username" />
          </div>
          <div class="form-group">
            <label for="profile-phone">Phone Number</label>
            <input type="tel" id="profile-phone" />
          </div>
          <div class="form-group">
            <label for="profile-position">Position</label>
            <input type="text" id="profile-position" />
          </div>
          <button type="submit" class="btn">Save Changes</button>
        </form>
      </div>
    </section>

    <!-- Admin Dashboard Section -->
    <section id="admin-dashboard-section" class="section hidden">
      <h1 class="admin-title">Admin Dashboard</h1>

      <ul class="admin-nav">
        <li onclick="showSection('admin-dashboard')">Dashboard</li>
        <li onclick="showSection('admin-complaints')">Manage Complaints</li>
        <li onclick="showSection('admin-users')">Manage Users</li>
        <li onclick="logout()">Logout</li>
      </ul>

      <div class="admin-cards">
        <div class="admin-card">
          <h3 id="admin-total-count">0</h3>
          <p>Total Complaints</p>
        </div>
        <div class="admin-card">
          <h3 id="admin-pending-count">0</h3>
          <p>Pending</p>
        </div>
        <div class="admin-card">
          <h3 id="admin-progress-count">0</h3>
          <p>In Progress</p>
        </div>
        <div class="admin-card">
          <h3 id="admin-resolved-count">0</h3>
          <p>Resolved</p>
        </div>
      </div>

      <div class="notification-badge">🔔 Welcome Administrator</div>
    </section>

    <!-- Admin Complaints Section -->
    <section id="admin-complaints-section" class="section hidden">
      <h1 class="admin-title">Manage Complaints</h1>

      <div class="filters">
        <button class="filter-btn active" onclick="filterAdminComplaints('all')">All Complaints</button>
        <button class="filter-btn" onclick="filterAdminComplaints('pending')">Pending</button>
        <button class="filter-btn" onclick="filterAdminComplaints('in-progress')">In Progress</button>
        <button class="filter-btn" onclick="filterAdminComplaints('resolved')">Resolved</button>
      </div>

      <div id="admin-complaint-list">Loading complaints...</div>

      <button class="btn btn-secondary" onclick="showSection('admin-dashboard')" style="margin-top: 1rem">
        Back to Dashboard
      </button>
    </section>

    <!-- Admin Users Section -->
    <section id="admin-users-section" class="section hidden">
      <h1 class="admin-title">Manage Users</h1>
      <div class="dashboard-card">
        <h4>User Management</h4>
        <p>User management functionality coming soon...</p>
        <ul style="list-style: none; padding: 0">
          <li>• View all registered users</li>
          <li>• Edit user permissions</li>
          <li>• Deactivate/activate accounts</li>
          <li>• Generate user reports</li>
        </ul>
      </div>
      <button class="btn btn-secondary" onclick="showSection('admin-dashboard')">
        Back to Dashboard
      </button>
    </section>

    <script>
    // Global variables
    let currentUser = null;
    let currentComplaintId = null;

    // Check session on page load
    document.addEventListener('DOMContentLoaded', function() {
        checkUserSession();
    });

    // Quick admin login function
    function quickAdminLogin() {
        document.getElementById('login-username').value = 'admin@qcexpress.com';
        document.getElementById('login-password').value = 'admin123';
        
        // Optionally auto-submit
        const event = new Event('submit');
        document.querySelector('#login-section form').dispatchEvent(event);
    }

    // API call function
    async function apiCall(action, data = {}) {
        try {
            const response = await fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    action: action,
                    ...data
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API call failed:', error);
            showMessage('Connection error. Please try again.', 'error');
            return { success: false, message: 'Connection error' };
        }
    }

    // Check user session
    async function checkUserSession() {
        const result = await apiCall('check_session');
        if (result.success && result.logged_in) {
            currentUser = result.user;
            if (currentUser.role === 'admin') {
                showAdminInterface();
            } else {
                showUserInterface();
            }
        } else {
            showSection('login');
        }
    }

    // Show message function
    function showMessage(message, type = 'success') {
        // Remove existing messages
        const existingMessages = document.querySelectorAll('.message');
        existingMessages.forEach(msg => msg.remove());

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.textContent = message;
        messageDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 5px;
            color: white;
            font-weight: bold;
            z-index: 1000;
            max-width: 300px;
            word-wrap: break-word;
            ${type === 'success' ? 'background-color: #10b981;' : 'background-color: #ef4444;'}
        `;

        document.body.appendChild(messageDiv);

        setTimeout(() => {
            messageDiv.remove();
        }, 5000);
    }

    // Show section function
    function showSection(sectionName) {
        // Hide all sections
        const sections = document.querySelectorAll('.section, .auth-section');
        sections.forEach(section => {
            section.classList.add('hidden');
        });

        // Hide navbar initially
        document.getElementById('main-navbar').classList.add('hidden');

        // Show requested section
        const targetSection = document.getElementById(sectionName + '-section');
        if (targetSection) {
            targetSection.classList.remove('hidden');
        }

        // Show navbar for staff sections only (not admin sections)
        const staffSections = ['dashboard', 'file-complaint', 'complaint-list', 'complaint-details', 'profile'];
        const adminSections = ['admin-dashboard', 'admin-complaints', 'admin-users'];
        
        if (staffSections.includes(sectionName)) {
            document.getElementById('main-navbar').classList.remove('hidden');
        } else if (adminSections.includes(sectionName)) {
            // Keep navbar hidden for admin sections since they have their own navigation
            document.getElementById('main-navbar').classList.add('hidden');
        }

        // Load section-specific data
        switch(sectionName) {
            case 'dashboard':
                loadDashboard();
                break;
            case 'complaint-list':
                loadComplaints();
                break;
            case 'profile':
                loadProfile();
                break;
            case 'admin-dashboard':
                loadAdminDashboard();
                break;
            case 'admin-complaints':
                loadAdminComplaints();
                break;
        }
    }

    // Handle login
    async function handleLogin(event) {
        event.preventDefault();
        
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        const result = await apiCall('login', {
            username: username,
            password: password
        });

        if (result.success) {
            currentUser = result.user;
            showMessage('Login successful!', 'success');
            
            if (currentUser.role === 'admin') {
                showAdminInterface();
            } else {
                showUserInterface();
            }
        } else {
            showMessage(result.message, 'error');
        }
    }

    // Handle signup
    async function handleSignup(event) {
        event.preventDefault();
        
        const formData = {
            full_name: document.getElementById('signup-name').value,
            email: document.getElementById('signup-email').value,
            username: document.getElementById('signup-username').value,
            password: document.getElementById('signup-password').value,
            confirm_password: document.getElementById('confirm-password').value,
            phone: document.getElementById('signup-phone').value,
            position: document.getElementById('signup-position').value,
        };

        const result = await apiCall('register', formData);

        if (result.success) {
            showMessage('Registration successful! Please login.', 'success');
            showSection('login');
            // Clear form
            document.querySelector('#signup-section form').reset();
        } else {
            showMessage(result.message, 'error');
        }
    }

    // Show user interface
    function showUserInterface() {
        showSection('dashboard');
        document.getElementById('user-name').textContent = currentUser.full_name;
        document.getElementById('user-role').textContent = currentUser.role;
    }

    // Show admin interface
    function showAdminInterface() {
        showSection('admin-dashboard');
        // Hide regular nav items for admin
        const regularNavItems = document.querySelectorAll('#file-complaint-nav');
        regularNavItems.forEach(item => {
            item.style.display = 'none';
        });
    }

    // Load dashboard
    async function loadDashboard() {
        const result = await apiCall('get_dashboard_stats');
        if (result.success) {
            document.getElementById('pending-count').textContent = result.stats.pending;
            document.getElementById('progress-count').textContent = result.stats['in-progress'];
            document.getElementById('resolved-count').textContent = result.stats.resolved;
            document.getElementById('total-complaints').textContent = result.stats.total;
        }

        // Load recent complaints
        const complaintsResult = await apiCall('get_complaints', { status: 'all' });
        if (complaintsResult.success) {
            const recentContainer = document.getElementById('recent-complaints');
            if (complaintsResult.complaints.length === 0) {
                recentContainer.innerHTML = '<p>No complaints found.</p>';
            } else {
                const recent = complaintsResult.complaints.slice(0, 3);
                recentContainer.innerHTML = recent.map(complaint => `
                    <div class="complaint-item" onclick="viewComplaintDetails(${complaint.id})">
                        <h5>${complaint.title}</h5>
                        <p>Status: <span class="status ${complaint.status}">${complaint.status}</span></p>
                        <p>Created: ${new Date(complaint.created_at).toLocaleDateString()}</p>
                    </div>
                `).join('');
            }
        }
    }

    // Load admin dashboard
    async function loadAdminDashboard() {
        const result = await apiCall('get_dashboard_stats');
        if (result.success) {
            document.getElementById('admin-pending-count').textContent = result.stats.pending;
            document.getElementById('admin-progress-count').textContent = result.stats['in-progress'];
            document.getElementById('admin-resolved-count').textContent = result.stats.resolved;
            document.getElementById('admin-total-count').textContent = result.stats.total;
        }
    }

    // Handle complaint submission
    async function handleComplaintSubmission(event) {
        event.preventDefault();
        
        const formData = {
            title: document.getElementById('complaint-title').value,
            category: document.getElementById('complaint-category').value,
            description: document.getElementById('complaint-description').value,
            attachment: '' // File upload would need additional handling
        };

        const result = await apiCall('submit_complaint', formData);

        if (result.success) {
            showMessage('Complaint submitted successfully!', 'success');
            document.querySelector('#file-complaint-section form').reset();
            showSection('complaint-list');
        } else {
            showMessage(result.message, 'error');
        }
    }

    // Load complaints
    async function loadComplaints(status = 'all') {
        const result = await apiCall('get_complaints', { status: status });
        const container = document.getElementById('complaint-list');

        if (result.success) {
            if (result.complaints.length === 0) {
                container.innerHTML = '<p>No complaints found.</p>';
            } else {
                container.innerHTML = result.complaints.map(complaint => `
                    <div class="complaint-item" onclick="viewComplaintDetails(${complaint.id})">
                        <div class="complaint-header">
                            <h4>${complaint.title}</h4>
                            <span class="status ${complaint.status}">${complaint.status}</span>
                        </div>
                        <p><strong>Category:</strong> ${complaint.category}</p>
                        <p><strong>Created:</strong> ${new Date(complaint.created_at).toLocaleDateString()}</p>
                        <p>${complaint.description.substring(0, 100)}...</p>
                    </div>
                `).join('');
            }
        } else {
            container.innerHTML = '<p>Error loading complaints.</p>';
        }
    }

    // Load admin complaints
    async function loadAdminComplaints(status = 'all') {
        const result = await apiCall('get_admin_complaints', { status: status });
        const container = document.getElementById('admin-complaint-list');

        if (result.success) {
            if (result.complaints.length === 0) {
                container.innerHTML = '<p>No complaints found.</p>';
            } else {
                container.innerHTML = result.complaints.map(complaint => `
                    <div class="complaint-item admin-complaint" onclick="viewComplaintDetails(${complaint.id})">
                        <div class="complaint-header">
                            <h4>${complaint.title}</h4>
                            <span class="status ${complaint.status}">${complaint.status}</span>
                        </div>
                        <p><strong>User:</strong> ${complaint.user_name} (${complaint.user_email})</p>
                        <p><strong>Category:</strong> ${complaint.category}</p>
                        <p><strong>Created:</strong> ${new Date(complaint.created_at).toLocaleDateString()}</p>
                        <p>${complaint.description.substring(0, 100)}...</p>
                        <div class="admin-actions">
                            <select onchange="updateComplaintStatus(${complaint.id}, this.value)" onclick="event.stopPropagation()">
                                <option value="">Change Status</option>
                                <option value="pending" ${complaint.status === 'pending' ? 'selected' : ''}>Pending</option>
                                <option value="in-progress" ${complaint.status === 'in-progress' ? 'selected' : ''}>In Progress</option>
                                <option value="resolved" ${complaint.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                            </select>
                        </div>
                    </div>
                `).join('');
            }
        } else {
            container.innerHTML = '<p>Error loading complaints.</p>';
        }
    }

    // Filter complaints
    function filterComplaints(status) {
        // Update active filter button
        document.querySelectorAll('#complaint-list-section .filter-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        event.target.classList.add('active');
        
        loadComplaints(status);
    }

    // Filter admin complaints
    function filterAdminComplaints(status) {
        // Update active filter button
        document.querySelectorAll('#admin-complaints-section .filter-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        event.target.classList.add('active');
        
        loadAdminComplaints(status);
    }

    // View complaint details
    async function viewComplaintDetails(complaintId) {
        currentComplaintId = complaintId;
        const result = await apiCall('get_complaint_details', { complaint_id: complaintId });

        if (result.success) {
            const complaint = result.complaint;
            document.getElementById('complaint-info').innerHTML = `
                <div class="complaint-detail">
                    <div class="complaint-header">
                        <h3>${complaint.title}</h3>
                        <span class="status ${complaint.status}">${complaint.status}</span>
                    </div>
                    <p><strong>Category:</strong> ${complaint.category}</p>
                    <p><strong>Submitted by:</strong> ${complaint.user_name}</p>
                    <p><strong>Created:</strong> ${new Date(complaint.created_at).toLocaleDateString()}</p>
                    <div class="complaint-description">
                        <h4>Description:</h4>
                        <p>${complaint.description}</p>
                    </div>
                </div>
            `;

            // Load comments
            const commentsContainer = document.getElementById('comments-list');
            if (complaint.comments.length === 0) {
                commentsContainer.innerHTML = '<p>No comments yet.</p>';
            } else {
                commentsContainer.innerHTML = complaint.comments.map(comment => `
                    <div class="comment">
                        <div class="comment-header">
                            <strong>${comment.author_name}</strong>
                            <span>${new Date(comment.created_at).toLocaleDateString()}</span>
                        </div>
                        <p>${comment.comment}</p>
                    </div>
                `).join('');
            }

            showSection('complaint-details');
        }
    }

    // Add complaint comment
    async function addComplaintComment() {
        const comment = document.getElementById('new-comment').value.trim();
        if (!comment) {
            showMessage('Please enter a comment', 'error');
            return;
        }

        const result = await apiCall('add_comment', {
            complaint_id: currentComplaintId,
            comment: comment
        });

        if (result.success) {
            showMessage('Comment added successfully!', 'success');
            document.getElementById('new-comment').value = '';
            viewComplaintDetails(currentComplaintId); // Reload details
        } else {
            showMessage(result.message, 'error');
        }
    }

    // Update complaint status (admin only)
    async function updateComplaintStatus(complaintId, status) {
        if (!status) return;

        const result = await apiCall('update_complaint_status', {
            complaint_id: complaintId,
            status: status
        });

        if (result.success) {
            showMessage('Status updated successfully!', 'success');
            loadAdminComplaints(); // Reload the list
        } else {
            showMessage(result.message, 'error');
        }
    }

    // Load profile
    async function loadProfile() {
        const result = await apiCall('get_profile');
        if (result.success) {
            const user = result.user;
            document.getElementById('profile-name').value = user.full_name || '';
            document.getElementById('profile-email').value = user.email || '';
            document.getElementById('profile-username').value = user.username || '';
            document.getElementById('profile-phone').value = user.phone || '';
            document.getElementById('profile-position').value = user.position || '';
        }
    }

    // Handle profile update
    async function handleProfileUpdate(event) {
        event.preventDefault();
        
        const formData = {
            full_name: document.getElementById('profile-name').value,
            email: document.getElementById('profile-email').value,
            username: document.getElementById('profile-username').value,
            phone: document.getElementById('profile-phone').value,
            position: document.getElementById('profile-position').value
        };

        const result = await apiCall('update_profile', formData);

        if (result.success) {
            showMessage('Profile updated successfully!', 'success');
            currentUser = { ...currentUser, ...result.user };
            document.getElementById('user-name').textContent = currentUser.full_name;
        } else {
            showMessage(result.message, 'error');
        }
    }

    // Logout function
    async function logout() {
        const result = await apiCall('logout');
        if (result.success) {
            currentUser = null;
            showMessage('Logged out successfully!', 'success');
            showSection('login');
            
            // Clear forms
            document.querySelectorAll('form').forEach(form => form.reset());
        }
    }
    </script>
  </body>
</html>