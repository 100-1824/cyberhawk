<?php
// Get user profile data
$user_id = $_SESSION['user_id'];
$user = get_user_profile($user_id);

if (!$user) {
    header("Location: " . MDIR . "login");
    exit;
}

// Profile picture URL
$profile_pic_url = !empty($user['profile_picture']) 
    ? MDIR . 'assets/uploads/profiles/' . $user['profile_picture'] 
    : null;

// Format join date
$join_date = !empty($user['created_at']) 
    ? date('F j, Y', strtotime($user['created_at'])) 
    : 'Unknown';

$last_updated = !empty($user['last_updated']) 
    ? date('F j, Y g:i A', strtotime($user['last_updated'])) 
    : 'Never';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>My Profile - CyberHawk</title>
</head>

<style>
    .profile-container {
        max-width: 1200px;
        margin: 0 auto;
    }

    .profile-header {
        background: linear-gradient(135deg, #0a74da, #061a40);
        border-radius: 15px;
        padding: 40px;
        color: white;
        margin-bottom: 30px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.1);
    }

    .profile-picture-section {
        text-align: center;
        margin-bottom: 20px;
    }

    .profile-picture {
        width: 150px;
        height: 150px;
        border-radius: 50%;
        object-fit: cover;
        border: 5px solid white;
        box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        margin-bottom: 15px;
        background: white;
    }

    .profile-picture-placeholder {
        width: 150px;
        height: 150px;
        border-radius: 50%;
        background: white;
        border: 5px solid white;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 15px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    }

    .profile-picture-placeholder i {
        font-size: 80px;
        color: #0a74da;
    }

    .profile-name {
        font-size: 2rem;
        font-weight: bold;
        margin-bottom: 5px;
    }

    .profile-role {
        font-size: 1.1rem;
        opacity: 0.9;
        text-transform: capitalize;
    }

    .profile-actions {
        margin-top: 20px;
    }

    .profile-actions button {
        margin: 5px;
    }

    .card-profile {
        border: 2px solid #0a74da;
        border-radius: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        margin-bottom: 30px;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }

    .card-profile:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 16px rgba(0,0,0,0.15);
    }

    .gradient-text {
        background: linear-gradient(135deg, #0a74da, #061a40);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-weight: bold;
    }

    .info-row {
        display: flex;
        justify-content: space-between;
        padding: 15px 0;
        border-bottom: 1px solid #dee2e6;
    }

    .info-row:last-child {
        border-bottom: none;
    }

    .info-label {
        font-weight: 600;
        color: #495057;
    }

    .info-value {
        color: #6c757d;
        text-align: right;
    }

    .form-control:focus {
        border-color: #0a74da;
        box-shadow: 0 0 0 0.2rem rgba(10, 116, 218, 0.25);
    }

    .btn-primary {
        background: linear-gradient(135deg, #0a74da, #061a40);
        border: none;
        transition: all 0.3s ease;
    }

    .btn-primary:hover {
        background: linear-gradient(135deg, #084e8a, #041229);
        transform: scale(1.02);
    }

    .btn-light:hover {
        transform: scale(1.05);
    }

    .btn-outline-light:hover {
        transform: scale(1.05);
    }

    @media (max-width: 768px) {
        .profile-header {
            padding: 30px 20px;
        }

        .profile-name {
            font-size: 1.5rem;
        }

        .profile-picture,
        .profile-picture-placeholder {
            width: 120px;
            height: 120px;
        }

        .profile-picture-placeholder i {
            font-size: 60px;
        }
    }
</style>

<body>
    <?php include 'app/views/common/header.php'; ?>

    <div class="d-flex" style="min-height: calc(100vh - 60px);">
        <?php include 'app/views/common/sidebar.php'; ?>

        <div class="main-content flex-grow-1 p-4">
            <div class="profile-container">

                <!-- Profile Header Card -->
                <div class="profile-header">
                    <div class="profile-picture-section">
                        <?php if ($profile_pic_url): ?>
                            <img src="<?= $profile_pic_url ?>?v=<?= time() ?>" 
                                 alt="Profile Picture" 
                                 class="profile-picture" 
                                 id="profileImage">
                        <?php else: ?>
                            <div class="profile-picture-placeholder">
                                <i class="bi bi-person-circle"></i>
                            </div>
                        <?php endif; ?>
                        
                        <div class="profile-actions">
                            <button class="btn btn-light" onclick="document.getElementById('profilePictureInput').click()">
                                <i class="bi bi-camera"></i> Change Photo
                            </button>
                            <?php if ($profile_pic_url): ?>
                                <button class="btn btn-outline-light" onclick="deleteProfilePicture()">
                                    <i class="bi bi-trash"></i> Remove
                                </button>
                            <?php endif; ?>
                        </div>
                        
                        <input type="file" 
                               id="profilePictureInput" 
                               accept="image/*" 
                               style="display: none;" 
                               onchange="uploadProfilePicture(this)">
                    </div>

                    <div class="profile-name"><?= htmlspecialchars($user['name']) ?></div>
                    <div class="profile-role">
                        <i class="bi bi-shield-check"></i> <?= htmlspecialchars($user['role']) ?>
                    </div>
                </div>

                <div class="row g-4">
                    <!-- Account Information -->
                    <div class="col-md-6">
                        <div class="card card-profile">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-person-badge"></i> Account Information
                                </h5>
                            </div>
                            <div class="card-body">
                                <div class="info-row">
                                    <span class="info-label"><i class="bi bi-envelope"></i> Email:</span>
                                    <span class="info-value"><?= htmlspecialchars($user['email']) ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label"><i class="bi bi-hash"></i> User ID:</span>
                                    <span class="info-value">#<?= htmlspecialchars($user['id']) ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label"><i class="bi bi-award"></i> Account Type:</span>
                                    <span class="info-value">
                                        <span class="badge bg-primary"><?= strtoupper(htmlspecialchars($user['role'])) ?></span>
                                    </span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label"><i class="bi bi-calendar-check"></i> Member Since:</span>
                                    <span class="info-value"><?= $join_date ?></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label"><i class="bi bi-clock-history"></i> Last Updated:</span>
                                    <span class="info-value"><?= $last_updated ?></span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Edit Profile Form -->
                    <div class="col-md-6">
                        <div class="card card-profile">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-pencil-square"></i> Edit Profile
                                </h5>
                            </div>
                            <div class="card-body">
                                <form id="profileForm">
                                    <div class="mb-3">
                                        <label for="name" class="form-label">
                                            <i class="bi bi-person"></i> Full Name <span class="text-danger">*</span>
                                        </label>
                                        <input type="text" 
                                               class="form-control" 
                                               id="name" 
                                               name="name" 
                                               value="<?= htmlspecialchars($user['name']) ?>" 
                                               required
                                               maxlength="100"
                                               placeholder="Enter your full name">
                                    </div>

                                    <div class="mb-3">
                                        <label for="phone" class="form-label">
                                            <i class="bi bi-telephone"></i> Phone Number
                                        </label>
                                        <input type="tel" 
                                               class="form-control" 
                                               id="phone" 
                                               name="phone" 
                                               value="<?= htmlspecialchars($user['phone'] ?? '') ?>"
                                               placeholder="+1 (234) 567-8900">
                                        <small class="text-muted">Optional</small>
                                    </div>

                                    <div class="mb-3">
                                        <label for="bio" class="form-label">
                                            <i class="bi bi-chat-left-text"></i> Bio
                                        </label>
                                        <textarea class="form-control" 
                                                  id="bio" 
                                                  name="bio" 
                                                  rows="4" 
                                                  maxlength="500"
                                                  placeholder="Tell us about yourself..."><?= htmlspecialchars($user['bio'] ?? '') ?></textarea>
                                        <small class="text-muted">Maximum 500 characters (<span id="bioCount">0</span>/500)</small>
                                    </div>

                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="bi bi-check-circle"></i> Save Changes
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Change Password Section -->
                <div class="row g-4 mt-2">
                    <div class="col-md-12">
                        <div class="card card-profile" id="password">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-lock"></i> Change Password
                                </h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6 offset-md-3">
                                        <form id="passwordForm">
                                            <div class="mb-3">
                                                <label for="current_password" class="form-label">
                                                    <i class="bi bi-key"></i> Current Password <span class="text-danger">*</span>
                                                </label>
                                                <input type="password" 
                                                       class="form-control" 
                                                       id="current_password" 
                                                       name="current_password" 
                                                       required
                                                       placeholder="Enter current password">
                                            </div>

                                            <div class="mb-3">
                                                <label for="new_password" class="form-label">
                                                    <i class="bi bi-shield-lock"></i> New Password <span class="text-danger">*</span>
                                                </label>
                                                <input type="password" 
                                                       class="form-control" 
                                                       id="new_password" 
                                                       name="new_password" 
                                                       required
                                                       minlength="6"
                                                       placeholder="Enter new password">
                                                <small class="text-muted">Minimum 6 characters</small>
                                            </div>

                                            <div class="mb-3">
                                                <label for="confirm_password" class="form-label">
                                                    <i class="bi bi-shield-check"></i> Confirm New Password <span class="text-danger">*</span>
                                                </label>
                                                <input type="password" 
                                                       class="form-control" 
                                                       id="confirm_password" 
                                                       name="confirm_password" 
                                                       required
                                                       placeholder="Confirm new password">
                                            </div>

                                            <button type="submit" class="btn btn-primary w-100">
                                                <i class="bi bi-shield-lock"></i> Change Password
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>

    <script>
        // Bio character counter
        const bioField = document.getElementById('bio');
        const bioCount = document.getElementById('bioCount');
        
        if (bioField && bioCount) {
            bioCount.textContent = bioField.value.length;
            
            bioField.addEventListener('input', function() {
                bioCount.textContent = this.value.length;
            });
        }

        // Profile Form Submission
        document.getElementById('profileForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const submitBtn = this.querySelector('button[type="submit"]');
            
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Saving...';
            
            fetch('<?= MDIR ?>update-profile', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Success', data.message, 'success');
                    
                    // Update header name if changed
                    if (data.user && data.user.name) {
                        const headerName = document.querySelector('.user-info span');
                        if (headerName) {
                            headerName.textContent = data.user.name;
                        }
                    }
                    
                    // Reload page after 1 second to show updates
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                } else {
                    showNotification('Error', data.message, 'danger');
                }
            })
            .catch(error => {
                showNotification('Error', 'Failed to update profile: ' + error, 'danger');
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="bi bi-check-circle"></i> Save Changes';
            });
        });

        // Password Form Submission
        document.getElementById('passwordForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (newPassword !== confirmPassword) {
                showNotification('Error', 'New passwords do not match', 'danger');
                return;
            }
            
            const formData = new FormData(this);
            const submitBtn = this.querySelector('button[type="submit"]');
            
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Changing...';
            
            fetch('<?= MDIR ?>change-password', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Success', data.message, 'success');
                    this.reset();
                } else {
                    showNotification('Error', data.message, 'danger');
                }
            })
            .catch(error => {
                showNotification('Error', 'Failed to change password: ' + error, 'danger');
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="bi bi-shield-lock"></i> Change Password';
            });
        });

        // Profile Picture Upload
        function uploadProfilePicture(input) {
            if (!input.files || !input.files[0]) {
                return;
            }
            
            const file = input.files[0];
            
            // Validate file type
            const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
            if (!allowedTypes.includes(file.type)) {
                showNotification('Error', 'Invalid file type. Only JPG, PNG, and GIF allowed', 'danger');
                input.value = '';
                return;
            }
            
            // Validate file size (5MB)
            if (file.size > 5 * 1024 * 1024) {
                showNotification('Error', 'File too large. Maximum size is 5MB', 'danger');
                input.value = '';
                return;
            }
            
            const formData = new FormData();
            formData.append('profile_picture', file);
            
            showNotification('Info', 'Uploading profile picture...', 'info');
            
            fetch('<?= MDIR ?>upload-profile-picture', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Success', data.message, 'success');
                    
                    // Reload page to show new picture
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                } else {
                    showNotification('Error', data.message, 'danger');
                }
            })
            .catch(error => {
                showNotification('Error', 'Failed to upload picture: ' + error, 'danger');
            })
            .finally(() => {
                input.value = '';
            });
        }

        // Delete Profile Picture
        function deleteProfilePicture() {
            if (!confirm('Are you sure you want to remove your profile picture?')) {
                return;
            }
            
            fetch('<?= MDIR ?>delete-profile-picture', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Success', data.message, 'success');
                    
                    // Reload page to show changes
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                } else {
                    showNotification('Error', data.message, 'danger');
                }
            })
            .catch(error => {
                showNotification('Error', 'Failed to delete picture: ' + error, 'danger');
            });
        }

        // Notification Function
        function showNotification(title, message, type) {
            // Create notification element
            const notification = document.createElement('div');
            notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
            notification.style.cssText = 'top: 80px; right: 20px; z-index: 9999; min-width: 300px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); animation: slideIn 0.3s ease;';
            notification.innerHTML = `
                <strong>${title}:</strong> ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            document.body.appendChild(notification);
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }, 5000);
        }

        // Add animation styles
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            @keyframes slideOut {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(400px);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>