<!-- header.php -->



    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <script>
        // Define MDIR for JavaScript
        const MDIR = '<?= MDIR ?>';
    </script>
    <script src="<?= MDIR ?>assets/js/scripts.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <link href= "<?= MDIR ?>assets/css/style.css" rel="stylesheet" />
    <script src="https://cdnjs.cloudflare.com/ajax/libs/notify/0.4.2/notify.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet" />
    <script src="<?= MDIR ?>assets/js/notifications.js"></script>



<style>
  .dropdown-menu {
    border: 2px solid #0a74da;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    border-radius: 8px;
    min-width: 200px;
}

.dropdown-item {
    padding: 10px 20px;
    transition: all 0.3s ease;
}

.dropdown-item:hover {
    background: linear-gradient(135deg, #0a74da, #061a40);
    color: white !important;
}

.dropdown-item i {
    margin-right: 8px;
    width: 20px;
}

.dropdown-toggle::after {
    margin-left: 8px;
}

.btn-link:focus {
    box-shadow: none;
}

/* Notification Styles */
.notification-item {
    transition: all 0.2s ease;
}

.notification-item:hover {
    background-color: #f8f9fa !important;
}

.notification-item.bg-white {
    background-color: #e3f2fd !important;
}

#notificationBadge {
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% {
        transform: translate(-50%, -50%) scale(1);
    }
    50% {
        transform: translate(-50%, -50%) scale(1.1);
    }
}
</style>
<header class="main-header d-flex justify-content-between align-items-center px-4 py-2">
  <!-- Left side -->
  <div class="header-left d-flex align-items-center gap-3">
    <h4 class="mb-0 text-white fw-bold">CyberHawk</h4>
  </div>

  <!-- Center -->
  <div class="header-center text-white fw-semibold fs-5">
    Dashboard
  </div>

  <!-- Right side -->
  <div class="header-right d-flex align-items-center gap-4 text-white">
    <!-- Notifications Dropdown -->
<div class="dropdown">

    <button class="btn btn-link text-white position-relative p-0"
            type="button"
            id="notificationsDropdown"
            data-bs-toggle="dropdown"
            aria-expanded="false">

        <i class="bi bi-bell fs-5" title="Notifications" role="button"></i>

        <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger"
              id="notificationBadge"
              style="font-size: 0.6rem; display: none;">
            0
        </span>

    </button>

    <div class="dropdown-menu dropdown-menu-end p-0"
         aria-labelledby="notificationsDropdown"
         style="width: 350px; max-height: 500px; overflow-y: auto;">

        <!-- Header -->
        <div class="p-3" style="background: linear-gradient(135deg, #0a74da, #061a40);">
            <h6 class="text-white mb-0">
                <i class="bi bi-bell me-2"></i>Notifications
            </h6>
        </div>

        <!-- Notifications List -->
        <div id="notificationsList">
            <div class="text-center py-4 text-muted">
                <i class="bi bi-bell-slash" style="font-size: 2rem;"></i>
                <p class="mb-0 mt-2">No new notifications</p>
            </div>
        </div>

        <!-- Footer -->
        <div class="border-top p-2 text-center">
            <a href="#" class="text-decoration-none small" onclick="clearAllNotifications(); return false;">
                <i class="bi bi-check-all me-1"></i>Clear All
            </a>
        </div>

    </div>

</div>

    <!-- <i class="bi bi-gear fs-5" title="Settings" role="button" tabindex="0"></i> -->
     <a href="<?= MDIR ?>settings" title="Settings">
    <i class="bi bi-gear fs-5" role="button" tabindex="0"></i>
</a>
    <?php if (isset($_SESSION['user_name'])): ?>
  <!-- User Profile (replace existing user-info section) -->
<div class="user-info dropdown">
    <button class="btn btn-link text-white text-decoration-none dropdown-toggle d-flex align-items-center" 
            type="button" 
            id="userDropdown" 
            data-bs-toggle="dropdown" 
            aria-expanded="false">
        <?php
        // Get profile picture if exists
        $user_profile = get_user_profile($_SESSION['user_id']);
        $has_picture = !empty($user_profile['profile_picture']);
        ?>
        
        <?php if ($has_picture): ?>
            <img src="<?= MDIR ?>assets/uploads/profiles/<?= $user_profile['profile_picture'] ?>?v=<?= time() ?>" 
                 alt="Profile" 
                 style="width: 35px; height: 35px; border-radius: 50%; object-fit: cover; margin-right: 8px; border: 2px solid white;">
        <?php else: ?>
            <i class="bi bi-person-circle" style="font-size: 1.8rem; margin-right: 8px;"></i>
        <?php endif; ?>
        <span><?= htmlspecialchars($_SESSION['user_name']) ?></span>
    </button>
    
    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
        <li>
            <a class="dropdown-item" href="<?= MDIR ?>profile">
                <i class="bi bi-person"></i> My Profile
            </a>
        </li>
        <li><hr class="dropdown-divider"></li>
        <li>
            <a class="dropdown-item" href="<?= MDIR ?>profile#password">
                <i class="bi bi-lock"></i> Change Password
            </a>
        </li>
        <li><hr class="dropdown-divider"></li>
        <li>
            <a class="dropdown-item text-danger" href="<?= MDIR ?>logout">
                <i class="bi bi-box-arrow-right"></i> Logout
            </a>
        </li>
    </ul>
</div>
<?php endif; ?>

    <a href="<?= MDIR ?>logout" title="Logout" aria-label="Logout" class="btn btn-link p-0">
  <i class="bi bi-box-arrow-right fs-5"></i>
</a>

  </div>
</header>





<?php


// require_once __DIR__ . '/../../app/core/views.php';
// require_once __DIR__ . '/../../routes/web.php';
// require_once __DIR__ . '/../../app/core/functions.php';  
// require_once __DIR__ . '/../../app/database/config.php';


?>