<!-- header.php -->



    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <script src="<?= MDIR ?>assets/js/scripts.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script> 
    <link href= "<?= MDIR ?>assets/css/style.css" rel="stylesheet" />
    <script src="https://cdnjs.cloudflare.com/ajax/libs/notify/0.4.2/notify.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet" />



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
    <i class="bi bi-bell fs-5" title="Notifications" role="button" tabindex="0"></i>
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