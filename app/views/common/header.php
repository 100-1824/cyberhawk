<!-- header.php -->



    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <script src="<?= MDIR ?>assets/js/scripts.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script> 
    <link href= "<?= MDIR ?>assets/css/style.css" rel="stylesheet" />
    <script src="https://cdnjs.cloudflare.com/ajax/libs/notify/0.4.2/notify.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet" />




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
    <i class="bi bi-gear fs-5" title="Settings" role="button" tabindex="0"></i>
    <?php if (isset($_SESSION['user_name'])): ?>
  <div class="user-info d-flex align-items-center gap-2">
    <i class="bi bi-person-circle fs-5"></i>
    <span><?= htmlspecialchars($_SESSION['user_name']) ?></span>
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