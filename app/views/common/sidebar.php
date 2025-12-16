<!-- sidebar.php -->

<!-- Mobile sidebar overlay backdrop -->
<div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

<nav class="sidebar minimized" id="sidebar">
  <div class="toggle-btn" onclick="toggleSidebar()">
    <i class="bi bi-list"></i>
  </div>
  <ul class="nav-links">
    <!-- <li><a href="<?= MDIR ?>dashboard"><i class="bi bi-house icon"></i><span class="text">Dashboard</span></a></li> -->
    <li><a href="<?= MDIR ?>dashboard"><i class="bi bi-shield icon"></i><span class="text">IPS Dashboard</span></a></li>
    <li><a href="<?= MDIR ?>ransomware"><i class="bi bi-virus icon"></i><span class="text">Ransomware</span></a></li>
    <li><a href="<?= MDIR ?>malware"><i class="bi bi-bug icon"></i><span class="text">Malware</span></a></li>
    <!-- <li class="nav-header">
      <span class="text">INTELLIGENCE</span>
    </li> -->

    <li>
      <a href="<?= MDIR ?>threat-intelligence">
        <i class="bi bi-globe2 icon"></i>
        <span class="text">Threat Intelligence</span>
      </a>
    </li>

    <li>
      <a href="<?= MDIR ?>network-analytics">
        <i class="bi bi-graph-up-arrow icon"></i>
        <span class="text">Network Analytics</span>
      </a>
    </li>
    <li><a href="<?= MDIR ?>reporting"><i class="bi bi-file-earmark-text icon"></i><span class="text">Reporting</span></a></li>
  </ul>
</nav>

<script>
  function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    // Check if on mobile (less than 992px)
    if (window.innerWidth < 992) {
      sidebar.classList.toggle('show');
      overlay.classList.toggle('show');
    } else {
      sidebar.classList.toggle('minimized');
    }
  }

  function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    sidebar.classList.remove('show');
    overlay.classList.remove('show');
  }

  // Close sidebar when clicking a link (mobile)
  document.querySelectorAll('.nav-links a').forEach(link => {
    link.addEventListener('click', () => {
      if (window.innerWidth < 992) {
        closeSidebar();
      }
    });
  });

  // Handle resize events
  window.addEventListener('resize', () => {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (window.innerWidth >= 992) {
      sidebar.classList.remove('show');
      overlay.classList.remove('show');
    }
  });
</script>