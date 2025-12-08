<!-- sidebar.php -->
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
    sidebar.classList.toggle('minimized');
  }
</script>