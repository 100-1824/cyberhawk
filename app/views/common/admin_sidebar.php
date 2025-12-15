<!-- admin_sidebar.php -->
<nav class="sidebar minimized" id="adminSidebar">
    <div class="toggle-btn" onclick="toggleSidebar()">
        <i class="bi bi-list"></i>
    </div>
    <ul class="nav-links">
        <li><a href="<?= MDIR ?>admin/dashboard"><i class="bi bi-speedometer2 icon"></i><span class="text">Dashboard</span></a></li>
        <li><a href="<?= MDIR ?>admin/dashboard#users"><i class="bi bi-people icon"></i><span class="text">Users</span></a></li>
        <li><a href="<?= MDIR ?>admin/dashboard#endpoints"><i class="bi bi-diagram-3 icon"></i><span class="text">Endpoints</span></a></li>
        <li><a href="<?= MDIR ?>admin/dashboard#activity"><i class="bi bi-activity icon"></i><span class="text">Activity</span></a></li>
        <li class="mt-4"><a href="<?= MDIR ?>dashboard"><i class="bi bi-shield icon"></i><span class="text">User Dashboard</span></a></li>
    </ul>
</nav>

<script>
    function toggleSidebar() {
        const sidebar = document.getElementById('adminSidebar');
        sidebar.classList.toggle('minimized');
    }
</script>
