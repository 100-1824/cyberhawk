<?php
// Admin Dashboard View
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin Dashboard - CyberHawk</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="<?= MDIR ?>assets/css/style.css" rel="stylesheet">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>const MDIR = '<?= MDIR ?>';</script>
    <style>
        :root {
            --primary: #0a74da;
            --primary-dark: #061a40;
            --accent: #00d4ff;
            --success: #28a745;
            --warning: #ffc107;
            --danger: #dc3545;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background: #f5f7fb;
        }

        .admin-header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            padding: 15px 30px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .admin-header h4 {
            margin: 0;
            font-weight: 700;
            color: white !important;
        }

        .admin-header a {
            color: white !important;
        }

        .admin-badge {
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.05);
            display: flex;
            align-items: center;
            gap: 20px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }

        .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: white;
        }

        .stat-icon.blue { background: linear-gradient(135deg, var(--primary), var(--accent)); }
        .stat-icon.green { background: linear-gradient(135deg, #28a745, #20c997); }
        .stat-icon.orange { background: linear-gradient(135deg, #fd7e14, #ffc107); }
        .stat-icon.purple { background: linear-gradient(135deg, #6f42c1, #e83e8c); }

        .stat-info h3 {
            font-size: 2rem;
            font-weight: 700;
            margin: 0;
            color: var(--primary-dark);
        }

        .stat-info p {
            margin: 0;
            color: #6c757d;
            font-size: 0.9rem;
        }

        .section-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.05);
            margin-bottom: 30px;
            overflow: hidden;
        }

        .section-header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            padding: 15px 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .section-header h5 {
            margin: 0;
            font-weight: 600;
        }

        .section-body {
            padding: 25px;
        }

        .user-table {
            width: 100%;
            border-collapse: collapse;
        }

        .user-table th {
            background: #f8f9fa;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            color: var(--primary-dark);
            border-bottom: 2px solid #dee2e6;
        }

        .user-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
            vertical-align: middle;
        }

        .user-table tr:hover {
            background: #f8f9fa;
        }

        .role-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .role-badge.admin { background: #e8f4ff; color: var(--primary); }
        .role-badge.user { background: #e8f5e9; color: #28a745; }

        .status-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .status-badge.verified { background: #e8f5e9; color: #28a745; }
        .status-badge.pending { background: #fff3e0; color: #fd7e14; }

        .action-btn {
            padding: 6px 12px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.3s ease;
        }

        .action-btn.edit { background: #e8f4ff; color: var(--primary); }
        .action-btn.edit:hover { background: var(--primary); color: white; }
        .action-btn.delete { background: #ffebee; color: var(--danger); }
        .action-btn.delete:hover { background: var(--danger); color: white; }

        .endpoint-table th, .endpoint-table td {
            padding: 10px 15px;
        }

        .method-badge {
            padding: 4px 10px;
            border-radius: 5px;
            font-size: 0.75rem;
            font-weight: 600;
            font-family: monospace;
        }

        .method-badge.get { background: #e8f5e9; color: #28a745; }
        .method-badge.post { background: #e3f2fd; color: #1976d2; }

        .endpoint-path {
            font-family: 'Consolas', monospace;
            background: #f5f5f5;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
        }

        .category-badge {
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.7rem;
            font-weight: 500;
            background: #f0f0f0;
            color: #666;
        }

        .activity-item {
            padding: 12px;
            border-left: 3px solid var(--primary);
            margin-bottom: 10px;
            background: #f8f9fa;
            border-radius: 0 8px 8px 0;
        }

        .activity-time {
            font-size: 0.75rem;
            color: #6c757d;
        }

        /* Modal Styles */
        .modal-header {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
        }

        .modal-header .btn-close {
            filter: brightness(0) invert(1);
        }

        .form-control:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 0.2rem rgba(10, 116, 218, 0.25);
        }

        .main-content {
            padding: 30px;
        }

        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            .user-table {
                font-size: 0.85rem;
            }
        }
    </style>
</head>
<body>
    <!-- Admin Header -->
    <header class="admin-header">
        <div class="d-flex align-items-center gap-3">
            <a href="<?= MDIR ?>" class="text-white text-decoration-none">
                <h4><i class="bi bi-shield-check me-2"></i>CyberHawk</h4>
            </a>
            <span class="admin-badge"><i class="bi bi-gear-fill me-1"></i>Admin Panel</span>
        </div>
        <div class="d-flex align-items-center gap-3">
            <span class="text-white-50">Welcome, <?= htmlspecialchars($_SESSION['user_name'] ?? 'Admin') ?></span>
            <a href="<?= MDIR ?>dashboard" class="btn btn-outline-light btn-sm">
                <i class="bi bi-speedometer2 me-1"></i>User Dashboard
            </a>
            <a href="<?= MDIR ?>logout" class="btn btn-outline-light btn-sm">
                <i class="bi bi-box-arrow-right me-1"></i>Logout
            </a>
        </div>
    </header>

    <div class="d-flex">
        <?php include 'app/views/common/admin_sidebar.php'; ?>

        <div class="main-content flex-grow-1">
            <!-- Stats Cards -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon blue"><i class="bi bi-people"></i></div>
                    <div class="stat-info">
                        <h3 id="totalUsers"><?= $stats['total_users'] ?? 0 ?></h3>
                        <p>Total Users</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon green"><i class="bi bi-patch-check"></i></div>
                    <div class="stat-info">
                        <h3 id="verifiedUsers"><?= $stats['verified_users'] ?? 0 ?></h3>
                        <p>Verified Users</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon purple"><i class="bi bi-person-gear"></i></div>
                    <div class="stat-info">
                        <h3 id="adminUsers"><?= $stats['admin_users'] ?? 0 ?></h3>
                        <p>Admin Users</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon orange"><i class="bi bi-diagram-3"></i></div>
                    <div class="stat-info">
                        <h3 id="totalEndpoints">45+</h3>
                        <p>API Endpoints</p>
                    </div>
                </div>
            </div>

            <!-- Users Section -->
            <div class="section-card" id="users">
                <div class="section-header">
                    <h5><i class="bi bi-people me-2"></i>User Management</h5>
                    <button class="btn btn-light btn-sm" onclick="refreshUsers()">
                        <i class="bi bi-arrow-clockwise me-1"></i>Refresh
                    </button>
                </div>
                <div class="section-body">
                    <div class="table-responsive">
                        <table class="user-table" id="usersTable">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Name</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Status</th>
                                    <th>Joined</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (!empty($users)): ?>
                                    <?php foreach ($users as $user): ?>
                                    <tr data-user-id="<?= $user['id'] ?>">
                                        <td>#<?= $user['id'] ?></td>
                                        <td>
                                            <strong><?= htmlspecialchars($user['name']) ?></strong>
                                        </td>
                                        <td><?= htmlspecialchars($user['email']) ?></td>
                                        <td>
                                            <span class="role-badge <?= $user['role'] ?>"><?= $user['role'] ?></span>
                                        </td>
                                        <td>
                                            <span class="status-badge <?= $user['is_verified'] ? 'verified' : 'pending' ?>">
                                                <?= $user['is_verified'] ? 'Verified' : 'Pending' ?>
                                            </span>
                                        </td>
                                        <td><?= date('M d, Y', strtotime($user['created_at'])) ?></td>
                                        <td>
                                            <button class="action-btn edit" onclick="editUser(<?= $user['id'] ?>)">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                            <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                            <button class="action-btn delete" onclick="deleteUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['name']) ?>')">
                                                <i class="bi bi-trash"></i>
                                            </button>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <tr><td colspan="7" class="text-center">No users found</td></tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Endpoints Section -->
            <div class="section-card" id="endpoints">
                <div class="section-header">
                    <h5><i class="bi bi-diagram-3 me-2"></i>System Endpoints</h5>
                    <input type="text" class="form-control form-control-sm" style="max-width: 250px;" 
                           placeholder="Filter endpoints..." id="endpointFilter" onkeyup="filterEndpoints()">
                </div>
                <div class="section-body">
                    <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                        <table class="user-table endpoint-table" id="endpointsTable">
                            <thead style="position: sticky; top: 0; background: white;">
                                <tr>
                                    <th>Method</th>
                                    <th>Path</th>
                                    <th>Name</th>
                                    <th>Category</th>
                                    <th>Auth</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody id="endpointsBody">
                                <tr><td colspan="6" class="text-center">Loading endpoints...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Activity Section -->
            <div class="section-card" id="activity">
                <div class="section-header">
                    <h5><i class="bi bi-activity me-2"></i>Recent Activity</h5>
                </div>
                <div class="section-body">
                    <?php if (!empty($recentActivity)): ?>
                        <?php foreach ($recentActivity as $activity): ?>
                        <div class="activity-item">
                            <strong><?= htmlspecialchars($activity['user'] ?? 'System') ?></strong>
                            <span class="ms-2"><?= htmlspecialchars($activity['message']) ?></span>
                            <div class="activity-time mt-1"><?= date('M d, Y H:i', strtotime($activity['time'])) ?></div>
                        </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p class="text-muted text-center">No recent activity</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit User Modal -->
    <div class="modal fade" id="editUserModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-pencil me-2"></i>Edit User</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="editUserForm">
                        <input type="hidden" id="editUserId" name="user_id">
                        <div class="mb-3">
                            <label class="form-label">Name</label>
                            <input type="text" class="form-control" id="editName" name="name" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Email</label>
                            <input type="email" class="form-control" id="editEmail" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Phone</label>
                            <input type="text" class="form-control" id="editPhone" name="phone">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Role</label>
                            <select class="form-select" id="editRole" name="role">
                                <option value="user">User</option>
                                <option value="admin">Admin</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="editVerified" name="is_verified" value="1">
                                <label class="form-check-label">Verified</label>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="saveUser()">Save Changes</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div class="modal fade" id="deleteUserModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header bg-danger text-white">
                    <h5 class="modal-title"><i class="bi bi-exclamation-triangle me-2"></i>Confirm Delete</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete user <strong id="deleteUserName"></strong>?</p>
                    <p class="text-muted small">This action cannot be undone.</p>
                    <input type="hidden" id="deleteUserId">
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-danger" onclick="confirmDeleteUser()">Delete User</button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let endpointsData = [];

        // Initialize on page load
        $(document).ready(function() {
            loadEndpoints();
        });

        // Load endpoints from API
        function loadEndpoints() {
            $.get(MDIR + 'admin/endpoints', function(response) {
                if (response.success) {
                    endpointsData = response.endpoints;
                    renderEndpoints(endpointsData);
                    $('#totalEndpoints').text(response.total);
                }
            }).fail(function() {
                $('#endpointsBody').html('<tr><td colspan="6" class="text-center text-danger">Failed to load endpoints</td></tr>');
            });
        }

        // Render endpoints table
        function renderEndpoints(endpoints) {
            let html = '';
            endpoints.forEach(ep => {
                html += `
                    <tr>
                        <td><span class="method-badge ${ep.method.toLowerCase()}">${ep.method}</span></td>
                        <td><code class="endpoint-path">${ep.path}</code></td>
                        <td>${ep.name}</td>
                        <td><span class="category-badge">${ep.category}</span></td>
                        <td>${ep.auth ? '<i class="bi bi-lock-fill text-warning"></i>' : '<i class="bi bi-unlock text-success"></i>'}</td>
                        <td><span class="badge bg-success">Active</span></td>
                    </tr>
                `;
            });
            $('#endpointsBody').html(html);
        }

        // Filter endpoints
        function filterEndpoints() {
            const filter = $('#endpointFilter').val().toLowerCase();
            const filtered = endpointsData.filter(ep => 
                ep.path.toLowerCase().includes(filter) || 
                ep.name.toLowerCase().includes(filter) ||
                ep.category.toLowerCase().includes(filter)
            );
            renderEndpoints(filtered);
        }

        // Refresh users
        function refreshUsers() {
            location.reload();
        }

        // Edit user
        function editUser(userId) {
            $.get(MDIR + 'admin/get-user', { id: userId }, function(response) {
                if (response.success) {
                    const user = response.user;
                    $('#editUserId').val(user.id);
                    $('#editName').val(user.name);
                    $('#editEmail').val(user.email);
                    $('#editPhone').val(user.phone || '');
                    $('#editRole').val(user.role);
                    $('#editVerified').prop('checked', user.is_verified == 1);
                    new bootstrap.Modal('#editUserModal').show();
                } else {
                    alert('Failed to load user data');
                }
            });
        }

        // Save user changes
        function saveUser() {
            const formData = new FormData($('#editUserForm')[0]);
            formData.append('is_verified', $('#editVerified').is(':checked') ? 1 : 0);

            $.ajax({
                url: MDIR + 'admin/update-user',
                method: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function(response) {
                    if (response.success) {
                        bootstrap.Modal.getInstance('#editUserModal').hide();
                        location.reload();
                    } else {
                        alert(response.message || 'Failed to update user');
                    }
                },
                error: function() {
                    alert('Error updating user');
                }
            });
        }

        // Delete user
        function deleteUser(userId, userName) {
            $('#deleteUserId').val(userId);
            $('#deleteUserName').text(userName);
            new bootstrap.Modal('#deleteUserModal').show();
        }

        // Confirm delete
        function confirmDeleteUser() {
            const userId = $('#deleteUserId').val();
            $.post(MDIR + 'admin/delete-user', { user_id: userId }, function(response) {
                if (response.success) {
                    bootstrap.Modal.getInstance('#deleteUserModal').hide();
                    location.reload();
                } else {
                    alert(response.message || 'Failed to delete user');
                }
            });
        }
    </script>
</body>
</html>
