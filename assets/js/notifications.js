/**
 * CyberHawk Notification System
 * Handles real-time task notifications
 */

(function() {
    'use strict';

    let notificationCheckInterval = null;
    const CHECK_INTERVAL = 10000; // Check every 10 seconds

    /**
     * Initialize the notification system
     */
    function initNotifications() {
        // Load notifications on page load
        loadNotifications();

        // Set up periodic checking
        if (!notificationCheckInterval) {
            notificationCheckInterval = setInterval(loadNotifications, CHECK_INTERVAL);
        }

        // Clean up interval when page is closed
        window.addEventListener('beforeunload', function() {
            if (notificationCheckInterval) {
                clearInterval(notificationCheckInterval);
            }
        });
    }

    /**
     * Load notifications from the server
     */
    function loadNotifications() {
        fetch(MDIR + 'get-notifications', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateNotificationUI(data.notifications, data.unread_count);
            }
        })
        .catch(error => {
            console.error('Error loading notifications:', error);
        });
    }

    /**
     * Update the notification UI
     */
    function updateNotificationUI(notifications, unreadCount) {
        const badge = document.getElementById('notificationBadge');
        const listContainer = document.getElementById('notificationsList');

        // Update badge
        if (unreadCount > 0) {
            badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
            badge.style.display = 'inline';
        } else {
            badge.style.display = 'none';
        }

        // Update notifications list
        if (notifications.length === 0) {
            listContainer.innerHTML = `
                <div class="text-center py-4 text-muted">
                    <i class="bi bi-bell-slash" style="font-size: 2rem;"></i>
                    <p class="mb-0 mt-2">No new notifications</p>
                </div>
            `;
        } else {
            listContainer.innerHTML = notifications.map(notif => createNotificationHTML(notif)).join('');
        }
    }

    /**
     * Create HTML for a single notification
     */
    function createNotificationHTML(notif) {
        const typeIcons = {
            'success': 'bi-check-circle-fill text-success',
            'info': 'bi-info-circle-fill text-info',
            'warning': 'bi-exclamation-triangle-fill text-warning',
            'error': 'bi-x-circle-fill text-danger'
        };

        const icon = typeIcons[notif.type] || typeIcons.info;
        const readClass = notif.is_read ? 'bg-light' : 'bg-white';
        const timeAgo = formatTimeAgo(notif.created_at);

        return `
            <div class="notification-item ${readClass} border-bottom p-3"
                 data-notification-id="${notif.id}"
                 style="cursor: pointer;">
                <div class="d-flex">
                    <div class="flex-shrink-0 me-3">
                        <i class="bi ${icon}" style="font-size: 1.5rem;"></i>
                    </div>
                    <div class="flex-grow-1" onclick="markNotificationAsRead('${notif.id}')">
                        <h6 class="mb-1 fw-bold">${escapeHtml(notif.title)}</h6>
                        <p class="mb-1 small">${escapeHtml(notif.message)}</p>
                        <small class="text-muted">
                            <i class="bi bi-clock me-1"></i>${timeAgo}
                        </small>
                    </div>
                    <div class="flex-shrink-0 ms-2">
                        <button class="btn btn-sm btn-link text-muted p-0"
                                onclick="deleteNotification('${notif.id}'); event.stopPropagation();"
                                title="Delete">
                            <i class="bi bi-x-lg"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Mark a notification as read
     */
    window.markNotificationAsRead = function(notificationId) {
        fetch(MDIR + 'mark-notification-read', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'notification_id=' + encodeURIComponent(notificationId)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadNotifications();
            }
        })
        .catch(error => {
            console.error('Error marking notification as read:', error);
        });
    };

    /**
     * Delete a notification
     */
    window.deleteNotification = function(notificationId) {
        fetch(MDIR + 'delete-notification', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'notification_id=' + encodeURIComponent(notificationId)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadNotifications();
                showToast('Notification deleted', 'success');
            }
        })
        .catch(error => {
            console.error('Error deleting notification:', error);
        });
    };

    /**
     * Clear all notifications
     */
    window.clearAllNotifications = function() {
        if (!confirm('Are you sure you want to clear all notifications?')) {
            return;
        }

        fetch(MDIR + 'clear-all-notifications', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadNotifications();
                showToast('All notifications cleared', 'success');
            }
        })
        .catch(error => {
            console.error('Error clearing notifications:', error);
        });
    };

    /**
     * Format time ago
     */
    function formatTimeAgo(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);

        if (seconds < 60) return 'Just now';
        if (seconds < 3600) return Math.floor(seconds / 60) + ' minutes ago';
        if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
        if (seconds < 604800) return Math.floor(seconds / 86400) + ' days ago';

        return date.toLocaleDateString();
    }

    /**
     * Escape HTML to prevent XSS
     */
    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    /**
     * Show toast notification
     */
    function showToast(message, type = 'info') {
        // Use notify.js if available
        if (typeof $.notify !== 'undefined') {
            $.notify(message, {
                className: type,
                position: 'top right'
            });
        } else {
            alert(message);
        }
    }

    /**
     * Add a new notification (can be called from other scripts)
     */
    window.addLocalNotification = function(title, message, type = 'info') {
        // Just trigger a reload of notifications
        // The server-side will have already added the notification
        setTimeout(loadNotifications, 500);
    };

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initNotifications);
    } else {
        initNotifications();
    }

})();
