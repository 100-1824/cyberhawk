const LOGS_URL = "assets/data/traffic_log.json";

function loadLogs() {
  $.getJSON(LOGS_URL, function(data) {
    const tbody = $("#logsTable tbody");
    tbody.empty();

    data.forEach(packet => {
      const protocolName = getProtocolName(packet.protocol);
      let rowClass = "";
      if (packet.protocol == 6) rowClass = "table-primary";
      else if (packet.protocol == 17) rowClass = "table-success";

      const row = `<tr class="${rowClass}">
        <td>${packet.timestamp}</td>
        <td>${packet.src_ip}</td>
        <td>${packet.dst_ip}</td>
        <td>${packet.protocol}</td>
        <td>${packet.src_port}</td>
        <td>${packet.dst_port}</td>
        <td>${packet.network_packet_size}</td>
        <td>${packet.encryption_used}</td>
        <td>${packet.ip_reputation_score}</td>
        <td>${packet.unusual_time_access}</td>
      </tr>`;

      tbody.append("yes");
    });
  });
}


// function updateSystemStatus() {
//   // Simulated values for CPU and Memory
//   $("#cpuUsage").text(Math.floor(Math.random() * 40) + 10 + "%");
//   $("#memUsage").text(Math.floor(Math.random() * 70) + 20 + "%");

//   // Real Network status
//   const netStatus = navigator.onLine ? "Connected" : "Disconnected";
//   const netStatusElem = $("#netStatus");

//   netStatusElem.text(netStatus);
//   netStatusElem.removeClass("text-success text-danger");

//   if (navigator.onLine) {
//     netStatusElem.addClass("text-success");
//   } else {
//     netStatusElem.addClass("text-danger");
//   }
// }

// // Optional: Listen to browser network changes
// window.addEventListener("online", updateSystemStatus);
// window.addEventListener("offline", updateSystemStatus);

// function getProtocolName(protoNum) {
//   switch(protoNum) {
//     case 6: return "TCP";
//     case 17: return "UDP";
//     case 1: return "ICMP";
//     default: return "Other";
//   }
// }

// // Search/filter functionality
// $("#searchInput").on("input", function() {
//   const val = $(this).val().toLowerCase();
//   $("#logsTable tbody tr").filter(function() {
//     $(this).toggle(
//       $(this).text().toLowerCase().indexOf(val) > -1
//     );
//   });
// });

function toggleSidebar() {
  document.getElementById("sidebar").classList.toggle("minimized");
}

// ==================== NOTIFICATIONS SYSTEM ====================

let notificationsList = [];
let notificationsShown = new Set();

// Load and display notifications from both security alerts and system notifications
function loadNotifications() {
    const baseUrl = window.location.pathname.split('/').slice(0, -1).join('/') + '/';

    // Load security alerts and system notifications in parallel
    Promise.all([
        $.getJSON("assets/data/alerts.json").catch(() => []),
        $.ajax({
            url: baseUrl + 'get-notifications',
            method: 'GET',
            dataType: 'json'
        }).catch(() => [])
    ]).then(([alerts, systemNotifications]) => {
        const allNotifications = [];

        // Process security alerts
        if (alerts && alerts.length > 0) {
            alerts.sort((a, b) => new Date(b.Timestamp) - new Date(a.Timestamp));
            const latestAlerts = alerts.slice(0, 10);

            latestAlerts.forEach(alert => {
                allNotifications.push({
                    id: `alert_${alert.Timestamp}_${alert['Src IP']}`,
                    type: 'security',
                    title: alert['Attack Type'],
                    severity: alert.Severity || 'LOW',
                    timestamp: alert.Timestamp,
                    data: alert
                });
            });

            // Check for new alerts for browser notifications
            const newAlerts = latestAlerts.filter(alert => {
                const alertId = `${alert.Timestamp}_${alert['Src IP']}_${alert['Attack Type']}`;
                return !notificationsShown.has(alertId);
            });

            newAlerts.forEach(alert => {
                const alertId = `${alert.Timestamp}_${alert['Src IP']}_${alert['Attack Type']}`;
                notificationsShown.add(alertId);
                if (alert.Severity === 'CRITICAL' || alert.Severity === 'HIGH') {
                    showBrowserNotification(alert);
                }
            });
        }

        // Process system notifications
        if (systemNotifications && systemNotifications.length > 0) {
            systemNotifications.slice(0, 10).forEach(notif => {
                allNotifications.push({
                    id: notif.id,
                    type: 'system',
                    title: notif.title,
                    message: notif.message,
                    severity: notif.type.toUpperCase(),
                    icon: notif.icon,
                    timestamp: notif.timestamp,
                    read: notif.read
                });
            });
        }

        // Sort all notifications by timestamp
        allNotifications.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        notificationsList = allNotifications.slice(0, 20); // Keep latest 20
        displayNotifications();

        // Count unread notifications
        const unreadCount = notificationsList.filter(n => n.type === 'system' ? !n.read : true).length;
        updateNotificationBadge(unreadCount);

    }).catch(error => {
        console.error('Error loading notifications:', error);
        updateNotificationBadge(0);
    });
}

// Display notifications in dropdown
function displayNotifications() {
    const container = $('#notificationsList');

    if (notificationsList.length === 0) {
        container.html(`
            <div class="text-center py-4 text-muted">
                <i class="bi bi-bell-slash" style="font-size: 2rem;"></i>
                <p class="mb-0 mt-2">No new notifications</p>
            </div>
        `);
        return;
    }

    let html = '';
    notificationsList.forEach(notification => {
        const severity = notification.severity || 'INFO';
        const severityColor = getSeverityColor(severity);
        const timeAgo = getTimeAgo(notification.timestamp);

        if (notification.type === 'security') {
            // Security alert notification
            const alert = notification.data;
            const severityIcon = getSeverityIcon(severity);

            html += `
                <div class="notification-item border-bottom p-3" style="cursor: pointer; transition: background 0.2s;"
                     onmouseover="this.style.background='#f8f9fa'"
                     onmouseout="this.style.background='white'">
                    <div class="d-flex align-items-start">
                        <div class="me-3">
                            <i class="bi ${severityIcon}" style="font-size: 1.5rem; color: ${severityColor};"></i>
                        </div>
                        <div class="flex-grow-1">
                            <div class="d-flex justify-content-between align-items-start mb-1">
                                <strong class="text-dark">${notification.title}</strong>
                                <span class="badge" style="background: ${severityColor}; font-size: 0.7rem;">
                                    ${severity}
                                </span>
                            </div>
                            <p class="mb-1 small text-muted">
                                Source: ${alert['Src IP']}:${alert['Src Port']} → ${alert['Dst IP']}:${alert['Dst Port']}
                            </p>
                            <div class="d-flex justify-content-between align-items-center">
                                <small class="text-muted">
                                    <i class="bi bi-clock me-1"></i>${timeAgo}
                                </small>
                                <small class="text-muted">
                                    Confidence: ${(alert.Confidence * 100).toFixed(1)}%
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            // System notification
            const icon = notification.icon || 'bi-info-circle';
            const readClass = notification.read ? 'opacity-75' : '';

            html += `
                <div class="notification-item border-bottom p-3 ${readClass}"
                     style="cursor: pointer; transition: background 0.2s;"
                     onmouseover="this.style.background='#f8f9fa'"
                     onmouseout="this.style.background='white'">
                    <div class="d-flex align-items-start">
                        <div class="me-3">
                            <i class="bi ${icon}" style="font-size: 1.5rem; color: ${severityColor};"></i>
                        </div>
                        <div class="flex-grow-1">
                            <div class="d-flex justify-content-between align-items-start mb-1">
                                <strong class="text-dark">${notification.title}</strong>
                                ${!notification.read ? '<span class="badge bg-primary" style="font-size: 0.6rem;">NEW</span>' : ''}
                            </div>
                            <p class="mb-1 small text-muted">${notification.message}</p>
                            <small class="text-muted">
                                <i class="bi bi-clock me-1"></i>${timeAgo}
                            </small>
                        </div>
                    </div>
                </div>
            `;
        }
    });

    container.html(html);
}

// Update notification badge count
function updateNotificationBadge(count) {
    const badge = $('#notificationBadge');
    if (count > 0) {
        badge.text(count > 99 ? '99+' : count);
        badge.show();
    } else {
        badge.hide();
    }
}

// Get severity color
function getSeverityColor(severity) {
    const sev = severity.toUpperCase();
    switch(sev) {
        // Security alert levels
        case 'CRITICAL': return '#dc3545';
        case 'HIGH': return '#fd7e14';
        case 'MEDIUM': return '#ffc107';
        case 'LOW': return '#28a745';
        // System notification types
        case 'SUCCESS': return '#28a745';
        case 'DANGER': return '#dc3545';
        case 'WARNING': return '#ffc107';
        case 'INFO': return '#0dcaf0';
        default: return '#6c757d';
    }
}

// Get severity icon
function getSeverityIcon(severity) {
    switch(severity) {
        case 'CRITICAL': return 'bi-exclamation-triangle-fill';
        case 'HIGH': return 'bi-exclamation-circle-fill';
        case 'MEDIUM': return 'bi-info-circle-fill';
        case 'LOW': return 'bi-check-circle-fill';
        default: return 'bi-bell-fill';
    }
}

// Calculate time ago
function getTimeAgo(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    const diffMs = now - time;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
}

// Clear all notifications
function clearAllNotifications() {
    notificationsList = [];
    notificationsShown.clear();
    displayNotifications();
    updateNotificationBadge(0);
}

// Show browser notification (requires permission)
function showBrowserNotification(alert) {
    if (!("Notification" in window)) {
        return;
    }

    if (Notification.permission === "granted") {
        new Notification("CyberHawk Security Alert", {
            body: `${alert['Attack Type']} detected from ${alert['Src IP']}`,
            icon: "assets/images/logo.png",
            badge: "assets/images/logo.png",
            tag: alert.Timestamp
        });
    } else if (Notification.permission !== "denied") {
        Notification.requestPermission().then(function (permission) {
            if (permission === "granted") {
                new Notification("CyberHawk Security Alert", {
                    body: `${alert['Attack Type']} detected from ${alert['Src IP']}`,
                    icon: "assets/images/logo.png"
                });
            }
        });
    }
}

// Request notification permission on page load
function requestNotificationPermission() {
    if ("Notification" in window && Notification.permission === "default") {
        Notification.requestPermission();
    }
}

$(document).ready(function() {
  loadLogs();

  setInterval(() => {
    loadLogs();
  }, 3000);

  // Initialize notifications
  requestNotificationPermission();
  loadNotifications();

  // Refresh notifications every 10 seconds
  setInterval(loadNotifications, 10000);
});
