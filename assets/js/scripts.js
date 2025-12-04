/**
 * CyberHawk Scripts - Class-Based Architecture
 *
 * Main application classes for traffic logs and notifications management
 */

// ============================================================================
// TrafficLogsManager Class
// ============================================================================

class TrafficLogsManager {
    constructor(logsUrl = "assets/data/traffic_log.json") {
        this.logsUrl = logsUrl;
        this.tableBodySelector = "#logsTable tbody";
        this.refreshInterval = 3000; // 3 seconds
        this.intervalId = null;
    }

    init() {
        this.loadLogs();
        this.startAutoRefresh();
    }

    loadLogs() {
        $.getJSON(this.logsUrl, (data) => {
            this.renderLogs(data);
        }).fail((error) => {
            console.error("Failed to load traffic logs:", error);
        });
    }

    renderLogs(data) {
        const tbody = $(this.tableBodySelector);
        tbody.empty();

        if (!data || data.length === 0) {
            tbody.append('<tr><td colspan="10" class="text-center">No traffic data available</td></tr>');
            return;
        }

        data.forEach(packet => {
            const protocolName = this.getProtocolName(packet.protocol);
            const rowClass = this.getRowClass(packet.protocol);

            const row = `<tr class="${rowClass}">
                <td>${packet.timestamp || 'N/A'}</td>
                <td>${packet['Src IP'] || packet.src_ip || 'N/A'}</td>
                <td>${packet['Dst IP'] || packet.dst_ip || 'N/A'}</td>
                <td>${packet.protocol || 'N/A'}</td>
                <td>${packet['Src Port'] || packet.src_port || 'N/A'}</td>
                <td>${packet['Dst Port'] || packet.dst_port || 'N/A'}</td>
                <td>${packet['Total Length of Fwd Packets'] || packet.network_packet_size || 0}</td>
                <td>${packet.encryption_used || 'N/A'}</td>
                <td>${packet.ip_reputation_score || 'N/A'}</td>
                <td>${packet.unusual_time_access || 'N/A'}</td>
            </tr>`;

            tbody.append(row);
        });
    }

    getProtocolName(protoNum) {
        switch(parseInt(protoNum)) {
            case 6: return "TCP";
            case 17: return "UDP";
            case 1: return "ICMP";
            default: return "Other";
        }
    }

    getRowClass(protocol) {
        switch(parseInt(protocol)) {
            case 6: return "table-primary";
            case 17: return "table-success";
            default: return "";
        }
    }

    startAutoRefresh() {
        if (this.intervalId) {
            clearInterval(this.intervalId);
        }

        this.intervalId = setInterval(() => {
            this.loadLogs();
        }, this.refreshInterval);
    }

    stopAutoRefresh() {
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = null;
        }
    }

    setRefreshInterval(milliseconds) {
        this.refreshInterval = milliseconds;
        this.startAutoRefresh();
    }
}


// ============================================================================
// NotificationManager Class
// ============================================================================

class NotificationManager {
    constructor(alertsUrl = "assets/data/alerts.json") {
        this.alertsUrl = alertsUrl;
        this.notificationsList = [];
        this.notificationsShown = new Set();
        this.refreshInterval = 10000; // 10 seconds
        this.intervalId = null;

        this.selectors = {
            container: '#notificationsList',
            badge: '#notificationBadge'
        };
    }

    init() {
        this.requestNotificationPermission();
        this.loadNotifications();
        this.startAutoRefresh();
    }

    loadNotifications() {
        $.getJSON(this.alertsUrl, (alerts) => {
            this.processAlerts(alerts);
        }).fail(() => {
            this.updateBadge(0);
        });
    }

    processAlerts(alerts) {
        if (!alerts || alerts.length === 0) {
            this.updateBadge(0);
            return;
        }

        // Sort by timestamp (newest first)
        alerts.sort((a, b) => new Date(b.Timestamp) - new Date(a.Timestamp));

        // Get only the latest 10 alerts
        const latestAlerts = alerts.slice(0, 10);

        // Filter out notifications already shown
        const newAlerts = latestAlerts.filter(alert => {
            const alertId = `${alert.Timestamp}_${alert['Src IP']}_${alert['Attack Type']}`;
            return !this.notificationsShown.has(alertId);
        });

        // Add new alerts to the shown set
        newAlerts.forEach(alert => {
            const alertId = `${alert.Timestamp}_${alert['Src IP']}_${alert['Attack Type']}`;
            this.notificationsShown.add(alertId);
        });

        this.notificationsList = latestAlerts;
        this.displayNotifications();
        this.updateBadge(latestAlerts.length);

        // Show browser notifications for critical/high severity
        if (newAlerts.length > 0) {
            newAlerts.forEach(alert => {
                if (alert.Severity === 'CRITICAL' || alert.Severity === 'HIGH') {
                    this.showBrowserNotification(alert);
                }
            });
        }
    }

    displayNotifications() {
        const container = $(this.selectors.container);

        if (this.notificationsList.length === 0) {
            container.html(`
                <div class="text-center py-4 text-muted">
                    <i class="bi bi-bell-slash" style="font-size: 2rem;"></i>
                    <p class="mb-0 mt-2">No new notifications</p>
                </div>
            `);
            return;
        }

        let html = '';

        this.notificationsList.forEach(notification => {
            html += this.createNotificationHTML(notification);
        });

        container.html(html);
    }

    createNotificationHTML(notification) {
        const severity = notification.Severity || 'LOW';
        const severityColor = this.getSeverityColor(severity);
        const severityIcon = this.getSeverityIcon(severity);
        const timeAgo = this.getTimeAgo(notification.Timestamp);

        return `
            <div class="notification-item border-bottom p-3"
                 style="cursor: pointer; transition: background 0.2s;"
                 onmouseover="this.style.background='#f8f9fa'"
                 onmouseout="this.style.background='white'">

                <div class="d-flex align-items-start">
                    <div class="me-3">
                        <i class="bi ${severityIcon}"
                           style="font-size: 1.5rem; color: ${severityColor};"></i>
                    </div>

                    <div class="flex-grow-1">
                        <div class="d-flex justify-content-between align-items-start mb-1">
                            <strong class="text-dark">${notification['Attack Type']}</strong>
                            <span class="badge"
                                  style="background: ${severityColor}; font-size: 0.7rem;">
                                ${severity}
                            </span>
                        </div>

                        <p class="mb-1 small text-muted">
                            Source: ${notification['Src IP']}:${notification['Src Port']} →
                            ${notification['Dst IP']}:${notification['Dst Port']}
                        </p>

                        <div class="d-flex justify-content-between align-items-center">
                            <small class="text-muted">
                                <i class="bi bi-clock me-1"></i>${timeAgo}
                            </small>
                            <small class="text-muted">
                                Confidence: ${(notification.Confidence * 100).toFixed(1)}%
                            </small>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    updateBadge(count) {
        const badge = $(this.selectors.badge);

        if (count > 0) {
            badge.text(count > 99 ? '99+' : count);
            badge.show();
        } else {
            badge.hide();
        }
    }

    getSeverityColor(severity) {
        const colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        };
        return colors[severity] || '#6c757d';
    }

    getSeverityIcon(severity) {
        const icons = {
            'CRITICAL': 'bi-exclamation-triangle-fill',
            'HIGH': 'bi-exclamation-circle-fill',
            'MEDIUM': 'bi-info-circle-fill',
            'LOW': 'bi-check-circle-fill'
        };
        return icons[severity] || 'bi-bell-fill';
    }

    getTimeAgo(timestamp) {
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

    clearAll() {
        this.notificationsList = [];
        this.notificationsShown.clear();
        this.displayNotifications();
        this.updateBadge(0);
    }

    showBrowserNotification(alert) {
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
            Notification.requestPermission().then((permission) => {
                if (permission === "granted") {
                    new Notification("CyberHawk Security Alert", {
                        body: `${alert['Attack Type']} detected from ${alert['Src IP']}`,
                        icon: "assets/images/logo.png"
                    });
                }
            });
        }
    }

    requestNotificationPermission() {
        if ("Notification" in window && Notification.permission === "default") {
            Notification.requestPermission();
        }
    }

    startAutoRefresh() {
        if (this.intervalId) {
            clearInterval(this.intervalId);
        }

        this.intervalId = setInterval(() => {
            this.loadNotifications();
        }, this.refreshInterval);
    }

    stopAutoRefresh() {
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = null;
        }
    }
}


// ============================================================================
// UIManager Class
// ============================================================================

class UIManager {
    constructor() {
        this.sidebarSelector = "#sidebar";
    }

    toggleSidebar() {
        const sidebar = document.getElementById(this.sidebarSelector.replace('#', ''));
        if (sidebar) {
            sidebar.classList.toggle("minimized");
        }
    }

    init() {
        // Add any UI initialization here
        console.log("UIManager initialized");
    }
}


// ============================================================================
// Application Initialization
// ============================================================================

class CyberHawkApp {
    constructor() {
        this.trafficManager = null;
        this.notificationManager = null;
        this.uiManager = null;
    }

    init() {
        console.log("Initializing CyberHawk Application...");

        // Initialize all managers
        this.trafficManager = new TrafficLogsManager();
        this.notificationManager = new NotificationManager();
        this.uiManager = new UIManager();

        // Start all components
        this.trafficManager.init();
        this.notificationManager.init();
        this.uiManager.init();

        // Expose to window for external access
        window.cyberHawkApp = this;

        console.log("CyberHawk Application initialized successfully");
    }

    getTrafficManager() {
        return this.trafficManager;
    }

    getNotificationManager() {
        return this.notificationManager;
    }

    getUIManager() {
        return this.uiManager;
    }
}


// ============================================================================
// Legacy Function Support (for backward compatibility)
// ============================================================================

function toggleSidebar() {
    if (window.cyberHawkApp && window.cyberHawkApp.uiManager) {
        window.cyberHawkApp.uiManager.toggleSidebar();
    }
}

function clearAllNotifications() {
    if (window.cyberHawkApp && window.cyberHawkApp.notificationManager) {
        window.cyberHawkApp.notificationManager.clearAll();
    }
}


// ============================================================================
// Document Ready - Initialize Application
// ============================================================================

$(document).ready(function () {
    // Create and initialize the main application
    const app = new CyberHawkApp();
    app.init();
});
