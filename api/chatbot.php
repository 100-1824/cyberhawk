<?php
/**
 * CyberHawk AI Chatbot API
 * Handles chatbot queries and provides intelligent responses
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit();
}

// Get request data
$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (!isset($data['message']) || empty(trim($data['message']))) {
    echo json_encode(['success' => false, 'error' => 'Message is required']);
    exit();
}

$userMessage = trim($data['message']);

// Get bot response
$response = getBotResponse($userMessage);

echo json_encode([
    'success' => true,
    'response' => $response,
    'timestamp' => date('Y-m-d H:i:s')
]);

/**
 * Generate intelligent bot response based on user query
 */
function getBotResponse($message) {
    $message = strtolower($message);

    // Knowledge base for CyberHawk
    $knowledgeBase = [
        // General Information
        'what is cyberhawk' => "CyberHawk is an advanced Intrusion Prevention System (IPS) designed to protect your network from cyber threats. It provides real-time monitoring, malware detection, ransomware protection, and comprehensive security reporting. Our system uses machine learning algorithms to detect and prevent various types of attacks before they can harm your infrastructure.",

        'cyberhawk' => "CyberHawk is your complete cybersecurity solution offering:\n• Real-time Intrusion Prevention\n• Advanced Malware Detection\n• Ransomware Protection\n• Comprehensive Security Reporting\n• Network Traffic Monitoring\n• Threat Intelligence Integration",

        // IPS Dashboard
        'ips' => "Our Intrusion Prevention System (IPS) provides real-time monitoring and protection against network threats. It analyzes network traffic patterns, identifies suspicious activities, and automatically blocks potential attacks. The IPS Dashboard shows:\n• Active threats and blocked attacks\n• Network traffic analysis\n• Security events timeline\n• System health status",

        'dashboard' => "The CyberHawk Dashboard provides a comprehensive overview of your security posture including:\n• Real-time threat detection statistics\n• Active connections and traffic analysis\n• Recent security events\n• System performance metrics\n• Quick access to all security features",

        'intrusion prevention' => "Our Intrusion Prevention System actively monitors your network for:\n• Port scanning attempts\n• DDoS attacks\n• SQL injection attempts\n• Cross-site scripting (XSS)\n• Brute force attacks\n• Malicious payload delivery\nIt automatically blocks threats and alerts administrators.",

        // Ransomware
        'ransomware' => "CyberHawk's Ransomware Protection module offers:\n• Behavioral analysis to detect encryption attempts\n• File integrity monitoring\n• Automatic backup triggers before suspicious activity\n• Ransomware signature database\n• Real-time blocking of ransomware processes\n• Recovery assistance tools",

        'ransomware detection' => "Our ransomware detection uses multiple techniques:\n1. Behavioral Analysis: Monitors file system activities for suspicious encryption patterns\n2. Signature Detection: Compares files against known ransomware signatures\n3. Heuristic Analysis: Identifies ransomware-like behavior\n4. Network Traffic Analysis: Detects C&C server communications\n5. Machine Learning: Identifies new ransomware variants",

        'ransomware protection' => "We protect against ransomware through:\n• Real-time file system monitoring\n• Automatic process termination\n• Network isolation of infected systems\n• Immediate backup creation\n• User notification and guidance\n• Forensic data collection for analysis",

        // Malware
        'malware' => "CyberHawk's Malware Detection provides:\n• Real-time scanning of files and processes\n• Signature-based detection\n• Heuristic analysis for unknown threats\n• Behavioral monitoring\n• Automatic quarantine of malicious files\n• Regular signature updates\n• Deep system scans",

        'malware detection' => "Our malware detection system uses:\n1. Signature Database: Identifies known malware variants\n2. Behavioral Analysis: Detects suspicious program behavior\n3. Sandboxing: Tests suspicious files in isolated environment\n4. Memory Analysis: Scans running processes\n5. Network Analysis: Identifies malicious communications\n6. Machine Learning: Detects zero-day threats",

        'virus' => "CyberHawk detects and removes various types of viruses including:\n• File infectors\n• Boot sector viruses\n• Macro viruses\n• Polymorphic viruses\n• Metamorphic viruses\nOur multi-layered approach ensures comprehensive protection.",

        // Reporting
        'reporting' => "The Reporting module provides:\n• Detailed security incident reports\n• Compliance reports (PCI DSS, HIPAA, GDPR)\n• Custom report generation\n• Scheduled automated reports\n• Export to PDF, CSV, and Excel\n• Trend analysis and statistics\n• Executive summaries",

        'reports' => "Generate comprehensive security reports including:\n• Threat Summary Reports\n• Incident Timeline Reports\n• Network Traffic Reports\n• Compliance Audit Reports\n• User Activity Reports\n• System Performance Reports\nAll reports can be scheduled and exported in multiple formats.",

        'how to use reporting' => "To use the Reporting feature:\n1. Navigate to 'Reporting' from the sidebar\n2. Select report type (Threat Summary, Compliance, Custom)\n3. Choose date range and filters\n4. Click 'Generate Report'\n5. Review the report online\n6. Export to PDF/CSV/Excel if needed\n7. Schedule recurring reports if desired",

        // Features
        'features' => "CyberHawk offers:\n• Real-time Intrusion Prevention (IPS)\n• Advanced Malware Detection\n• Ransomware Protection\n• Comprehensive Reporting\n• Network Traffic Analysis\n• Automated Threat Response\n• User & Entity Behavior Analytics (UEBA)\n• Integration with SIEM systems\n• Custom alerting rules",

        'how does it work' => "CyberHawk works through:\n1. Traffic Monitoring: Analyzes all network traffic\n2. Threat Detection: Uses signatures, heuristics, and ML\n3. Automated Response: Blocks threats automatically\n4. Alert Generation: Notifies administrators\n5. Logging & Reporting: Maintains detailed records\n6. Continuous Learning: Updates threat intelligence",

        'protection' => "CyberHawk protects against:\n• Network intrusions\n• Malware and viruses\n• Ransomware attacks\n• DDoS attacks\n• SQL injection\n• Cross-site scripting\n• Zero-day exploits\n• Advanced persistent threats (APTs)\n• Data exfiltration attempts",

        // Technical
        'how to use' => "To use CyberHawk:\n1. Log in to your dashboard\n2. Monitor real-time security events\n3. Check IPS alerts for intrusions\n4. Review malware and ransomware scans\n5. Generate security reports\n6. Configure settings as needed\n7. Set up custom alert rules\nThe system works automatically in the background!",

        'settings' => "In Settings, you can:\n• Configure notification preferences\n• Set up email alerts\n• Customize security rules\n• Manage user accounts\n• Update profile information\n• Configure backup settings\n• Set reporting schedules\n• Integrate with external tools",

        'alerts' => "CyberHawk sends alerts for:\n• Critical security threats\n• Malware detections\n• Ransomware attempts\n• Failed login attempts\n• System health issues\n• Policy violations\nAlerts can be sent via email, SMS, or in-app notifications.",

        // Support
        'help' => "I'm here to help! You can ask me about:\n• CyberHawk features and capabilities\n• How to use specific modules (IPS, Malware, Ransomware, Reporting)\n• Understanding security alerts\n• Best practices for cybersecurity\n• System configuration\n• Troubleshooting issues\nWhat would you like to know?",

        'support' => "For support:\n• Use this chatbot for quick answers\n• Check the documentation in Settings\n• Contact our support team at support@cyberhawk.com\n• Access knowledge base articles\n• Join our community forum\nI'm available 24/7 to answer your questions!",

        // Security Best Practices
        'best practices' => "Security Best Practices:\n1. Keep CyberHawk updated\n2. Review alerts daily\n3. Run regular scans\n4. Generate weekly reports\n5. Configure custom rules for your environment\n6. Enable all protection modules\n7. Train your team on security awareness\n8. Maintain regular backups\n9. Monitor network traffic patterns",

        'security' => "CyberHawk enhances your security through:\n• Multi-layered defense strategy\n• Real-time threat detection\n• Automated incident response\n• Continuous monitoring\n• Threat intelligence integration\n• Regular security updates\n• Compliance support\nYour security is our top priority!",
    ];

    // Try exact match first
    foreach ($knowledgeBase as $key => $response) {
        if (strpos($message, $key) !== false) {
            return $response;
        }
    }

    // Keyword-based matching
    $keywords = [
        'hello' => "Hello! 👋 Welcome to CyberHawk. I'm your AI assistant here to help you understand our cybersecurity platform. What would you like to know?",
        'hi' => "Hi there! I'm CyberHawk AI. I can help you with questions about our IPS, malware detection, ransomware protection, and reporting features. How can I assist you?",
        'thanks' => "You're welcome! If you have any more questions about CyberHawk, feel free to ask. I'm here to help! 😊",
        'thank you' => "My pleasure! Don't hesitate to reach out if you need more information about CyberHawk's security features.",
        'bye' => "Goodbye! Stay secure with CyberHawk. Feel free to come back anytime you have questions!",
    ];

    foreach ($keywords as $keyword => $response) {
        if (strpos($message, $keyword) !== false) {
            return $response;
        }
    }

    // Default response with suggestions
    return "I'd be happy to help you with that! Here are some topics I can assist you with:\n\n" .
           "• What is CyberHawk?\n" .
           "• How does IPS work?\n" .
           "• Ransomware detection and protection\n" .
           "• Malware detection features\n" .
           "• How to use reporting\n" .
           "• Security best practices\n\n" .
           "Please ask me about any of these topics or specific features you'd like to know more about!";
}
