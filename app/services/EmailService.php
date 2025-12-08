<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

/**
 * EmailService Class
 *
 * Purpose: Handles all email sending operations with professional HTML templates
 * Features: Modern email templates with CyberHawk branding
 */
class EmailService {

    private $mail;
    private $fromEmail;
    private $fromName;
    private $brandColor = '#0d6efd';
    private $brandColorDark = '#0a58ca';
    private $accentColor = '#00d4ff';

    /**
     * Constructor
     */
    public function __construct() {
        $this->mail = new PHPMailer(true);
        $this->fromEmail = 'ahmedsahni71@gmail.com';
        $this->fromName = 'CyberHawk Security';
        $this->configureSMTP();
    }

    /**
     * Configure SMTP settings
     */
    private function configureSMTP() {
        $this->mail->isSMTP();
        $this->mail->Host       = 'smtp.gmail.com';
        $this->mail->SMTPAuth   = true;
        $this->mail->Username   = 'ahmedsahni71@gmail.com';
        $this->mail->Password   = 'oolg ltfj vpux ctft';  // GMAIL APP PASSWORD
        $this->mail->SMTPSecure = 'tls';
        $this->mail->Port       = 587;
        $this->mail->CharSet    = 'UTF-8';
        $this->mail->setFrom($this->fromEmail, $this->fromName);
    }

    /**
     * Get the base email template wrapper
     * 
     * @param string $content Main content HTML
     * @param string $title Email title
     * @return string Complete HTML email
     */
    private function getEmailTemplate($content, $title = 'CyberHawk Security') {
        $year = date('Y');
        
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{$title}</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333333;">
    <!-- Main Container -->
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f4f6f9;">
        <tr>
            <td style="padding: 40px 20px;">
                <!-- Email Content Container -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="margin: 0 auto; max-width: 600px;">
                    
                    <!-- Header with Logo -->
                    <tr>
                        <td style="text-align: center; padding-bottom: 30px;">
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin: 0 auto;">
                                <tr>
                                    <td style="vertical-align: middle; padding-right: 12px;">
                                        <!-- Shield Icon -->
                                        <div style="width: 50px; height: 50px; background: linear-gradient(135deg, #0d6efd 0%, #00d4ff 100%); border-radius: 12px; display: inline-block; text-align: center; line-height: 50px;">
                                            <span style="font-size: 24px; color: #ffffff; font-weight: bold;">CH</span>
                                        </div>
                                    </td>
                                    <td style="vertical-align: middle;">
                                        <h1 style="margin: 0; font-size: 28px; font-weight: 700; color: #1a1a2e; letter-spacing: -0.5px;">
                                            Cyber<span style="color: #0d6efd;">Hawk</span>
                                        </h1>
                                        <p style="margin: 0; font-size: 12px; color: #6c757d; letter-spacing: 1px; text-transform: uppercase;">
                                            Intrusion Detection System
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Main Content Card -->
                    <tr>
                        <td>
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #ffffff; border-radius: 16px; border: 1px solid #e0e0e0; box-shadow: 0 4px 20px rgba(0,0,0,0.08);">
                                <tr>
                                    <td style="padding: 40px;">
                                        {$content}
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="padding-top: 30px; text-align: center;">
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                <tr>
                                    <td style="padding-bottom: 20px;">
                                        <hr style="border: none; height: 1px; background-color: #e0e0e0;">
                                    </td>
                                </tr>
                                <tr>
                                    <td style="color: #6c757d; font-size: 13px; line-height: 20px;">
                                        <p style="margin: 0 0 8px 0;">
                                            This email was sent by <strong style="color: #1a1a2e;">CyberHawk IDS</strong>
                                        </p>
                                        <p style="margin: 0 0 8px 0; color: #999999;">
                                            Protecting your network 24/7
                                        </p>
                                        <p style="margin: 0; color: #999999; font-size: 12px;">
                                            &copy; {$year} CyberHawk Security. All rights reserved.
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
HTML;
    }

    /**
     * Send verification email
     *
     * @param string $toEmail Recipient email address
     * @param string $toName Recipient name
     * @param string $code Verification code
     * @return bool True on success, false on failure
     */
    public function sendVerificationEmail($toEmail, $toName, $code) {
        try {
            $this->mail->clearAddresses();
            $this->mail->addAddress($toEmail, $toName);

            $content = <<<HTML
                <!-- Greeting -->
                <h2 style="margin: 0 0 20px 0; font-size: 24px; font-weight: 600; color: #1a1a2e;">
                    Email Verification
                </h2>
                <p style="margin: 0 0 25px 0; font-size: 16px; color: #555555; line-height: 24px;">
                    Hello <strong style="color: #1a1a2e;">{$toName}</strong>,
                </p>
                <p style="margin: 0 0 25px 0; font-size: 16px; color: #555555; line-height: 24px;">
                    Thank you for registering with CyberHawk. Please use the verification code below to complete your account setup:
                </p>
                
                <!-- Verification Code Box -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: 30px 0;">
                    <tr>
                        <td style="text-align: center;">
                            <div style="display: inline-block; background: linear-gradient(135deg, #f0f7ff 0%, #e6f3ff 100%); border: 2px solid #0d6efd; border-radius: 12px; padding: 25px 50px;">
                                <p style="margin: 0 0 8px 0; font-size: 12px; color: #6c757d; text-transform: uppercase; letter-spacing: 2px;">
                                    Your Verification Code
                                </p>
                                <h1 style="margin: 0; font-size: 42px; font-weight: 700; color: #0d6efd; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                                    {$code}
                                </h1>
                            </div>
                        </td>
                    </tr>
                </table>
                
                <!-- Instructions -->
                <p style="margin: 0 0 15px 0; font-size: 14px; color: #6c757d; line-height: 22px;">
                    Enter this code on the verification page to activate your account. This code will expire in <strong style="color: #dc3545;">15 minutes</strong>.
                </p>
                
                <!-- Security Notice -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-top: 30px; background-color: #fff3cd; border-radius: 8px; border-left: 4px solid #ffc107;">
                    <tr>
                        <td style="padding: 15px 20px;">
                            <p style="margin: 0; font-size: 13px; color: #856404;">
                                <strong>Security Notice:</strong> If you didn't create an account with CyberHawk, please disregard this email.
                            </p>
                        </td>
                    </tr>
                </table>
HTML;

            $this->mail->isHTML(true);
            $this->mail->Subject = 'Your CyberHawk Email Verification Code';
            $this->mail->Body = $this->getEmailTemplate($content, 'Email Verification - CyberHawk');

            $this->mail->send();
            return true;

        } catch (Exception $e) {
            error_log("Email sending failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Send password reset email
     *
     * @param string $toEmail Recipient email address
     * @param string $toName Recipient name
     * @param string $resetToken Password reset token
     * @return bool True on success, false on failure
     */
    public function sendPasswordResetEmail($toEmail, $toName, $resetToken) {
        try {
            $this->mail->clearAddresses();
            $this->mail->addAddress($toEmail, $toName);

            $resetLink = MDIR . "reset-password?token=" . $resetToken;

            $content = <<<HTML
                <!-- Greeting -->
                <h2 style="margin: 0 0 20px 0; font-size: 24px; font-weight: 600; color: #1a1a2e;">
                    Password Reset Request
                </h2>
                <p style="margin: 0 0 25px 0; font-size: 16px; color: #555555; line-height: 24px;">
                    Hello <strong style="color: #1a1a2e;">{$toName}</strong>,
                </p>
                <p style="margin: 0 0 25px 0; font-size: 16px; color: #555555; line-height: 24px;">
                    We received a request to reset the password for your CyberHawk account. Click the button below to set a new password:
                </p>
                
                <!-- Reset Button -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: 35px 0;">
                    <tr>
                        <td style="text-align: center;">
                            <a href="{$resetLink}" style="display: inline-block; background: linear-gradient(135deg, #0d6efd 0%, #0a58ca 100%); color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 600; padding: 16px 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(13,110,253,0.3);">
                                Reset My Password
                            </a>
                        </td>
                    </tr>
                </table>
                
                <!-- Alternative Link -->
                <p style="margin: 0 0 15px 0; font-size: 14px; color: #6c757d; line-height: 22px;">
                    Or copy and paste this link into your browser:
                </p>
                <p style="margin: 0 0 25px 0; font-size: 13px; color: #0d6efd; word-break: break-all; background-color: #f8f9fa; padding: 12px; border-radius: 6px; border: 1px solid #e0e0e0;">
                    {$resetLink}
                </p>
                
                <!-- Expiry Notice -->
                <p style="margin: 0 0 15px 0; font-size: 14px; color: #6c757d; line-height: 22px;">
                    This link will expire in <strong style="color: #dc3545;">1 hour</strong> for security reasons.
                </p>
                
                <!-- Security Notice -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-top: 30px; background-color: #fff3cd; border-radius: 8px; border-left: 4px solid #ffc107;">
                    <tr>
                        <td style="padding: 15px 20px;">
                            <p style="margin: 0; font-size: 13px; color: #856404;">
                                <strong>Didn't request this?</strong> If you didn't request a password reset, please ignore this email. Your account is secure.
                            </p>
                        </td>
                    </tr>
                </table>
HTML;

            $this->mail->isHTML(true);
            $this->mail->Subject = 'CyberHawk Password Reset Request';
            $this->mail->Body = $this->getEmailTemplate($content, 'Password Reset - CyberHawk');

            $this->mail->send();
            return true;

        } catch (Exception $e) {
            error_log("Email sending failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Send security alert email
     *
     * @param string $toEmail Recipient email address
     * @param string $toName Recipient name
     * @param string $alertMessage Alert message
     * @return bool True on success, false on failure
     */
    public function sendSecurityAlertEmail($toEmail, $toName, $alertMessage) {
        try {
            $this->mail->clearAddresses();
            $this->mail->addAddress($toEmail, $toName);

            $timestamp = date('F j, Y \a\t g:i A');

            $content = <<<HTML
                <!-- Alert Badge -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 25px;">
                    <tr>
                        <td>
                            <span style="display: inline-block; background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: #ffffff; font-size: 11px; font-weight: 700; padding: 6px 12px; border-radius: 20px; text-transform: uppercase; letter-spacing: 1px;">
                                ! SECURITY ALERT
                            </span>
                        </td>
                    </tr>
                </table>
                
                <!-- Greeting -->
                <h2 style="margin: 0 0 20px 0; font-size: 24px; font-weight: 600; color: #1a1a2e;">
                    Security Event Detected
                </h2>
                <p style="margin: 0 0 25px 0; font-size: 16px; color: #555555; line-height: 24px;">
                    Hello <strong style="color: #1a1a2e;">{$toName}</strong>,
                </p>
                <p style="margin: 0 0 25px 0; font-size: 16px; color: #555555; line-height: 24px;">
                    CyberHawk IDS has detected a security event that requires your immediate attention:
                </p>
                
                <!-- Alert Box -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: 25px 0; background-color: #f8d7da; border-radius: 12px; border-left: 4px solid #dc3545;">
                    <tr>
                        <td style="padding: 25px;">
                            <p style="margin: 0 0 10px 0; font-size: 12px; color: #6c757d; text-transform: uppercase; letter-spacing: 1px;">
                                Alert Details
                            </p>
                            <p style="margin: 0; font-size: 16px; color: #721c24; font-weight: 500; line-height: 26px;">
                                {$alertMessage}
                            </p>
                            <p style="margin: 15px 0 0 0; font-size: 13px; color: #6c757d;">
                                <strong>Detected at:</strong> {$timestamp}
                            </p>
                        </td>
                    </tr>
                </table>
                
                <!-- Action Button -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: 30px 0;">
                    <tr>
                        <td style="text-align: center;">
                            <a href="#" style="display: inline-block; background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 600; padding: 16px 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(220,53,69,0.3);">
                                View in Dashboard
                            </a>
                        </td>
                    </tr>
                </table>
                
                <!-- Recommendations -->
                <h3 style="margin: 30px 0 15px 0; font-size: 16px; font-weight: 600; color: #1a1a2e;">
                    Recommended Actions:
                </h3>
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                    <tr>
                        <td style="padding: 8px 0; color: #555555; font-size: 14px;">
                            * Review the affected systems immediately
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #555555; font-size: 14px;">
                            * Check for any unauthorized access attempts
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #555555; font-size: 14px;">
                            * Update security rules if necessary
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #555555; font-size: 14px;">
                            * Contact your security team if the threat persists
                        </td>
                    </tr>
                </table>
HTML;

            $this->mail->isHTML(true);
            $this->mail->Subject = 'CyberHawk Security Alert - Immediate Action Required';
            $this->mail->Body = $this->getEmailTemplate($content, 'Security Alert - CyberHawk');

            $this->mail->send();
            return true;

        } catch (Exception $e) {
            error_log("Email sending failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Send report email with formatted content
     *
     * @param string $toEmail Recipient email address
     * @param string $toName Recipient name
     * @param string $subject Email subject
     * @param string $reportType Type of report
     * @param array $reportData Report data array
     * @return bool True on success, false on failure
     */
    public function sendReportEmail($toEmail, $toName, $subject, $reportType, $reportData) {
        try {
            $this->mail->clearAddresses();
            $this->mail->addAddress($toEmail, $toName);

            $timestamp = date('F j, Y \a\t g:i A');
            $reportTypeDisplay = ucfirst($reportType);
            
            // Build stats section based on report data
            $statsHtml = $this->buildReportStatsHtml($reportData);
            $detailsHtml = $this->buildReportDetailsHtml($reportData);

            $content = <<<HTML
                <!-- Report Badge -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 25px;">
                    <tr>
                        <td>
                            <span style="display: inline-block; background: linear-gradient(135deg, #0d6efd 0%, #0a58ca 100%); color: #ffffff; font-size: 11px; font-weight: 700; padding: 6px 12px; border-radius: 20px; text-transform: uppercase; letter-spacing: 1px;">
                                SECURITY REPORT
                            </span>
                        </td>
                    </tr>
                </table>
                
                <!-- Greeting -->
                <h2 style="margin: 0 0 20px 0; font-size: 24px; font-weight: 600; color: #1a1a2e;">
                    {$reportTypeDisplay} Report
                </h2>
                <p style="margin: 0 0 25px 0; font-size: 16px; color: #555555; line-height: 24px;">
                    Hello <strong style="color: #1a1a2e;">{$toName}</strong>,
                </p>
                <p style="margin: 0 0 25px 0; font-size: 16px; color: #555555; line-height: 24px;">
                    Your requested <strong style="color: #0d6efd;">{$reportTypeDisplay} Report</strong> from CyberHawk IDS is ready. Here's a summary of the findings:
                </p>
                
                <!-- Stats Grid -->
                {$statsHtml}
                
                <!-- Report Details -->
                {$detailsHtml}
                
                <!-- Generated Timestamp -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0;">
                    <tr>
                        <td style="color: #6c757d; font-size: 13px;">
                            <strong>Report Generated:</strong> {$timestamp}
                        </td>
                    </tr>
                </table>
                
                <!-- Action Note -->
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-top: 20px; background-color: #e7f3ff; border-radius: 8px; border-left: 4px solid #0d6efd;">
                    <tr>
                        <td style="padding: 15px 20px;">
                            <p style="margin: 0; font-size: 13px; color: #0d6efd;">
                                <strong>Tip:</strong> Log into your CyberHawk dashboard for real-time monitoring and detailed analytics.
                            </p>
                        </td>
                    </tr>
                </table>
HTML;

            $this->mail->isHTML(true);
            $this->mail->Subject = $subject;
            $this->mail->Body = $this->getEmailTemplate($content, $subject);

            $this->mail->send();
            return true;

        } catch (Exception $e) {
            error_log("Email sending failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Build HTML for report stats section
     * 
     * @param array $data Report data
     * @return string HTML for stats
     */
    private function buildReportStatsHtml($data) {
        // Parse the data if it's a JSON string
        if (is_string($data)) {
            $data = json_decode($data, true) ?? [];
        }

        // Extract relevant stats
        $stats = [];
        
        if (isset($data['total_alerts'])) {
            $stats[] = ['label' => 'Total Alerts', 'value' => $data['total_alerts'], 'color' => '#ffc107'];
        }
        if (isset($data['threats_detected'])) {
            $stats[] = ['label' => 'Threats Detected', 'value' => $data['threats_detected'], 'color' => '#dc3545'];
        }
        if (isset($data['malware_detected'])) {
            $stats[] = ['label' => 'Malware Found', 'value' => $data['malware_detected'], 'color' => '#dc3545'];
        }
        if (isset($data['blocked'])) {
            $stats[] = ['label' => 'Blocked', 'value' => $data['blocked'], 'color' => '#28a745'];
        }
        if (isset($data['total_scans'])) {
            $stats[] = ['label' => 'Total Scans', 'value' => $data['total_scans'], 'color' => '#17a2b8'];
        }
        if (isset($data['clean_files'])) {
            $stats[] = ['label' => 'Clean Files', 'value' => $data['clean_files'], 'color' => '#28a745'];
        }

        if (empty($stats)) {
            return '';
        }

        $html = '<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: 25px 0;"><tr>';
        
        foreach ($stats as $index => $stat) {
            $html .= <<<HTML
                <td style="width: 50%; padding: 10px; vertical-align: top;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f8f9fa; border-radius: 10px; border: 1px solid #e0e0e0;">
                        <tr>
                            <td style="padding: 20px; text-align: center;">
                                <p style="margin: 0 0 5px 0; font-size: 32px; font-weight: 700; color: {$stat['color']};">{$stat['value']}</p>
                                <p style="margin: 0; font-size: 12px; color: #6c757d; text-transform: uppercase; letter-spacing: 1px;">{$stat['label']}</p>
                            </td>
                        </tr>
                    </table>
                </td>
HTML;
            // Add row break after every 2 items
            if (($index + 1) % 2 === 0 && $index < count($stats) - 1) {
                $html .= '</tr><tr>';
            }
        }
        
        $html .= '</tr></table>';
        return $html;
    }

    /**
     * Build HTML for report details section
     * 
     * @param array $data Report data
     * @return string HTML for details
     */
    private function buildReportDetailsHtml($data) {
        // Parse the data if it's a JSON string
        if (is_string($data)) {
            $data = json_decode($data, true) ?? [];
        }

        $html = '<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: 25px 0; background-color: #f8f9fa; border-radius: 10px; border: 1px solid #e0e0e0;">';
        $html .= '<tr><td style="padding: 20px;">';
        $html .= '<h3 style="margin: 0 0 15px 0; font-size: 14px; font-weight: 600; color: #1a1a2e; text-transform: uppercase; letter-spacing: 1px;">Report Details</h3>';
        
        $html .= '<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">';
        
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $value = json_encode($value, JSON_PRETTY_PRINT);
            }
            $label = ucwords(str_replace(['_', '-'], ' ', $key));
            $displayValue = is_string($value) && strlen($value) > 100 ? substr($value, 0, 100) . '...' : $value;
            
            $html .= <<<HTML
                <tr>
                    <td style="padding: 10px 0; border-bottom: 1px solid #e0e0e0; color: #6c757d; font-size: 13px; width: 40%; vertical-align: top;">
                        {$label}
                    </td>
                    <td style="padding: 10px 0; border-bottom: 1px solid #e0e0e0; color: #1a1a2e; font-size: 13px; font-weight: 500;">
                        {$displayValue}
                    </td>
                </tr>
HTML;
        }
        
        $html .= '</table>';
        $html .= '</td></tr></table>';
        
        return $html;
    }

    /**
     * Send generic email with template wrapper
     *
     * @param string $toEmail Recipient email address
     * @param string $toName Recipient name
     * @param string $subject Email subject
     * @param string $body Email body content (will be wrapped in template)
     * @return bool True on success, false on failure
     */
    public function sendEmail($toEmail, $toName, $subject, $body) {
        try {
            $this->mail->clearAddresses();
            $this->mail->addAddress($toEmail, $toName);

            // Wrap the body content in the professional template
            $content = <<<HTML
                <p style="margin: 0 0 25px 0; font-size: 16px; color: #555555; line-height: 24px;">
                    Hello <strong style="color: #1a1a2e;">{$toName}</strong>,
                </p>
                <div style="font-size: 15px; color: #555555; line-height: 24px;">
                    {$body}
                </div>
HTML;

            $this->mail->isHTML(true);
            $this->mail->Subject = $subject;
            $this->mail->Body = $this->getEmailTemplate($content, $subject);

            $this->mail->send();
            return true;

        } catch (Exception $e) {
            error_log("Email sending failed: " . $e->getMessage());
            return false;
        }
    }
}

?>
