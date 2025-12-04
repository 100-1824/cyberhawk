<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

/**
 * EmailService Class
 *
 * Purpose: Handles all email sending operations
 * Replaces: sendVerificationEmail() function
 */
class EmailService {

    private $mail;
    private $fromEmail;
    private $fromName;

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
        $this->mail->setFrom($this->fromEmail, $this->fromName);
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

            $this->mail->isHTML(true);
            $this->mail->Subject = 'Your CyberHawk Email Verification Code';
            $this->mail->Body = "
                <h2>CyberHawk Security Verification</h2>
                <p>Hello <b>$toName</b>,</p>
                <p>Your verification code is:</p>
                <h1 style='color:#0a74da;'>$code</h1>
                <p>Enter this code on the verification page to activate your account.</p>
            ";

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

            $this->mail->isHTML(true);
            $this->mail->Subject = 'CyberHawk Password Reset Request';
            $this->mail->Body = "
                <h2>CyberHawk Security - Password Reset</h2>
                <p>Hello <b>$toName</b>,</p>
                <p>We received a request to reset your password.</p>
                <p>Click the link below to reset your password:</p>
                <p><a href='$resetLink'>Reset Password</a></p>
                <p>If you didn't request this, please ignore this email.</p>
            ";

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

            $this->mail->isHTML(true);
            $this->mail->Subject = 'CyberHawk Security Alert';
            $this->mail->Body = "
                <h2>CyberHawk Security Alert</h2>
                <p>Hello <b>$toName</b>,</p>
                <p>We detected a security event that requires your attention:</p>
                <div style='background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545;'>
                    <p><strong>$alertMessage</strong></p>
                </div>
                <p>Please review your CyberHawk dashboard for more details.</p>
            ";

            $this->mail->send();
            return true;

        } catch (Exception $e) {
            error_log("Email sending failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Send generic email
     *
     * @param string $toEmail Recipient email address
     * @param string $toName Recipient name
     * @param string $subject Email subject
     * @param string $body Email body (HTML)
     * @return bool True on success, false on failure
     */
    public function sendEmail($toEmail, $toName, $subject, $body) {
        try {
            $this->mail->clearAddresses();
            $this->mail->addAddress($toEmail, $toName);

            $this->mail->isHTML(true);
            $this->mail->Subject = $subject;
            $this->mail->Body = $body;

            $this->mail->send();
            return true;

        } catch (Exception $e) {
            error_log("Email sending failed: " . $e->getMessage());
            return false;
        }
    }
}

?>
