<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require DIR . "vendor/autoload.php";

function sendVerificationEmail($toEmail, $toName, $code) {
    $mail = new PHPMailer(true);

    try {
        // EC2/Gmail-safe settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; // For EC2, you can replace this with Amazon SES SMTP
        $mail->SMTPAuth   = true;
        $mail->Username   = 'ahmedsahni71@gmail.com';
        $mail->Password   = 'oolg ltfj vpux ctft';  // GMAIL APP PASSWORD
        $mail->SMTPSecure = 'tls';
        $mail->Port       = 587;

        // Sender
        $mail->setFrom('ahmedsahni71@gmail.com', 'CyberHawk Security');

        // Receiver
        $mail->addAddress($toEmail, $toName);

        // Email content
        $mail->isHTML(true);
        $mail->Subject = 'Your CyberHawk Email Verification Code';
        $mail->Body = "
            <h2>CyberHawk Security Verification</h2>
            <p>Hello <b>$toName</b>,</p>
            <p>Your verification code is:</p>
            <h1 style='color:#0a74da;'>$code</h1>
            <p>Enter this code on the verification page to activate your account.</p>
        ";

        $mail->send();
        return true;

    } catch (Exception $e) {
        return false;
    }
}
