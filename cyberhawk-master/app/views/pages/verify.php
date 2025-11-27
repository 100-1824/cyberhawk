<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Email Verification - CyberHawk</title>
</head>
<body>

<h2>Verify Your Email</h2>

<?php if (!empty($error)): ?>
  <p style="color:red"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<form method="POST" action="<?= MDIR ?>verify-email">
  <input type="text" name="code" placeholder="Enter Verification Code" required>
  <button type="submit">Verify Account</button>
</form>

</body>
</html>
