<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Register - CyberHawk</title>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet" />
  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      background: linear-gradient(135deg, #0a74da, #061a40);
      font-family: 'Poppins', sans-serif;
      color: #fff;
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
    }

    .register-container {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      border-radius: 15px;
      padding: 40px 50px;
      width: 360px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.37);
      position: relative;
      overflow: hidden;
    }

    .register-container::before {
      content: "CyberHawk";
      position: absolute;
      top: -40px;
      left: 50%;
      transform: translateX(-50%);
      font-size: 4rem;
      font-weight: 900;
      color: rgba(255, 255, 255, 0.1);
      letter-spacing: 8px;
      user-select: none;
      pointer-events: none;
      font-family: 'Poppins', sans-serif;
    }

    h2 {
      margin-bottom: 30px;
      font-weight: 600;
      letter-spacing: 2px;
      text-align: center;
      color: #ffffffdd;
    }

    input[type="text"],
    input[type="email"],
    input[type="password"] {
      width: 100%;
      padding: 14px 18px;
      margin-bottom: 20px;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      transition: background-color 0.3s ease, box-shadow 0.3s ease;
      background: rgba(255, 255, 255, 0.15);
      color: white;
    }

    input::placeholder {
      color: rgba(255, 255, 255, 0.7);
    }

    input:focus {
      background: rgba(255, 255, 255, 0.3);
      outline: none;
      box-shadow: 0 0 8px #0a74da;
    }

    button {
      width: 100%;
      padding: 14px 18px;
      background: #0a74da;
      border: none;
      border-radius: 8px;
      font-size: 18px;
      font-weight: 600;
      cursor: pointer;
      color: white;
      transition: background-color 0.3s ease;
    }

    button:hover {
      background: #084e8a;
    }

    .error, .success {
      padding: 12px 15px;
      border-radius: 8px;
      margin-bottom: 20px;
      text-align: center;
      font-weight: 600;
    }

    .error {
      background: #e74c3c;
      box-shadow: 0 0 8px #e74c3caa;
    }

    .success {
      background: #2ecc71;
      box-shadow: 0 0 8px #2ecc71aa;
    }

    p {
      margin-top: 15px;
      text-align: center;
      font-size: 14px;
      color: #ddd;
    }

    a {
      color: #0a74da;
      text-decoration: none;
      font-weight: 600;
    }

    a:hover {
      text-decoration: underline;
    }

    @media (max-width: 400px) {
      .register-container {
        width: 90%;
        padding: 30px 25px;
      }
    }
  </style>
</head>
<body>

  <div class="register-container">
    <h2>Create your CyberHawk account</h2>

    <?php if (!empty($error)): ?>
      <div class="error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if (!empty($_SESSION['success'])): ?>
      <div class="success"><?= htmlspecialchars($_SESSION['success']) ?></div>
      <?php unset($_SESSION['success']); ?>
    <?php endif; ?>

    <form method="POST" action="<?= MDIR ?>register">
      <input type="text" name="name" placeholder="Full Name" required value="<?= htmlspecialchars($_POST['name'] ?? '') ?>" />
      <input type="email" name="email" placeholder="Email address" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Register</button>
    </form>

    <p>Already have an account? <a href="<?= MDIR ?>login">Login here</a></p>
  </div>

</body>
</html>