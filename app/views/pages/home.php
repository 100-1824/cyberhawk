<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberHawk - Enterprise Intrusion Detection System</title>
    <meta name="description" content="CyberHawk is an enterprise-level Intrusion Detection System providing real-time threat detection, malware analysis, and ransomware protection.">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #0a74da;
            --primary-dark: #061a40;
            --accent: #00d4ff;
            --glass-bg: rgba(255, 255, 255, 0.1);
            --glass-border: rgba(255, 255, 255, 0.2);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 50%, #000814 100%);
            min-height: 100vh;
            color: #fff;
            overflow-x: hidden;
        }

        /* Animated Background */
        .bg-animation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            overflow: hidden;
        }

        .bg-animation::before {
            content: '';
            position: absolute;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle at 20% 80%, rgba(0, 212, 255, 0.15) 0%, transparent 40%),
                        radial-gradient(circle at 80% 20%, rgba(10, 116, 218, 0.2) 0%, transparent 40%),
                        radial-gradient(circle at 40% 40%, rgba(6, 26, 64, 0.3) 0%, transparent 50%);
            animation: bgPulse 15s ease-in-out infinite;
        }

        @keyframes bgPulse {
            0%, 100% { transform: translate(0, 0) scale(1); }
            50% { transform: translate(-5%, -5%) scale(1.1); }
        }

        /* Floating Particles */
        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
        }

        .particle {
            position: absolute;
            width: 4px;
            height: 4px;
            background: rgba(0, 212, 255, 0.6);
            border-radius: 50%;
            animation: float 8s infinite ease-in-out;
        }

        @keyframes float {
            0%, 100% { transform: translateY(100vh) rotate(0deg); opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { transform: translateY(-100vh) rotate(720deg); opacity: 0; }
        }

        /* Navigation */
        .navbar-custom {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--glass-border);
            padding: 15px 0;
            position: fixed;
            top: 0;
            width: 100%;
            z-index: 1000;
            transition: all 0.3s ease;
        }

        .navbar-custom.scrolled {
            background: rgba(6, 26, 64, 0.95);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
        }

        .navbar-brand {
            font-size: 1.8rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, var(--accent) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .navbar-brand i {
            color: var(--accent);
            -webkit-text-fill-color: var(--accent);
            margin-right: 8px;
        }

        .nav-link-custom {
            color: rgba(255, 255, 255, 0.85) !important;
            font-weight: 500;
            padding: 10px 20px !important;
            margin: 0 5px;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .nav-link-custom:hover {
            color: #fff !important;
            background: var(--glass-bg);
        }

        .btn-login {
            background: transparent;
            border: 2px solid var(--accent);
            color: var(--accent) !important;
            padding: 10px 30px !important;
            border-radius: 50px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .btn-login:hover {
            background: var(--accent);
            color: var(--primary-dark) !important;
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4);
        }

        .btn-signup {
            background: linear-gradient(135deg, var(--accent) 0%, var(--primary) 100%);
            border: none;
            color: #fff !important;
            padding: 12px 35px !important;
            border-radius: 50px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .btn-signup:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 212, 255, 0.5);
        }

        /* Hero Section */
        .hero {
            min-height: 100vh;
            display: flex;
            align-items: center;
            padding: 120px 0 80px;
            position: relative;
        }

        .hero-content {
            position: relative;
            z-index: 1;
        }

        .hero-badge {
            display: inline-block;
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            padding: 8px 20px;
            border-radius: 50px;
            font-size: 0.9rem;
            font-weight: 500;
            margin-bottom: 25px;
            backdrop-filter: blur(10px);
        }

        .hero-badge i {
            color: var(--accent);
            margin-right: 8px;
        }

        .hero h1 {
            font-size: 4rem;
            font-weight: 800;
            line-height: 1.1;
            margin-bottom: 25px;
        }

        .hero h1 span {
            background: linear-gradient(135deg, var(--accent) 0%, #fff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .hero p {
            font-size: 1.25rem;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 35px;
            max-width: 550px;
        }

        .hero-buttons {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }

        .btn-hero-primary {
            background: linear-gradient(135deg, var(--accent) 0%, var(--primary) 100%);
            border: none;
            color: #fff;
            padding: 18px 45px;
            border-radius: 50px;
            font-size: 1.1rem;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            transition: all 0.3s ease;
        }

        .btn-hero-primary:hover {
            color: #fff;
            transform: translateY(-3px);
            box-shadow: 0 10px 40px rgba(0, 212, 255, 0.5);
        }

        .btn-hero-secondary {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            color: #fff;
            padding: 18px 45px;
            border-radius: 50px;
            font-size: 1.1rem;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }

        .btn-hero-secondary:hover {
            color: #fff;
            background: rgba(255, 255, 255, 0.2);
            transform: translateY(-3px);
        }

        /* Hero Visual */
        .hero-visual {
            position: relative;
        }

        .shield-container {
            position: relative;
            width: 100%;
            height: 500px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .shield-icon {
            font-size: 15rem;
            background: linear-gradient(135deg, var(--accent) 0%, var(--primary) 50%, var(--primary-dark) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: shieldPulse 3s ease-in-out infinite;
            filter: drop-shadow(0 0 50px rgba(0, 212, 255, 0.5));
        }

        @keyframes shieldPulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }

        .orbit {
            position: absolute;
            border: 2px dashed rgba(0, 212, 255, 0.3);
            border-radius: 50%;
            animation: rotate 20s linear infinite;
        }

        .orbit-1 { width: 350px; height: 350px; }
        .orbit-2 { width: 450px; height: 450px; animation-duration: 30s; animation-direction: reverse; }
        .orbit-3 { width: 550px; height: 550px; animation-duration: 40s; }

        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .orbit-icon {
            position: absolute;
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, var(--accent), var(--primary));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.3rem;
            color: #fff;
            box-shadow: 0 5px 20px rgba(0, 212, 255, 0.5);
        }

        /* Stats Section */
        .stats-section {
            padding: 80px 0;
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border-top: 1px solid var(--glass-border);
            border-bottom: 1px solid var(--glass-border);
        }

        .stat-card {
            text-align: center;
            padding: 30px;
        }

        .stat-number {
            font-size: 3.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--accent) 0%, #fff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }

        .stat-label {
            font-size: 1.1rem;
            color: rgba(255, 255, 255, 0.7);
            font-weight: 500;
        }

        /* Features Section */
        .features-section {
            padding: 120px 0;
        }

        .section-header {
            text-align: center;
            margin-bottom: 60px;
        }

        .section-header h2 {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 20px;
        }

        .section-header p {
            font-size: 1.2rem;
            color: rgba(255, 255, 255, 0.7);
            max-width: 600px;
            margin: 0 auto;
        }

        .feature-card {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 40px 30px;
            height: 100%;
            transition: all 0.4s ease;
            position: relative;
            overflow: hidden;
        }

        .feature-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent), var(--primary));
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .feature-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            border-color: var(--accent);
        }

        .feature-card:hover::before {
            opacity: 1;
        }

        .feature-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--accent), var(--primary));
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            color: #fff;
            margin-bottom: 25px;
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.3);
        }

        .feature-card h3 {
            font-size: 1.4rem;
            font-weight: 600;
            margin-bottom: 15px;
        }

        .feature-card p {
            color: rgba(255, 255, 255, 0.7);
            line-height: 1.7;
        }

        /* CTA Section */
        .cta-section {
            padding: 120px 0;
            text-align: center;
            position: relative;
        }

        .cta-card {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            border-radius: 30px;
            padding: 80px 60px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 30px 80px rgba(0, 0, 0, 0.4);
        }

        .cta-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(0, 212, 255, 0.1) 0%, transparent 50%);
            animation: ctaPulse 10s ease-in-out infinite;
        }

        @keyframes ctaPulse {
            0%, 100% { transform: translate(0, 0); }
            50% { transform: translate(20%, 20%); }
        }

        .cta-card h2 {
            font-size: 2.8rem;
            font-weight: 700;
            margin-bottom: 20px;
            position: relative;
        }

        .cta-card p {
            font-size: 1.2rem;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 40px;
            position: relative;
        }

        /* Footer */
        footer {
            background: rgba(0, 0, 0, 0.3);
            padding: 40px 0;
            border-top: 1px solid var(--glass-border);
        }

        footer p {
            color: rgba(255, 255, 255, 0.6);
            margin: 0;
        }

        footer a {
            color: var(--accent);
            text-decoration: none;
        }

        /* Responsive */
        @media (max-width: 992px) {
            .hero h1 {
                font-size: 2.8rem;
            }
            
            .shield-container {
                height: 350px;
            }
            
            .shield-icon {
                font-size: 10rem;
            }
            
            .orbit-1 { width: 250px; height: 250px; }
            .orbit-2 { width: 320px; height: 320px; }
            .orbit-3 { display: none; }
        }

        @media (max-width: 768px) {
            .hero h1 {
                font-size: 2.2rem;
            }
            
            .hero-buttons {
                flex-direction: column;
            }
            
            .btn-hero-primary,
            .btn-hero-secondary {
                width: 100%;
                justify-content: center;
            }

            .stat-number {
                font-size: 2.5rem;
            }
        }
    </style>
</head>
<body>
    <!-- Background Animation -->
    <div class="bg-animation"></div>
    
    <!-- Particles -->
    <div class="particles">
        <div class="particle" style="left: 10%; animation-delay: 0s;"></div>
        <div class="particle" style="left: 20%; animation-delay: 2s;"></div>
        <div class="particle" style="left: 35%; animation-delay: 4s;"></div>
        <div class="particle" style="left: 50%; animation-delay: 1s;"></div>
        <div class="particle" style="left: 65%; animation-delay: 3s;"></div>
        <div class="particle" style="left: 80%; animation-delay: 5s;"></div>
        <div class="particle" style="left: 90%; animation-delay: 2.5s;"></div>
    </div>

    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-custom" id="mainNav">
        <div class="container">
            <a class="navbar-brand" href="<?= MDIR ?>">
                <i class="bi bi-shield-check"></i>CyberHawk
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse justify-content-end" id="navbarNav">
                <ul class="navbar-nav align-items-center">
                    <li class="nav-item">
                        <a class="nav-link nav-link-custom" href="#features">Features</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link nav-link-custom" href="#about">About</a>
                    </li>
                    <li class="nav-item ms-lg-3">
                        <a class="nav-link nav-link-custom btn-login" href="<?= MDIR ?>login">Login</a>
                    </li>
                    <li class="nav-item ms-lg-2">
                        <a class="nav-link nav-link-custom btn-signup" href="<?= MDIR ?>register">Sign Up</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-lg-6 hero-content">
                    <div class="hero-badge">
                        <i class="bi bi-lightning-charge-fill"></i>
                        Enterprise-Grade Security
                    </div>
                    <h1>Protect Your Network with <span>AI-Powered</span> Intelligence</h1>
                    <p>CyberHawk is an advanced Intrusion Detection System that uses deep learning to detect threats in real-time, protecting your infrastructure from DDoS attacks, malware, ransomware, and more.</p>
                    <div class="hero-buttons">
                        <a href="<?= MDIR ?>register" class="btn-hero-primary">
                            Get Started Free <i class="bi bi-arrow-right"></i>
                        </a>
                        <a href="#features" class="btn-hero-secondary">
                            <i class="bi bi-play-circle"></i> See How It Works
                        </a>
                    </div>
                </div>
                <div class="col-lg-6 hero-visual d-none d-lg-block">
                    <div class="shield-container">
                        <div class="orbit orbit-1"></div>
                        <div class="orbit orbit-2"></div>
                        <div class="orbit orbit-3"></div>
                        <i class="bi bi-shield-lock-fill shield-icon"></i>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Stats Section -->
    <section class="stats-section">
        <div class="container">
            <div class="row">
                <div class="col-6 col-md-3">
                    <div class="stat-card">
                        <div class="stat-number">97.7%</div>
                        <div class="stat-label">Detection Accuracy</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="stat-card">
                        <div class="stat-number">15+</div>
                        <div class="stat-label">Attack Types Detected</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="stat-card">
                        <div class="stat-number">&lt;1s</div>
                        <div class="stat-label">Response Time</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="stat-card">
                        <div class="stat-number">24/7</div>
                        <div class="stat-label">Real-Time Monitoring</div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Features Section -->
    <section class="features-section" id="features">
        <div class="container">
            <div class="section-header">
                <h2>Enterprise Security Features</h2>
                <p>Comprehensive protection powered by advanced AI and machine learning technologies</p>
            </div>
            <div class="row g-4">
                <div class="col-md-6 col-lg-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="bi bi-shield-check"></i>
                        </div>
                        <h3>Intrusion Detection</h3>
                        <p>Deep Neural Network trained on CICIDS2022 dataset detects DDoS, port scans, brute force attacks, and more with 97.7% accuracy.</p>
                    </div>
                </div>
                <div class="col-md-6 col-lg-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="bi bi-bug"></i>
                        </div>
                        <h3>Malware Analysis</h3>
                        <p>Upload and analyze suspicious files with VirusTotal and MalwareBazaar integration. Get comprehensive threat reports instantly.</p>
                    </div>
                </div>
                <div class="col-md-6 col-lg-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="bi bi-virus"></i>
                        </div>
                        <h3>Ransomware Protection</h3>
                        <p>Real-time monitoring and scanning to detect ransomware threats. Automatic quarantine and signature-based detection.</p>
                    </div>
                </div>
                <div class="col-md-6 col-lg-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="bi bi-globe2"></i>
                        </div>
                        <h3>Threat Intelligence</h3>
                        <p>Access live threat feeds, track threat actors, and monitor IOCs to stay ahead of emerging cyber threats.</p>
                    </div>
                </div>
                <div class="col-md-6 col-lg-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="bi bi-graph-up-arrow"></i>
                        </div>
                        <h3>Network Analytics</h3>
                        <p>Real-time network traffic visualization, bandwidth monitoring, protocol analysis, and anomaly detection.</p>
                    </div>
                </div>
                <div class="col-md-6 col-lg-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="bi bi-file-earmark-text"></i>
                        </div>
                        <h3>Comprehensive Reporting</h3>
                        <p>Generate executive summaries, security reports, and threat timelines. Export to PDF or email directly from the dashboard.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <section class="cta-section" id="about">
        <div class="container">
            <div class="cta-card">
                <h2>Ready to Secure Your Infrastructure?</h2>
                <p>Join thousands of security professionals using CyberHawk to protect their networks</p>
                <a href="<?= MDIR ?>register" class="btn-hero-primary">
                    Start Your Free Trial <i class="bi bi-arrow-right"></i>
                </a>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer>
        <div class="container text-center">
            <p>&copy; 2024 CyberHawk IDS. All rights reserved. | Built with <i class="bi bi-heart-fill text-danger"></i> for Cybersecurity</p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Navbar scroll effect
        window.addEventListener('scroll', function() {
            const navbar = document.getElementById('mainNav');
            if (window.scrollY > 50) {
                navbar.classList.add('scrolled');
            } else {
                navbar.classList.remove('scrolled');
            }
        });

        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    </script>
</body>
</html>
