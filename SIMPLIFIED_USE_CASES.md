# CyberHawk - Simplified Fully Dressed Use Cases

## Table of Contents
1. [UC-01: Register Account](#uc-01-register-account)
2. [UC-02: Login](#uc-02-login)
3. [UC-04: Upload Malware Sample](#uc-04-upload-malware-sample)
4. [UC-05: Analyze Malware](#uc-05-analyze-malware)
5. [UC-07: Start Ransomware Monitor](#uc-07-start-ransomware-monitor)
6. [UC-10: Monitor Network Traffic](#uc-10-monitor-network-traffic)
7. [UC-15: Generate Security Report](#uc-15-generate-security-report)

---

## UC-01: Register Account

**Primary Actor:** User  
**Stakeholders:** User, System Administrator  
**Preconditions:** User has internet access  
**Postconditions:** User account created and verification email sent

**Main Success Scenario:**
1. User navigates to registration page
2. User enters name, email, and password
3. System validates input
4. System creates account with "unverified" status
5. System sends verification email
6. System displays "Check your email" message

**Extensions:**
- **3a. Email already exists:** System shows error, offers login option
- **3b. Weak password:** System shows password requirements
- **5a. Email fails:** System logs error, allows resend

**Special Requirements:**
- Password must be hashed with bcrypt
- HTTPS required

---

## UC-02: Login

**Primary Actor:** User  
**Stakeholders:** User  
**Preconditions:** User has registered account  
**Postconditions:** User authenticated and redirected to dashboard

**Main Success Scenario:**
1. User enters email and password
2. System validates credentials
3. System checks if email is verified
4. System creates session
5. System redirects to dashboard

**Extensions:**
- **2a. Invalid credentials:** System shows error message
- **3a. Email not verified:** System prompts to verify email
- **4a. Session creation fails:** System logs error

**Special Requirements:**
- Session timeout: 30 minutes
- Failed attempts logged

---

## UC-04: Upload Malware Sample

**Primary Actor:** Security Analyst  
**Stakeholders:** Security Analyst, Organization  
**Preconditions:** Analyst is logged in  
**Postconditions:** Malware sample uploaded and queued for analysis

**Main Success Scenario:**
1. Analyst clicks "Upload Sample"
2. Analyst selects file from computer
3. System validates file (size < 50MB)
4. System generates unique filename
5. System saves file to secure directory
6. System creates database entry with "pending" status
7. System displays success message

**Extensions:**
- **3a. File too large:** System shows size limit error
- **3b. Invalid file type:** System shows supported formats
- **6a. Database error:** System logs error, deletes uploaded file

**Special Requirements:**
- Files stored in isolated directory
- Automatic cleanup after 30 days

---

## UC-05: Analyze Malware

**Primary Actor:** Security Analyst  
**Stakeholders:** Security Analyst, Organization  
**Preconditions:** Malware sample uploaded, VirusTotal API configured  
**Postconditions:** Analysis complete, report generated

**Main Success Scenario:**
1. Analyst clicks "Start Analysis" on uploaded sample
2. System initiates Python analyzer script
3. System performs static analysis (hash, size, type)
4. System queries VirusTotal API
5. System receives detection results
6. System calculates threat score
7. System generates JSON report
8. System saves report to database
9. System creates notification
10. System displays analysis results

**Extensions:**
- **4a. VirusTotal API unavailable:** System continues with local analysis only
- **4b. API rate limit exceeded:** System queues for later retry
- **6a. High threat detected:** System creates critical alert, sends email

**Special Requirements:**
- Analysis completes within 5 minutes
- API errors handled gracefully

---

## UC-07: Start Ransomware Monitor

**Primary Actor:** Administrator  
**Stakeholders:** Administrator, End Users  
**Preconditions:** Admin logged in, Python monitor available  
**Postconditions:** Real-time monitoring active

**Main Success Scenario:**
1. Admin navigates to Ransomware Protection page
2. Admin clicks "Start Monitor"
3. System checks if monitor already running
4. System initiates Python monitoring script
5. System begins watching protected directories
6. System updates status to "Active"
7. System displays monitoring dashboard

**Extensions:**
- **3a. Monitor already running:** System shows current status
- **4a. Script fails to start:** System logs error, shows troubleshooting steps
- **5a. Threat detected:** System quarantines files, creates alert

**Special Requirements:**
- Minimal performance impact
- Automatic restart on system reboot

---

## UC-10: Monitor Network Traffic

**Primary Actor:** Administrator  
**Stakeholders:** Administrator, Security Team  
**Preconditions:** Admin logged in, network interface available  
**Postconditions:** Network traffic captured and analyzed

**Main Success Scenario:**
1. Admin navigates to Network Analytics page
2. Admin clicks "Start Capture"
3. System prompts for network interface selection
4. Admin selects interface
5. System initiates packet capture
6. System processes packets in real-time
7. System feeds data to ML intrusion detection model
8. System displays live metrics and alerts

**Extensions:**
- **3a. No interfaces found:** System shows error, provides guidance
- **5a. Insufficient permissions:** System requests admin elevation
- **7a. Intrusion detected:** System creates alert, logs incident

**Special Requirements:**
- Real-time processing
- ML model accuracy > 95%

---

## UC-15: Generate Security Report

**Primary Actor:** Security Analyst  
**Stakeholders:** Security Analyst, Management, Compliance Officer  
**Preconditions:** Analyst logged in, security data available  
**Postconditions:** Report generated and available for download/email

**Main Success Scenario:**
1. Analyst navigates to Reporting page
2. Analyst selects report type (Executive/Malware/Network/Comprehensive)
3. Analyst selects date range
4. Analyst clicks "Generate Report"
5. System collects data from all modules
6. System aggregates statistics
7. System calculates key metrics
8. System generates visualizations
9. System compiles report
10. System displays report preview
11. Analyst can export as PDF or email

**Extensions:**
- **5a. Insufficient data:** System shows warning, generates with available data
- **9a. PDF generation fails:** System offers HTML/CSV alternatives
- **11a. Email sending fails:** System logs error, allows retry

**Special Requirements:**
- Report generation < 30 seconds
- Professional formatting
- PDF size < 25MB for email

---

## Use Case Relationships

### Include Relationships
- UC-05 (Analyze Malware) **includes** UC-20 (View Notifications)
- UC-16 (Export Report) **includes** UC-15 (Generate Security Report)
- UC-17 (Email Report) **includes** UC-15 (Generate Security Report)

### Extend Relationships
- UC-03 (Verify Email) **extends** UC-02 (Login)
- UC-09 (Quarantine Threats) **extends** UC-08 (Scan for Ransomware)

### External Dependencies
- UC-05 uses VirusTotal API
- UC-03, UC-17 use Email Server

---

## Actor Descriptions

**User:** Any registered person using the system for basic security monitoring

**Security Analyst:** Professional responsible for threat analysis and reporting

**Administrator:** System admin with elevated privileges for network and system-wide operations

---

**Document Version:** 1.0  
**Last Updated:** December 2024  
**Status:** Final
