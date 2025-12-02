# Alert Validation System - Threat Intelligence Integration

## Overview

This system reduces false positives in intrusion detection alerts by validating suspicious IPs against multiple external threat intelligence APIs before displaying them to the frontend.

## How It Works

### 1. **Alert Detection Flow**

```
ML Model (predict_realtime.py)
    ↓
Detects intrusion → writes to alerts.json
    ↓
Backend (get_validated_alerts endpoint)
    ↓
Validates IPs using 3 threat intelligence APIs
    ↓
Only confirmed threats sent to frontend
```

### 2. **Threat Intelligence APIs Used**

The system validates each alert's source IP against three APIs:

#### **AbuseIPDB**
- **Purpose**: Community-driven IP abuse database
- **API Key**: `856f7c63bf4d0a05daa8a735281b58783d4e2264192b720ed87ba4cb2d4701cdaeb968ee02352465`
- **Validation Logic**: IPs with abuse confidence score > 50% are considered threats
- **API Endpoint**: `https://api.abuseipdb.com/api/v2/check`

#### **AlienVault OTX**
- **Purpose**: Open Threat Exchange - collaborative threat intelligence
- **API Key**: `ea8f1f4c26a19094e0e9ce1e4a4c35868bbd8a4167bfa72bad0daac1cef69bc4`
- **Validation Logic**: IPs appearing in threat pulses are flagged as malicious
- **API Endpoint**: `https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general`

#### **IPQualityScore**
- **Purpose**: VPN/Proxy detection and fraud prevention
- **API Key**: `4wlszArEp8w221zs8pgIf7uZftNKroYH`
- **Validation Logic**: IPs with fraud score > 75% or VPN/Proxy/Tor with fraud > 50%
- **API Endpoint**: `https://ipqualityscore.com/api/json/ip/{key}/{ip}`

### 3. **Validation Process**

For each alert in `alerts.json`:

1. **Extract Source IP** from the alert
2. **Check Cache** - if IP was recently validated, use cached result (1 hour TTL)
3. **Query APIs** - check IP against all 3 threat intelligence sources
4. **Aggregate Results** - require at least ONE API to confirm the IP as malicious
5. **Filter Alerts** - only pass validated threats to frontend

**Special Cases:**
- **Private IPs** (10.x.x.x, 192.168.x.x, etc.) - Always shown (no external validation needed)
- **No API confirmation** - Alert is filtered as false positive

### 4. **Implementation Files**

#### **Backend**
- `app/core/IPValidationService.php` - Main validation service class
  - Handles API requests to all 3 services
  - Manages IP validation cache
  - Aggregates results from multiple sources

- `app/core/functions.php:get_validated_alerts()` - API endpoint function
  - Loads alerts from `assets/data/alerts.json`
  - Uses IPValidationService to validate each IP
  - Returns only validated alerts with statistics

#### **Frontend**
- `app/views/pages/dashboard.php` - Updated `loadAlerts()` function
  - Now calls `/get-validated-alerts` endpoint instead of reading JSON directly
  - Displays validation statistics in console
  - Has fallback to direct file access if API fails

#### **Routes**
- `routes/routes.php` - Added route:
  ```php
  $r->addRoute('GET', MDIR . 'get-validated-alerts', checkSession('user_id', 'get_validated_alerts'));
  ```

#### **Configuration**
- `system_settings` database table - Stores API keys per user:
  - `abuseipdb_api_key`
  - `alienvault_api_key`
  - `ipqualityscore_api_key`

### 5. **API Key Management**

API keys are stored in the database via the Settings page:

```php
// Updated handle_save_api_keys() function supports:
POST /save-api-keys
{
    "abuseipdb_api_key": "...",
    "alienvault_api_key": "...",
    "ipqualityscore_api_key": "..."
}
```

Keys are loaded automatically when validating alerts. Default keys are hardcoded as fallback.

### 6. **Caching System**

To avoid API rate limits and improve performance:

- **Cache File**: `assets/data/ip_validation_cache.json`
- **Cache Duration**: 1 hour (3600 seconds)
- **Cleanup**: Old entries (>24 hours) are automatically removed

Cache structure:
```json
{
    "8.8.8.8": {
        "timestamp": 1701234567,
        "result": {
            "is_validated": true,
            "confidence": 85,
            "sources": ["abuseipdb", "alienvault"],
            "details": [...]
        }
    }
}
```

### 7. **Statistics & Monitoring**

The endpoint returns detailed statistics:

```json
{
    "success": true,
    "alerts": [...],
    "stats": {
        "total_alerts": 150,
        "validated_alerts": 25,
        "filtered_alerts": 125,
        "validation_details": [
            {
                "ip": "45.76.123.45",
                "sources": ["abuseipdb", "ipqualityscore"],
                "confidence": 92
            }
        ]
    },
    "message": "Filtered 125 false positives out of 150 total alerts"
}
```

### 8. **Testing the System**

1. **Start the intrusion detection system**:
   ```bash
   python3 python/training/predict_realtime.py
   ```

2. **Generate network traffic** that triggers alerts

3. **Check the dashboard** - you should see:
   - Only validated alerts displayed
   - Console logs showing validation statistics
   - Reduced false positive count

4. **Check validation cache**:
   ```bash
   cat assets/data/ip_validation_cache.json
   ```

### 9. **Benefits**

✅ **Reduces False Positives** - Only shows alerts confirmed by external threat intelligence

✅ **Multi-Source Validation** - Requires at least one of 3 APIs to confirm threat

✅ **Performance Optimized** - Caches validation results to minimize API calls

✅ **Fallback Mechanism** - Dashboard falls back to direct file access if API fails

✅ **Transparency** - Provides detailed statistics on what was filtered and why

### 10. **Future Enhancements**

Potential improvements:

- [ ] Add more threat intelligence sources (VirusTotal, Shodan, etc.)
- [ ] Configurable validation threshold (require 2+ APIs instead of just 1)
- [ ] UI to view filtered alerts and manually approve/block IPs
- [ ] Email notifications for validated high-severity alerts
- [ ] Automated IP blocking for confirmed threats
- [ ] Historical trend analysis of validation accuracy

## Troubleshooting

### Alerts not showing up?

Check the console logs:
```javascript
console.log('Alert Validation Stats:', response.stats);
```

### API errors?

1. Verify API keys are saved in Settings
2. Check error logs: `tail -f /var/log/apache2/error.log` (or your PHP error log)
3. Verify network connectivity to API endpoints
4. Check API rate limits haven't been exceeded

### Cache issues?

Clear the cache manually:
```bash
rm assets/data/ip_validation_cache.json
```

Or use the validation service:
```php
$validator = new IPValidationService();
$validator->clearCache();
```

## Security Notes

⚠️ **API Keys**: Currently stored in database per user. Consider using environment variables for production.

⚠️ **Rate Limiting**: Caching helps but monitor API usage to avoid hitting rate limits.

⚠️ **Private IPs**: Currently bypass validation. Adjust `isPrivateIP()` method if you need internal validation.

---

**Author**: CyberHawk Development Team
**Date**: 2025-12-02
**Version**: 1.0
