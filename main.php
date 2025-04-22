<?php
// Config
require_once 'config.php';

// Set proper headers for JSON response
header('Content-Type: application/json');

// Start session with secure settings
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
    'cookie_samesite' => 'Strict'
]);

// Error handling to catch and report issues properly
try {
    $pdo = getDatabaseConnection();
    $encryption_key = getEncryptionKey();
    
    // Rate-limiting configuration
    $rateLimit = [
        'create' => ['max_requests' => 75, 'time_window' => 3600], // 75 requests per hour
        'delete' => ['max_requests' => 100, 'time_window' => 3600],  // 100 requests per hour
        'change' => ['max_requests' => 50, 'time_window' => 3600],   // 50 requests per hour
        'stats' => ['max_requests' => 300, 'time_window' => 3600]   // 300 requests per hour
    ];
    
    // AES-256 Encryption functions
    function encryptData($data, $key) {
        if (empty($data)) return null;
        
        // Generate a random initialization vector
        $iv = openssl_random_pseudo_bytes(16);
        
        // Encrypt the data using AES-256-CBC
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        
        // Combine the IV and encrypted data
        return [
            'data' => base64_decode($encrypted), // Store raw binary data
            'iv' => $iv
        ];
    }
    
    function decryptData($encryptedData, $iv, $key) {
        if (empty($encryptedData) || empty($iv)) return null;
        
        // Convert the binary data back to base64 for decryption
        $encryptedB64 = base64_encode($encryptedData);
        
        // Decrypt the data
        return openssl_decrypt($encryptedB64, 'AES-256-CBC', $key, 0, $iv);
    }

    // Function to check and enforce rate limits
    function checkRateLimit($pdo, $ip, $action, $maxRequests, $timeWindow) {
        $stmt = $pdo->prepare("
            SELECT request_count, last_request 
            FROM rate_limits 
            WHERE ip_address = :ip AND action = :action
        ");
        $stmt->execute([':ip' => $ip, ':action' => $action]);
        $row = $stmt->fetch();

        $currentTime = time();
        
        if ($row) {
            $lastRequestTime = strtotime($row['last_request']);
            $elapsedTime = $currentTime - $lastRequestTime;

            // Reset count if time window has elapsed
            if ($elapsedTime >= $timeWindow) {
                $stmt = $pdo->prepare("
                    UPDATE rate_limits 
                    SET request_count = 1, last_request = NOW() 
                    WHERE ip_address = :ip AND action = :action
                ");
                $stmt->execute([':ip' => $ip, ':action' => $action]);
                return true;
            }

            // Check if limit exceeded
            if ($row['request_count'] >= $maxRequests) {
                $remainingTime = $timeWindow - $elapsedTime;
                return [
                    'status' => 'error',
                    'message' => "Rate limit exceeded for $action. Try again in " . ceil($remainingTime / 60) . " minutes."
                ];
            }

            // Increment count
            $stmt = $pdo->prepare("
                UPDATE rate_limits 
                SET request_count = request_count + 1, last_request = NOW() 
                WHERE ip_address = :ip AND action = :action
            ");
            $stmt->execute([':ip' => $ip, ':action' => $action]);
            return true;
        } else {
            // First request for this IP/action
            $stmt = $pdo->prepare("
                INSERT INTO rate_limits (ip_address, action, request_count, last_request) 
                VALUES (:ip, :action, 1, NOW())
            ");
            $stmt->execute([':ip' => $ip, ':action' => $action]);
            return true;
        }
    }
    
    function getClientIP() {
        $ipAddress = '';
    
        // Check for shared internet or proxies
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipAddress = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Check for multiple IPs in the header (comma-separated)
            $ipAddresses = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ipAddress = trim($ipAddresses[0]); // Get the first IP in the list
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED'])) {
            $ipAddress = $_SERVER['HTTP_X_FORWARDED'];
        } elseif (!empty($_SERVER['HTTP_FORWARDED_FOR'])) {
            $ipAddress = $_SERVER['HTTP_FORWARDED_FOR'];
        } elseif (!empty($_SERVER['HTTP_FORWARDED'])) {
            $ipAddress = $_SERVER['HTTP_FORWARDED'];
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ipAddress = $_SERVER['REMOTE_ADDR'];
        } else {
            $ipAddress = 'UNKNOWN';
        }
    
        // Validate the IP address format
        if (filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return $ipAddress;
        } else {
            return '0.0.0.0'; // Default/error value
        }
    }

    // Function to generate a cryptographically secure random string
    function generateRandomString($length = 4, $format = 'alphanumeric') {
        // Set a sensible default length range (10 characters offers much more uniqueness)
        if ($length < 1 || $length > 32) {
            $length = 4;
        }
        
        // Define character sets
        $lowercase = 'abcdefghijklmnopqrstuvwxyz';
        $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $numbers = '0123456789';
        
        switch ($format) {
            case 'alphanumeric':
                $chars = $lowercase . $uppercase . $numbers;
                break;
            case 'readable': // More readable format avoiding confusing characters
                $chars = str_replace(['0', 'O', '1', 'l', 'I'], '', $lowercase . $uppercase . $numbers);
                break;
            case 'hex':
                $chars = $numbers . 'abcdef';
                break;
            case 'segments': // Returns format like xxxx-xxxx-xxxx
                return implode('-', array_map(
                    function() { return generateRandomString(4, 'alphanumeric'); },
                    array_fill(0, ceil($length / 4), 0)
                ));
            default:
                $chars = $lowercase . $uppercase . $numbers;
        }
        
        // Generate random string
        $result = '';
        $max = strlen($chars) - 1;
        for ($i = 0; $i < $length; $i++) {
            $result .= $chars[random_int(0, $max)];
        }
        
        // Ensure there's at least one letter and one number for better uniqueness
        if (ctype_alpha($result) || ctype_digit($result)) {
            $pos1 = random_int(0, $length - 1);
            $pos2 = ($pos1 + floor($length/2)) % $length; // Place far from first replacement
            
            $result[$pos1] = $numbers[random_int(0, strlen($numbers) - 1)]; // Add a number
            $result[$pos2] = $lowercase[random_int(0, strlen($lowercase) - 1)]; // Add a letter
        }
        
        return $result;
    }
    
    // Function to check if a short code already exists with proper parameter binding
    function shortCodeExists($pdo, $code) {
        $stmt = $pdo->prepare("SELECT 1 FROM links WHERE short_code = :code LIMIT 1");
        $stmt->execute([':code' => $code]);
        return $stmt->fetchColumn() !== false;
    }

    // Function to fix URL format by ensuring it has a valid scheme
    function formatUrl($url) {
        // Trim whitespace
        $url = trim($url);
        
        // Return empty string as is
        if (empty($url)) {
            return $url;
        }
        
        // Check if it's already a valid URL with scheme
        if (preg_match('~^(?:f|ht)tps?://~i', $url)) {
            return $url; // Already has http:// or https:// scheme
        }
        
        // Handle other schemes that should be preserved (ftp, etc.)
        if (preg_match('~^([a-z][a-z0-9+.-]*):\/\/~i', $url)) {
            return $url; // Already has a valid scheme we want to preserve
        }
        
        // Handle mailto: links
        if (preg_match('~^mailto:~i', $url)) {
            return $url;
        }
        
        // Check for protocol-relative URLs (//example.com)
        if (strpos($url, '//') === 0) {
            return 'https:' . $url; // Convert to https
        }
        
        // Handle localhost with port
        if (preg_match('~^localhost(:[0-9]+)?(/.*)?$~i', $url)) {
            return 'http://' . $url;
        }
        
        // Handle IP addresses
        
        // IPv4
        if (preg_match('/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/', $url)) {
            return 'http://' . $url;
        }
        
        // IPv6 enclosed in brackets
        if (preg_match('/^\[.*\]/', $url)) {
            return 'http://' . $url;
        }
        
        // Handle URLs with user:pass@ format
        if (preg_match('/^[^\/]+@([^\/]+)/', $url, $matches)) {
            return 'https://' . $url;
        }
        
        // Handle domain-only URLs (potentially with paths/query/fragment)
        
        // Split the URL to check for domain validity
        // This will handle cases like "example.com/path?query=1#fragment"
        $urlParts = parse_url('http://' . $url);
        
        if (isset($urlParts['host'])) {
            // Check for intranet URLs (single word hostnames without dots or TLDs)
            if (!strpos($urlParts['host'], '.') && !preg_match('/^localhost$/i', $urlParts['host'])) {
                // Could be an intranet URL or an incomplete domain
                // For public websites, assume it's missing ".com"
                if (preg_match('/^(google|facebook|twitter|instagram|youtube|github|gitlab|bitbucket)$/i', $urlParts['host'])) {
                    $newUrl = $urlParts['host'] . '.com';
                    
                    // Rebuild the URL with the fixed domain
                    if (isset($urlParts['path'])) {
                        $newUrl .= $urlParts['path'];
                    }
                    if (isset($urlParts['query'])) {
                        $newUrl .= '?' . $urlParts['query'];
                    }
                    if (isset($urlParts['fragment'])) {
                        $newUrl .= '#' . $urlParts['fragment'];
                    }
                    
                    return 'https://' . $newUrl;
                }
                
                // For generic single-word hostnames, assume intranet/local
                return 'http://' . $url;
            }
            
            // For all other domains, default to https
            return 'https://' . $url;
        }
        
        // If we couldn't parse the URL, just add https:// as a fallback
        return 'https://' . $url;
    }

    // Create a new shortened link with improved security and AES-256 encryption
    function createLink($pdo, $originalUrl, $customLength = 4, $password = '', $encryption_key) {
        // Format the URL first
        $originalUrl = formatUrl($originalUrl);
        
        // Validate URL
        if (!filter_var($originalUrl, FILTER_VALIDATE_URL)) {
            return ['status' => 'error', 'message' => 'Invalid URL format'];
        }
        
        // Protect against unsafe URLs
        $disallowedSchemes = ['javascript', 'data', 'vbscript', 'file'];
        $urlParts = parse_url($originalUrl);
        if (!$urlParts || !isset($urlParts['scheme'])) {
            return ['status' => 'error', 'message' => 'Invalid URL format'];
        }
        
        if (in_array(strtolower($urlParts['scheme']), $disallowedSchemes)) {
            return ['status' => 'error', 'message' => 'URL scheme not allowed'];
        }
    
        // Validate length
        $customLength = (int)$customLength;
        if ($customLength < 1 || $customLength > 32) {
            $customLength = 4; // Default to 4 if invalid
        }
    
        // Password validation
        if (!empty($password)) {
            $passwordLength = strlen($password);
            if ($passwordLength < 4 || $passwordLength > 20) {
                return ['status' => 'error', 'message' => 'Password must be between 4 and 20 characters'];
            }
            
            // Check for at least one letter and one number
            if (!preg_match('/[A-Za-z]/', $password) ||
                !preg_match('/[0-9]/', $password)) {
                return ['status' => 'error', 'message' => 'Password must contain at least one letter and one number'];
            }
        }
    
        // Generate unique short code
        $maxAttempts = 10;
        $attempts = 0;
        $shortCode = null;
        
        do {
            $shortCode = generateRandomString($customLength);
            $attempts++;
            
            if ($attempts >= $maxAttempts) {
                return ['status' => 'error', 'message' => 'Could not generate a unique code after multiple attempts'];
            }
        } while (shortCodeExists($pdo, $shortCode));
        
        // Generate access key
        $accessKey = bin2hex(random_bytes(16));
        
        // Encrypt password if provided
        $encryptedPassword = null;
        $passwordIv = null;
        
        if (!empty($password)) {
            $passwordEncryption = encryptData($password, $encryption_key);
            $encryptedPassword = $passwordEncryption['data'];
            $passwordIv = $passwordEncryption['iv'];
        }
        
        // Encrypt access key
        $accessKeyEncryption = encryptData($accessKey, $encryption_key);
        $encryptedAccessKey = $accessKeyEncryption['data'];
        $accessKeyIv = $accessKeyEncryption['iv'];
    
        try {
            $stmt = $pdo->prepare("
                INSERT INTO links (
                    original_url, 
                    short_code, 
                    password, 
                    access_key, 
                    encryption_iv,
                    password_iv,
                    created_at
                ) VALUES (
                    :url, 
                    :code, 
                    :password, 
                    :access_key, 
                    :encryption_iv,
                    :password_iv,
                    NOW()
                )
            ");
            
            $stmt->execute([
                ':url' => $originalUrl,
                ':code' => $shortCode,
                ':password' => $encryptedPassword,
                ':access_key' => $encryptedAccessKey,
                ':encryption_iv' => $accessKeyIv,
                ':password_iv' => $passwordIv
            ]);
            
            if (!empty($password)) {
                // If we have a password, store its IV separately
                $stmt = $pdo->prepare("
                    UPDATE links 
                    SET password_iv = :password_iv 
                    WHERE short_code = :code
                ");
                
                try {
                    $result = $stmt->execute([
                        ':password_iv' => $passwordIv,
                        ':code' => $shortCode
                    ]);
                    
                    if (!$result) {
                        error_log("Failed to update password_iv for code: $shortCode");
                    }
                } catch (PDOException $e) {
                    error_log("Error updating password_iv: " . $e->getMessage());
                }
            }
            
            return [
                'status' => 'success', 
                'shortCode' => $shortCode,
                'accessKey' => $accessKey
            ];
        } catch (PDOException $e) {
            return ['status' => 'error', 'message' => 'Failed to create shortened link: ' . $e->getMessage()];
        }
    }
    
    // Delete a shortened link with improved security and AES-256 encryption
    function deleteLink($pdo, $shortCode, $accessKey, $encryption_key) {
        if (empty($shortCode) || empty($accessKey)) {
            return ['status' => 'error', 'message' => 'Missing required parameters'];
        }
        
        try {
            $stmt = $pdo->prepare("
                SELECT access_key, encryption_iv 
                FROM links 
                WHERE short_code = :code
            ");
            $stmt->execute([':code' => $shortCode]);
            $result = $stmt->fetch();
            
            if (!$result) {
                return ['status' => 'error', 'message' => 'Link not found'];
            }
            
            // Decrypt the stored access key
            $storedKey = decryptData($result['access_key'], $result['encryption_iv'], $encryption_key);
            
            if (!hash_equals($storedKey, $accessKey)) {
                return ['status' => 'error', 'message' => 'Invalid access key'];
            }
            
            $stmt = $pdo->prepare("DELETE FROM links WHERE short_code = :code");
            $stmt->execute([':code' => $shortCode]);
            
            if ($stmt->rowCount() > 0) {
                return ['status' => 'success', 'message' => 'Link deleted successfully'];
            } else {
                return ['status' => 'error', 'message' => 'Failed to delete link'];
            }
        } catch (PDOException $e) {
            return ['status' => 'error', 'message' => 'Failed to delete link: ' . $e->getMessage()];
        }
    }
    
    // Function to change a link's destination URL and/or password
    function changeLink($pdo, $shortCode, $accessKey, $newUrl = null, $newPassword = null, $encryption_key) {
        if (empty($shortCode) || empty($accessKey) || (empty($newUrl) && $newPassword === null)) {
            return ['status' => 'error', 'message' => 'Missing required parameters'];
        }
        
        // Validate new URL if provided
        if (!empty($newUrl)) {
            // Format the URL first
            $newUrl = formatUrl($newUrl);
            
            if (!filter_var($newUrl, FILTER_VALIDATE_URL)) {
                return ['status' => 'error', 'message' => 'Invalid URL format'];
            }
            
            $urlParts = parse_url($newUrl);
            if (!$urlParts || !isset($urlParts['scheme'])) {
                return ['status' => 'error', 'message' => 'Invalid URL format'];
            }
            
            $disallowedSchemes = ['javascript', 'data', 'vbscript', 'file'];
            if (in_array(strtolower($urlParts['scheme']), $disallowedSchemes)) {
                return ['status' => 'error', 'message' => 'URL scheme not allowed'];
            }
        }
        
        // Password validation if provided
        $encryptedPassword = null;
        $passwordIv = null;
        
        if ($newPassword !== null) {
            if (!empty($newPassword)) {
                $passwordLength = strlen($newPassword);
                if ($passwordLength < 4 || $passwordLength > 20) {
                    return ['status' => 'error', 'message' => 'Password must be between 4 and 20 characters'];
                }
                
                // Check for at least one letter and one number
                if (!preg_match('/[A-Za-z]/', $newPassword) ||
                    !preg_match('/[0-9]/', $newPassword)) {
                    return ['status' => 'error', 'message' => 'Password must contain at least one letter and one number'];
                }
                
                // Encrypt the new password
                $passwordEncryption = encryptData($newPassword, $encryption_key);
                $encryptedPassword = $passwordEncryption['data'];
                $passwordIv = $passwordEncryption['iv'];
            }
            // If newPassword is empty string, we're removing the password
        }
        
        try {
            $stmt = $pdo->prepare("
                SELECT access_key, encryption_iv 
                FROM links 
                WHERE short_code = :code
            ");
            $stmt->execute([':code' => $shortCode]);
            $result = $stmt->fetch();
            
            if (!$result) {
                return ['status' => 'error', 'message' => 'Link not found'];
            }
            
            // Decrypt the stored access key
            $storedKey = decryptData($result['access_key'], $result['encryption_iv'], $encryption_key);
            
            if (!hash_equals($storedKey, $accessKey)) {
                return ['status' => 'error', 'message' => 'Invalid access key'];
            }
            
            // Build the query based on what's being updated
            $setValues = [];
            $params = [':code' => $shortCode];
            
            if (!empty($newUrl)) {
                $setValues[] = "original_url = :url";
                $params[':url'] = $newUrl;
            }
            
            if ($newPassword !== null) {
                if (!empty($newPassword)) {
                    $setValues[] = "password = :password, password_iv = :password_iv";
                    $params[':password'] = $encryptedPassword;
                    $params[':password_iv'] = $passwordIv;
                } else {
                    $setValues[] = "password = NULL, password_iv = NULL";
                }
            }
            
            $setValues[] = "updated_at = NOW()";
            
            $query = "UPDATE links SET " . implode(", ", $setValues) . " WHERE short_code = :code";
            $stmt = $pdo->prepare($query);
            $stmt->execute($params);
            
            if ($stmt->rowCount() > 0) {
                $messages = [];
                if (!empty($newUrl)) $messages[] = "URL";
                if ($newPassword !== null) $messages[] = "Password";
                
                return [
                    'status' => 'success', 
                    'message' => implode(" and ", $messages) . ' updated successfully'
                ];
            } else {
                return ['status' => 'error', 'message' => 'No changes were made'];
            }
        } catch (PDOException $e) {
            return ['status' => 'error', 'message' => 'Failed to update link: ' . $e->getMessage()];
        }
    }

    // Function to get global link statistics
    function getLinkStats($pdo) {
        try {
            $stats = [
                'total_links' => 0,
                'total_clicks' => 0,
                'active_links' => 0,
                'password_protected' => 0,
                'average_clicks' => 0,
                'last_24h_created' => 0,
                'last_24h_clicks' => 0,
                'most_clicked' => 0
            ];
    
            // Verify table exists
            $stmt = $pdo->query("SHOW TABLES LIKE 'links'");
            if ($stmt->rowCount() === 0) {
                throw new Exception("Links table not found in database");
            }
    
            // Total number of links
            $stmt = $pdo->query("SELECT COUNT(*) FROM links");
            if ($stmt === false) {
                throw new Exception("Failed to query total links");
            }
            $stats['total_links'] = (int)$stmt->fetchColumn();
    
            // Total clicks across all links
            $stmt = $pdo->query("SELECT COALESCE(SUM(clicks), 0) FROM links");
            if ($stmt === false) {
                throw new Exception("Failed to query total clicks");
            }
            $stats['total_clicks'] = (int)$stmt->fetchColumn();
    
            // Active links (with at least 1 click)
            $stmt = $pdo->query("SELECT COUNT(*) FROM links WHERE clicks > 0");
            if ($stmt === false) {
                throw new Exception("Failed to query active links");
            }
            $stats['active_links'] = (int)$stmt->fetchColumn();
    
            // Password protected links
            $stmt = $pdo->query("SELECT COUNT(*) FROM links WHERE password IS NOT NULL");
            if ($stmt === false) {
                throw new Exception("Failed to query password protected links");
            }
            $stats['password_protected'] = (int)$stmt->fetchColumn();
    
            // Average clicks per link
            if ($stats['total_links'] > 0) {
                $stats['average_clicks'] = round($stats['total_clicks'] / $stats['total_links'], 2);
            }
    
            // Links created in last 24 hours
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM links WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            $stmt->execute();
            $stats['last_24h_created'] = (int)$stmt->fetchColumn();
            
            // Alternative for clicks in last 24 hours - count clicks for links created in last day
            // This is an estimate since we don't have direct last_clicked timestamp
            $stmt = $pdo->prepare("SELECT COALESCE(SUM(clicks), 0) FROM links WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            $stmt->execute();
            $stats['last_24h_clicks'] = (int)$stmt->fetchColumn();
            
            // Most clicked link count
            $stmt = $pdo->query("SELECT COALESCE(MAX(clicks), 0) FROM links");
            if ($stmt === false) {
                throw new Exception("Failed to query most clicked link");
            }
            $stats['most_clicked'] = (int)$stmt->fetchColumn();
    
            return [
                'status' => 'success',
                'data' => $stats
            ];
        } catch (Exception $e) {
            error_log("Stats Error: " . $e->getMessage());
            
            return [
                'status' => 'error',
                'message' => 'Failed to retrieve statistics: ' . $e->getMessage()
            ];
        }
    }

    // Redirect to the original URL with improved security and AES-256 encryption
    function redirectToOriginal($pdo, $shortCode, $providedPassword = '', $encryption_key) {
        if (empty($shortCode)) {
            return ['status' => 'error', 'message' => 'Short code is required'];
        }
        
        try {
            $stmt = $pdo->prepare("
                SELECT id, original_url, password, password_iv 
                FROM links 
                WHERE short_code = :code
            ");
            $stmt->execute([':code' => $shortCode]);
            $link = $stmt->fetch();
            
            if (!$link) {
                return ['status' => 'error', 'message' => 'Link not found'];
            }
            
            // Check if link is password protected
            if (!empty($link['password'])) {
                if (empty($providedPassword)) {
                    return ['status' => 'password_required', 'message' => 'This link is password protected'];
                }
                
                // Decrypt the stored password
                $decryptedPassword = decryptData($link['password'], $link['password_iv'], $encryption_key);
                
                if ($providedPassword !== $decryptedPassword) {
                    return ['status' => 'error', 'message' => 'Incorrect password'];
                }
            }
            
            // Update click count using parameterized query
            $stmt = $pdo->prepare("UPDATE links SET clicks = clicks + 1, last_accessed = NOW() WHERE id = :id");
            $stmt->execute([':id' => $link['id']]);
            
            return ['status' => 'success', 'url' => $link['original_url']];
        } catch (PDOException $e) {
            return ['status' => 'error', 'message' => 'Error retrieving link: ' . $e->getMessage()];
        }
    }
    
    // Sanitize input data
    function sanitizeInput($data) {
        if (is_null($data) || !is_string($data)) {
            return '';
        }
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        return $data;
    }
    
    // Main logic for handling requests
    $action = isset($_GET['action']) ? sanitizeInput($_GET['action']) : '';

    if ($action === 'create' || $action === 'delete' || $action === 'change' || $action === 'stats') {
        // Check rate limit before processing the request
        if (isset($rateLimit[$action])) {
            $ip = getClientIP();
            
            $limitCheck = checkRateLimit(
                $pdo,
                $ip,
                $action,
                $rateLimit[$action]['max_requests'],
                $rateLimit[$action]['time_window']
            );
            
            if ($limitCheck !== true) {
                echo json_encode($limitCheck);
                exit;
            }
        }

        switch ($action) {
            case 'create':
                if (isset($_GET['url'])) {
                    $originalUrl = $_GET['url'];
                    $customLength = isset($_GET['length']) ? (int)$_GET['length'] : 4;
                    $password = isset($_GET['password']) ? $_GET['password'] : '';
                    
                    $result = createLink($pdo, $originalUrl, $customLength, $password, $encryption_key);
                    
                    if ($result['status'] === 'success') {
                        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
                        $host = $_SERVER['HTTP_HOST'];
                        $scriptName = basename($_SERVER['SCRIPT_NAME']);
                        $shortUrl = "$protocol://$host/$scriptName?code=" . urlencode($result['shortCode']);
                        
                        echo json_encode([
                            'status' => 'success',
                            'original_url' => $originalUrl,
                            'short_url' => $shortUrl,
                            'short_code' => $result['shortCode'],
                            'access_key' => $result['accessKey']
                        ]);
                    } else {
                        echo json_encode($result);
                    }
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'URL is required']);
                }
                break;
                
            case 'delete':
                if (isset($_GET['code']) && isset($_GET['key'])) {
                    $shortCode = sanitizeInput($_GET['code']);
                    $accessKey = sanitizeInput($_GET['key']);
                    $result = deleteLink($pdo, $shortCode, $accessKey, $encryption_key);
                    echo json_encode($result);
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'Short code and access key are required']);
                }
                break;
                
            case 'change':
                if (isset($_GET['code']) && isset($_GET['key'])) {
                    $shortCode = sanitizeInput($_GET['code']);
                    $accessKey = sanitizeInput($_GET['key']);
                    $newUrl = isset($_GET['url']) ? $_GET['url'] : null; // Don't sanitize URL to preserve format
                    $newPassword = isset($_GET['password']) ? $_GET['password'] : null;
                    
                    // Check if at least one of URL or password is provided
                    if ($newUrl === null && $newPassword === null) {
                        echo json_encode(['status' => 'error', 'message' => 'New URL or password is required']);
                        break;
                    }
                    
                    $result = changeLink($pdo, $shortCode, $accessKey, $newUrl, $newPassword, $encryption_key);
                    echo json_encode($result);
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'Short code and access key are required']);
                }
                break;
                
            case 'stats':
                $result = getLinkStats($pdo);
                echo json_encode($result);
                break;
                
            default:
                echo json_encode(['status' => 'error', 'message' => 'Invalid action']);
                break;
        }
    } else {
        if (isset($_GET['code'])) {
            $shortCode = sanitizeInput($_GET['code']);
            $password = isset($_GET['password']) ? $_GET['password'] : '';
            
            $result = redirectToOriginal($pdo, $shortCode, $password, $encryption_key);
            
            if ($result['status'] === 'success') {
                header("X-Frame-Options: DENY");
                header("X-XSS-Protection: 1; mode=block");
                header("X-Content-Type-Options: nosniff");
                header("Referrer-Policy: strict-origin-when-cross-origin");
                header("Content-Security-Policy: default-src 'self'");
                header("Location: " . $result['url']);
                exit;
            } elseif ($result['status'] === 'password_required' || $result['status'] === 'error') {
                header('Content-Type: text/html; charset=UTF-8');
                ?>
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Password Protected Link</title>
                    <link rel="stylesheet" href="https://fonts.xz.style/serve/inter.css">
                    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@exampledev/new.css@1.1.2/new.min.css">
                    <style>
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .form-group { margin-bottom: 15px; }
                        .btn { display: inline-block; padding: 8px 16px; background-color: #1a1a1a; color: #fff; border: none; cursor: pointer; }
                        .error-message { color: #f44336; margin-top: 10px; }
                    </style>
                    <meta http-equiv="X-Frame-Options" content="DENY">
                    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
                    <meta http-equiv="X-Content-Type-Options" content="nosniff">
                    <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
                </head>
                <body>
                    <div class="container">
                        <h1>Password required</h1>
                        <p>This link requires a password to access.</p>
                        
                        <?php if ($result['status'] === 'error' && $result['message'] === 'Incorrect password'): ?>
                            <p class="error-message">Incorrect password. Please try again.</p>
                        <?php endif; ?>
                        
                        <form method="get" action="" onsubmit="submitPasswordForm(event)">
                            <input type="hidden" name="code" value="<?php echo htmlspecialchars($shortCode, ENT_QUOTES, 'UTF-8'); ?>">
                            <div class="form-group">
                                <label for="password">Password:</label>
                                <br>
                                <input type="password" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn">Submit</button>
                        </form>
                        
                        <script>
                            function submitPasswordForm(e) {
                                e.preventDefault();
                                var password = document.getElementById('password').value;
                                var code = "<?php echo htmlspecialchars($shortCode, ENT_QUOTES, 'UTF-8'); ?>";
                                var currentUrl = window.location.href;
                                
                                if (currentUrl.includes("/r/") && !currentUrl.includes("main.php")) {
                                    window.location.href = '/r/' + encodeURIComponent(code) + '/p/' + encodeURIComponent(password);
                                } else {
                                    window.location.href = '/ls/main.php?code=' + encodeURIComponent(code) + '&password=' + encodeURIComponent(password);
                                }
                            }
                        </script>
                    </div>
                </body>
                </html>
                <?php
                exit;
            }
        } else {
            header('Content-Type: text/plain');
            echo "Oops! This page can't be accessed directly. Please return to the index page.";
        }
    }
} catch (Exception $e) {
    // Return error as JSON
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Server Error: ' . $e->getMessage()
    ]);
}
?>