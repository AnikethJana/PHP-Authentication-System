<?php
 // Set CORS headers (ensure your frontend origin is correct)
 header("Access-Control-Allow-Origin: https://cricster.pages.dev");
 header("Access-Control-Allow-Credentials: true");
 header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
 header("Access-Control-Allow-Headers: Content-Type, Authorization");

 // Set cache control headers
 header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
 header("Pragma: no-cache");
 header("Expires: 0");

 // Load Composer dependencies
 require 'vendor/autoload.php';
 use Firebase\JWT\JWT;
 use Firebase\JWT\Key;

 // --- Configuration ---
 $JWT_SECRET = ''; // KEEP THIS SECRET! Use env vars in production.
 $COOKIE_NAME = 'auth_token';
 $AUTH_DURATION = 12 * 60 * 60; // 12 hours

 // Database configuration (Use env vars in production!)
 $DB_HOST = '';
 $DB_PORT = ;
 $DB_NAME = '';
 $DB_USER = '';
 $DB_PASS = '';

 /**
  * Establishes a database connection using mysqli.
  * Throws an Exception if the connection fails.
  *
  * @return mysqli Database connection object.
  * @throws Exception If database connection fails.
  */
 function getDbConnection() {
     global $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS;
     // Error suppression (@) can hide connection errors, better to let them be caught or logged
     $conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME, $DB_PORT);
     if ($conn->connect_error) {
         error_log("Database connection failed: " . $conn->connect_error);
         throw new Exception("Database connection failed");
     }
     $conn->set_charset("utf8mb4");
     return $conn;
 }

 /**
  * Gets the client's IP address, considering proxy headers.
  *
  * @return string The client's IP address or 'UNKNOWN'.
  */
 function getClientIp() {
     // Check common headers for forwarded IPs first
     if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
         return $_SERVER['HTTP_CLIENT_IP'];
     } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
         // HTTP_X_FORWARDED_FOR can contain multiple IPs (proxy chain), take the first one
         $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
         return trim($ips[0]);
     } else {
         // Fallback to the direct remote address
         return $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
     }
 }

 /**
  * Sets the authentication cookie with secure attributes.
  *
  * @param string $token The JWT token to store in the cookie.
  */
 function setAuthCookie($token) {
     global $AUTH_DURATION, $COOKIE_NAME;
     // Set the cookie with appropriate security flags
     setcookie($COOKIE_NAME, $token, [
         "expires" => time() + $AUTH_DURATION, // Set expiration time
         "path" => "/",                       // Available across the entire domain
         "domain" => "",                      // Set to your domain in production if needed, empty for current host
         "secure" => true,                    // Transmit only over HTTPS
         "httponly" => true,                  // Not accessible via JavaScript
         "samesite" => "None"                 // Required for cross-site requests (ensure 'secure' is also true)
         // Use "Lax" or "Strict" if the cookie is only needed for same-site contexts
     ]);
 }

 /**
  * Stores or updates the IP address and associated JWT token in the database.
  * Uses ON DUPLICATE KEY UPDATE for efficiency.
  *
  * @param string $ipAddress The client's IP address.
  * @param string $token The JWT token.
  * @return bool True on success, false on failure.
  */
 function storeIpAndToken($ipAddress, $token) {
     $conn = null; // Initialize connection variable
     $stmt = null; // Initialize statement variable
     try {
         $conn = getDbConnection();
         $timestamp = time(); // Current Unix timestamp

         // Use a prepared statement to prevent SQL injection
         // Insert a new record or update the token and timestamp if the IP address already exists
         $stmt = $conn->prepare("INSERT INTO auth_sessions (ip_address, token, timestamp) VALUES (?, ?, ?)
                                 ON DUPLICATE KEY UPDATE token = ?, timestamp = ?");
         // Ensure the table structure matches: ip_address (PK or UNIQUE), token, timestamp
         // Assuming ip_address is the PRIMARY KEY or has a UNIQUE constraint.
         $stmt->bind_param("ssisi", $ipAddress, $token, $timestamp, $token, $timestamp);
         $result = $stmt->execute();

         // Check for execution errors
         if (!$result) {
              error_log("Failed to store IP and token: " . $stmt->error);
         }

         $stmt->close();
         $conn->close();
         return $result;

     } catch (Exception $e) {
         // Log the exception
         error_log("Error in storeIpAndToken: " . $e->getMessage());
         // Clean up resources if they were initialized
         if ($stmt) $stmt->close();
         if ($conn) $conn->close();
         return false; // Indicate failure
     }
 }

 /**
  * Retrieves the stored token and timestamp for a given IP address.
  *
  * @param string $ipAddress The IP address to look up.
  * @return array|null An associative array with 'token' and 'timestamp' if found, otherwise null.
  */
 function getIpData($ipAddress) {
     $conn = null;
     $stmt = null;
     try {
         $conn = getDbConnection();

         // Prepare statement to safely query the database
         $stmt = $conn->prepare("SELECT token, timestamp FROM auth_sessions WHERE ip_address = ?");
         $stmt->bind_param("s", $ipAddress); // 's' for string
         $stmt->execute();
         $result = $stmt->get_result(); // Get the result set

         $data = null;
         if ($result->num_rows > 0) {
             // Fetch the data if a record exists
             $row = $result->fetch_assoc();
             $data = [
                 "token" => $row['token'],
                 "timestamp" => (int)$row['timestamp'] // Ensure timestamp is integer
             ];
         }

         $stmt->close();
         $conn->close();
         return $data;

     } catch (Exception $e) {
         error_log("Error in getIpData: " . $e->getMessage());
         if ($stmt) $stmt->close();
         if ($conn) $conn->close();
         return null; // Indicate failure or not found
     }
 }

 /**
  * Generates a cryptographically secure random state token (hex string).
  *
  * @return string A 32-character hexadecimal state token.
  */
 function generateStateToken() {
     // Generate 16 random bytes and convert to a 32-character hex string
     return bin2hex(random_bytes(16));
 }

 /**
  * Stores the state token associated with an IP address in the auth_state table.
  * Creates the table if it doesn't exist.
  *
  * @param string $ipAddress The client's IP address.
  * @param string $stateToken The state token to store.
  * @return bool True on success, false on failure.
  */
 function storeStateToken($ipAddress, $stateToken) {
      $conn = null;
      $stmt = null;
      try {
          $conn = getDbConnection();

          // Simple table creation - consider proper migrations for production
          $conn->query("CREATE TABLE IF NOT EXISTS auth_state (
              ip_address VARCHAR(45) NOT NULL PRIMARY KEY, -- IP address is the primary key
              state_token VARCHAR(64) NOT NULL,           -- Store the state token
              timestamp INT UNSIGNED NOT NULL             -- Store the creation time
          )");
          // Consider adding an index on timestamp if you query by it often

          $timestamp = time(); // Current Unix timestamp

          // Prepare statement for inserting or updating the state token
          $stmt = $conn->prepare("INSERT INTO auth_state (ip_address, state_token, timestamp) VALUES (?, ?, ?)
                                  ON DUPLICATE KEY UPDATE state_token = ?, timestamp = ?");
          // 'ssisi' for string, string, integer, string, integer
          $stmt->bind_param("ssisi", $ipAddress, $stateToken, $timestamp, $stateToken, $timestamp);
          $result = $stmt->execute();

          if (!$result) {
              error_log("Failed to store state token: " . $stmt->error);
          }
          $stmt->close();
          $conn->close();
          return $result;
      } catch (Exception $e) {
          error_log("Error in storeStateToken: " . $e->getMessage());
          if ($stmt) $stmt->close();
          if ($conn) $conn->close();
          return false;
      }
 }

 /**
  * Verifies the provided state token against the one stored for the IP address.
  * Deletes the token after verification (one-time use). Checks expiration (10 minutes).
  *
  * @param string $ipAddress The client's IP address.
  * @param string $stateToken The state token received from the client (may include encoded params).
  * @return bool True if the token is valid and not expired, false otherwise.
  */
 function verifyStateToken($ipAddress, $stateToken) {
     // Extract the actual token part (everything before the first colon, if present)
     $tokenParts = explode(':', $stateToken, 2); // Limit split to 2 parts
     $actualToken = $tokenParts[0];

     $conn = null;
     $stmt = null;
     $deleteStmt = null;
     try {
         $conn = getDbConnection();

         // Prepare statement to fetch the stored token and timestamp
         $stmt = $conn->prepare("SELECT state_token, timestamp FROM auth_state WHERE ip_address = ?");
         $stmt->bind_param("s", $ipAddress);
         $stmt->execute();
         $result = $stmt->get_result();

         $isValid = false; // Default to invalid

         if ($result->num_rows > 0) {
             $row = $result->fetch_assoc();
             $storedToken = $row['state_token'];
             $timestamp = (int)$row['timestamp'];

             // Check if the provided token matches the stored token
             // Use hash_equals for timing-attack resistant comparison
             if (hash_equals($storedToken, $actualToken)) {
                  // Check if the token is within the valid time window (10 minutes = 600 seconds)
                  if ((time() - $timestamp) <= 600) {
                      $isValid = true;
                  } else {
                      error_log("State token expired for IP: " . $ipAddress);
                  }
             } else {
                  error_log("State token mismatch for IP: " . $ipAddress . ". Received: " . $actualToken . ", Expected: " . $storedToken);
             }

             // --- Clean up the used/checked token regardless of validity ---
             // Ensure cleanup happens even if validation failed
             try {
                 $deleteStmt = $conn->prepare("DELETE FROM auth_state WHERE ip_address = ?");
                 $deleteStmt->bind_param("s", $ipAddress);
                 $deleteStmt->execute();
                 $deleteStmt->close(); // Close delete statement immediately
             } catch (Exception $deleteError) {
                 // Log error during deletion but don't necessarily fail the overall verification result based on this
                 error_log("Error deleting state token for IP " . $ipAddress . ": " . $deleteError->getMessage());
             }
             // --- End cleanup ---

         } else {
              error_log("No state token found for IP: " . $ipAddress);
         }

         $stmt->close();
         $conn->close();
         return $isValid;

     } catch (Exception $e) {
         error_log("Error in verifyStateToken: " . $e->getMessage());
         // Ensure resources are closed in case of exception
         // Check if statement exists and is not already closed before trying to close
         if (isset($deleteStmt) && $deleteStmt instanceof mysqli_stmt && $deleteStmt->errno === 0) {
             @$deleteStmt->close(); // Use @ to suppress errors if already closed
         }
         if (isset($stmt) && $stmt instanceof mysqli_stmt) {
            @$stmt->close();
         }
         if (isset($conn) && $conn instanceof mysqli) {
            @$conn->close();
         }
         return false; // Indicate failure
     }
 }


 /**
  * Extracts original parameters encoded in the state token.
  * Format: 'token:url_encoded_json_string'.
  *
  * @param string $stateToken The state token potentially containing encoded parameters.
  * @return array An associative array of the original parameters, or empty array if none found or error.
  */
 function extractOriginalParams($stateToken) {
     $parts = explode(':', $stateToken, 2); // Split into max 2 parts: token and the rest

     // Check if there's a second part containing parameters
     if (count($parts) < 2 || empty($parts[1])) {
         return []; // No parameters encoded
     }

     // Get the URL-encoded JSON string part
     $encodedParams = $parts[1];
     // Decode the URL encoding
     $jsonParams = urldecode($encodedParams);

     // Parse the JSON string into an associative array
     $params = json_decode($jsonParams, true); // 'true' for associative array

     // Return the decoded parameters or an empty array if JSON decoding fails
     return $params ?: [];
 }

 /**
  * Verifies a JWT token's signature and expiration ONLY.
  * Does NOT check IP address claim here.
  *
  * @param string $token The JWT token to verify.
  * @return object|array Decoded payload object on success, or an array ['error' => string] on failure.
  */
 function verifyTokenSignatureAndExpiry($token) {
     global $JWT_SECRET;
     try {
         // Decode the JWT token using the secret key and HS256 algorithm
         // This automatically checks signature and standard time claims (exp, nbf, iat)
         $decoded = JWT::decode($token, new Key($JWT_SECRET, 'HS256'));
         // Ensure $decoded is an object (as expected by JWT::decode on success)
         if (is_object($decoded)) {
            return $decoded; // Return the decoded payload object
         } else {
            // Should not happen with successful decode, but handle defensively
            error_log("JWT::decode returned non-object on apparent success.");
            return ["error" => "Invalid token structure after decode"];
         }

     } catch (\Firebase\JWT\ExpiredException $e) {
         // Token has expired
         error_log("Token verification failed: Expired - " . $e->getMessage());
         return ["error" => "Token expired"];
     } catch (\Firebase\JWT\SignatureInvalidException $e) {
         // Token signature is invalid (tampered or wrong secret)
         error_log("Token verification failed: Invalid Signature - " . $e->getMessage());
         return ["error" => "Invalid token signature"];
     } catch (Exception $e) { // Catches other JWT errors (BeforeValidException, UnexpectedValueException, etc.)
         // Other JWT decoding errors (e.g., malformed token, algorithm mismatch)
         error_log("Token verification failed: " . $e->getMessage());
         return ["error" => "Invalid token"];
     }
 }

 // --- Request Handling ---

 // Set default content type to JSON
 header('Content-Type: application/json');

 // Handle CORS preflight OPTIONS requests
 if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
     // Respond with OK status and exit - headers are already set
     http_response_code(200);
     exit(0);
 }

 // Basic routing based on 'route' query parameter
 $route = $_GET['route'] ?? '';

 // --- Endpoint: /initiate-auth (GET) ---
 // Generates and stores a state token for the client's IP.
 if ($_SERVER['REQUEST_METHOD'] === 'GET' && $route === 'initiate-auth') {
     try {
         $clientIp = getClientIp();
         if ($clientIp === 'UNKNOWN') {
             // Provide a more specific error before throwing generic exception
             http_response_code(400); // Bad Request
             echo json_encode(["success" => false, "error" => "Could not determine client IP address."]);
             exit;
             // throw new Exception("Could not determine client IP address."); // Alternative
         }

         // Generate a secure state token
         $stateToken = generateStateToken();
         // Store the token associated with the IP
         if (!storeStateToken($clientIp, $stateToken)) {
             throw new Exception("Failed to store state token."); // Caught below
         }

         // Return the state token to the client
         echo json_encode([
             "success" => true,
             "state" => $stateToken // Client needs this for the callback
         ]);

     } catch (Exception $error) {
         error_log("Auth initiation error: " . $error->getMessage());
         http_response_code(500); // Internal Server Error
         // Provide a generic error to the client
         echo json_encode(["success" => false, "error" => "Internal server error during auth initiation."]);
     }
     exit; // Stop script execution
 }

 // --- Endpoint: /check-auth (GET) ---
 // Checks auth via cookie (JWT) or existing IP session, handles IP changes.
 if ($_SERVER['REQUEST_METHOD'] === 'GET' && $route === 'check-auth') {
     try {
         $clientIp = getClientIp();
         if ($clientIp === 'UNKNOWN') {
             http_response_code(400); // Bad Request
             echo json_encode(["authenticated" => false, "error" => "Could not determine client IP."]);
             exit;
         }

         // --- Referrer Check ---
         $allowed_referrer_base = 'https://cricster.pages.dev';
         $referrer = $_SERVER['HTTP_REFERER'] ?? '';
         // Use str_starts_with (PHP 8+) or fallback for older versions
         $is_allowed = false;
         if (function_exists('str_starts_with')) {
             $is_allowed = str_starts_with(strtolower($referrer), $allowed_referrer_base);
         } else {
             // Fallback for PHP < 8
             $is_allowed = (strpos(strtolower($referrer), $allowed_referrer_base) === 0);
         }

         if (!$is_allowed) {
             http_response_code(403); // Forbidden
             error_log("Invalid referrer detected: " . $referrer . " for IP: " . $clientIp);
             echo json_encode([
                 "authenticated" => false,
                 "error" => "Access denied. Invalid origin.",
                 // "debug_referrer" => $referrer // Uncomment ONLY for temporary debugging
             ]);
             exit;
         }
         // --- End Referrer Check ---

         $token = $_COOKIE[$COOKIE_NAME] ?? null;
         $authResult = ["authenticated" => false]; // Default state
         $verificationError = null; // To store potential token verification error message

         // 1. Check for a JWT token in the cookie and verify its signature/expiry
         if ($token) {
             $decodedPayload = verifyTokenSignatureAndExpiry($token);

             if (is_object($decodedPayload) && isset($decodedPayload->ip)) { // Check if decode was successful and payload has 'ip'
                 $tokenIp = $decodedPayload->ip;

                 // Compare IP from valid token with current client IP
                 if (hash_equals($tokenIp, $clientIp)) {
                     // Token is valid AND IP matches
                     $authResult = ["authenticated" => true, "method" => "token"];
                     // Optional: Update timestamp in DB to track activity?
                     // storeIpAndToken($clientIp, $token); // Careful: only if you want to refresh timestamp on every check
                 } else {
                     // Token is valid BUT IP mismatch - Authenticate and refresh token/IP
                     error_log("Valid token with IP mismatch. Old IP: $tokenIp, New IP: $clientIp. Refreshing.");

                     // Generate a NEW token with the CURRENT IP
                     $newTokenPayload = [
                         "ip" => $clientIp, // Use the new IP
                         "timestamp" => time(),
                         "iat" => time(),
                         "exp" => time() + $AUTH_DURATION
                         // Add other claims from $decodedPayload if needed, e.g., user ID
                         // 'user_id' => $decodedPayload->user_id ?? null
                     ];
                     $newToken = JWT::encode($newTokenPayload, $JWT_SECRET, 'HS256');

                     // Store the NEW token associated with the NEW IP
                     if (!storeIpAndToken($clientIp, $newToken)) {
                          error_log("Failed to update token in DB during IP refresh for IP: $clientIp");
                          // Decide if this is fatal: maybe proceed but log, as cookie is set
                     }

                     // Set the NEW token in the cookie
                     setAuthCookie($newToken);

                     $authResult = ["authenticated" => true, "method" => "token_ip_updated"];
                 }
             } else {
                 // Decode failed (expired, invalid signature, malformed, etc.)
                 $verificationError = $decodedPayload['error'] ?? 'Invalid token'; // Get error reason
                 error_log("Token verification failed: " . $verificationError . " for IP: " . $clientIp);
                 // Expire the invalid cookie (ensure all params match setAuthCookie except expiry)
                 setcookie($COOKIE_NAME, '', time() - 3600, "/", "", true, true); // Expire past
                 // Authentication remains false, proceed to IP check below
             }
         }

         // 2. If no token, or token verification failed, check for an active IP-based session
         if (!$authResult["authenticated"]) {
             $ipData = getIpData($clientIp);

             if ($ipData && (time() - $ipData['timestamp']) < $AUTH_DURATION) {
                 // Valid IP session exists in DB, issue a new token
                 error_log("No valid token (or failed verification), but found active DB session for IP: $clientIp. Refreshing token.");
                 $newTokenPayload = [
                     "ip" => $clientIp,
                     "timestamp" => time(),
                     "iat" => time(),
                     "exp" => time() + $AUTH_DURATION
                 ];
                 $newToken = JWT::encode($newTokenPayload, $JWT_SECRET, 'HS256');
                 setAuthCookie($newToken);
                 // Update DB with the new token for this IP
                 storeIpAndToken($clientIp, $newToken);
                 $authResult = ["authenticated" => true, "method" => "ip_refresh"];
             } else {
                  if ($ipData) { // IP session existed but expired
                      error_log("Expired DB session found for IP: " . $clientIp);
                      // Optionally: Clean up expired DB entry here
                      // try { $conn = getDbConnection(); $stmt = $conn->prepare("DELETE FROM auth_sessions WHERE ip_address = ?"); $stmt->bind_param("s", $clientIp); $stmt->execute(); $stmt->close(); $conn->close(); } catch (Exception $cleanupError) { error_log("Error cleaning up expired session: ".$cleanupError->getMessage()); }
                  }
                  // No valid token AND no valid/active IP session in DB
                  // Use the verification error if available, otherwise a generic message
                  $authResult['reason'] = $verificationError ?? 'No valid session found';
             }
         }

         // --- Respond based on final authentication status ---
         if ($authResult["authenticated"]) {
             http_response_code(200); // OK
             echo json_encode($authResult);
         } else {
             http_response_code(401); // Unauthorized
             // Ensure reason is included if available
             echo json_encode($authResult); // Includes 'authenticated' => false and potentially 'reason'
         }

     } catch (Exception $error) {
         error_log("Auth check error: " . $error->getMessage());
         http_response_code(500); // Internal Server Error
         echo json_encode(["authenticated" => false, "error" => "Internal server error during auth check."]);
     }
     exit; // Stop script execution
 }


 // --- Endpoint: /verify-token (POST) ---
 // Verifies a token provided in the request body. Keeps strict IP check.
 if ($_SERVER['REQUEST_METHOD'] === 'POST' && $route === 'verify-token') {
     try {
         $clientIp = getClientIp();
         if ($clientIp === 'UNKNOWN') {
             // ** Filled in IP error handling **
             http_response_code(400);
             echo json_encode(["authenticated" => false, "error" => "Could not determine client IP."]);
             exit;
         }

         // Get token from JSON request body
         $input = json_decode(file_get_contents("php://input"), true);
         $token = $input['token'] ?? null;

         if (!$token) {
             // ** Filled in missing token error handling **
             http_response_code(400); // Bad Request
             echo json_encode(["authenticated" => false, "error" => "Token required in request body."]);
             exit;
         }

         // *** Using the NEW verify function FIRST ***
         $decodedPayload = verifyTokenSignatureAndExpiry($token);

         if (is_object($decodedPayload) && isset($decodedPayload->ip)) {
             // Signature/Expiry OK. NOW check IP for this specific endpoint.
             if (hash_equals($decodedPayload->ip, $clientIp)) {
                 // IPs match - Verification successful for this endpoint's purpose
                 // Optionally set cookie if this endpoint implies login
                 // setAuthCookie($token);
                 http_response_code(200); // OK
                 echo json_encode(["authenticated" => true, "method" => "token_verified"]);
             } else {
                 // Valid token, but IP mismatch - fail for this specific endpoint
                 error_log("/verify-token IP mismatch. Token IP: " . $decodedPayload->ip . ", Client IP: " . $clientIp);
                 http_response_code(401); // Unauthorized
                 echo json_encode(["authenticated" => false, "reason" => "Token valid but IP mismatch for verification"]);
             }
         } else {
             // Token failed signature/expiry check
             http_response_code(401); // Unauthorized
             echo json_encode(["authenticated" => false, "reason" => $decodedPayload['error'] ?? 'Invalid token']);
         }

     } catch (Exception $error) {
         // ** Filled in generic error handling for the catch block **
         error_log("Token verification error [/verify-token]: " . $error->getMessage());
         http_response_code(500); // Internal Server Error
         echo json_encode(["authenticated" => false, "error" => "Internal server error during token verification."]);
     }
     exit; // Stop script execution
 }


 // --- Endpoint: /auth-callback (GET) ---
 // Handles redirect after external action, verifies state, generates JWT, stores, sets cookie, redirects.
 if ($_SERVER['REQUEST_METHOD'] === 'GET' && $route === 'auth-callback') {
     try {
         $clientIp = getClientIp();
          if ($clientIp === 'UNKNOWN') {
              // Provide specific error before throwing
              http_response_code(400);
              echo json_encode(["error" => "Could not determine client IP address for callback."]);
              exit;
              // throw new Exception("Could not determine client IP address for callback.");
          }
         $stateTokenWithParams = $_GET['state'] ?? ''; // Get the full state string from query param

         // Verify State Token (prevents CSRF)
         if (empty($stateTokenWithParams) || !verifyStateToken($clientIp, $stateTokenWithParams)) {
             // Invalid or missing state token - prevents CSRF
             http_response_code(400); // Bad Request
             error_log("Invalid or missing state token during auth callback for IP: " . $clientIp);
             // Provide error response to client
             echo json_encode(["error" => "Invalid authentication request or state token."]);
             exit;
         }
         // State is valid, proceed with authentication

         // Extract Original Parameters encoded in state (if any)
         $originalParams = extractOriginalParams($stateTokenWithParams);

         // Generate NEW JWT Token for the CURRENT IP
         $payload = [
             "ip" => $clientIp,        // Bind token to the current IP
             "timestamp" => time(),    // Record creation time in payload
             "iat" => time(),          // Issued At timestamp (standard JWT claim)
             "exp" => time() + $AUTH_DURATION // Expiration timestamp (standard JWT claim)
             // Add other relevant user data here if applicable (e.g., user ID from an OAuth flow)
         ];
         $token = JWT::encode($payload, $JWT_SECRET, 'HS256');

         // Store Session Info (IP/New Token)
         if (!storeIpAndToken($clientIp, $token)) {
              // Log the error but potentially continue; the cookie is the primary mechanism now.
              error_log("Failed to store IP and token after successful auth callback for IP: " . $clientIp);
              // Depending on requirements, you might throw an exception here instead.
         }

         // Set Auth Cookie
         setAuthCookie($token);

         // Prepare Redirect URL back to frontend
         $baseUrl = 'https://cricster.pages.dev'; // Base frontend URL (no trailing slash needed)
         $redirectParams = $originalParams; // Start with params from state

         // Add authentication result parameters
         $redirectParams['auth-return'] = 'true'; // Indicate successful auth return
         // $redirectParams['auth-token'] = $token; // Optional: Send token in URL? Cookie is usually sufficient.

         // Build the final query string using http_build_query
         // This function handles URL encoding of keys and values correctly.
         $queryString = http_build_query($redirectParams);

         // Construct the full redirect URL
         // Ensure no double slash if baseUrl ends with / and query string is empty
         $redirectUrl = rtrim($baseUrl, '/') . '/?' . $queryString;

         // --- Perform Redirect ---
         header("Location: " . $redirectUrl); // Send 302 Redirect header
         exit; // Important: Stop script execution after sending redirect header

     } catch (Exception $error) {
         error_log("Auth callback error: " . $error->getMessage());
         http_response_code(500); // Internal Server Error
         // Avoid redirecting on error, show an error message instead
         echo json_encode(["error" => "An internal error occurred during authentication callback."]);
     }
     exit; // Stop script execution
 }


 // --- Fallback for Invalid Routes ---
 // If none of the above routes matched
 http_response_code(404); // Not Found
 echo json_encode(["error" => "Endpoint not found."]);
 exit;

?>
