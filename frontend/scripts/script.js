// == Configuration ==
var AUTH_API_URL = ''; // the index page URL
var SERVER_DATA_URL = ''; // URL to fetch server data
var WEBPAGE_DATA_URL = ''; // URL to fetch webpage data
var AUTH_PAGE = '/auth.html'; // Relative path to auth page

// == Loading Indicator Functions ==
function showLoadingIndicator() {
    var loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'flex';
    }
}

function hideLoadingIndicator() {
    var loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'none';
    }
}

// == Data Fetching Function (XMLHttpRequest) ==
/**
 * Fetches data from a URL using XMLHttpRequest.
 * @param {string} url The URL to fetch data from.
 * @param {string} method The HTTP method (e.g., 'GET', 'POST').
 * @param {object|null} options Optional settings: { headers: object, body: any, withCredentials: true|false }
 * @returns {Promise<any>} A promise that resolves with the parsed JSON data or rejects with an error.
 */
function fetchData(url, method, options) {
    return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open(method || 'GET', url, true); // true for asynchronous

        // Set headers if provided
        if (options && options.headers) {
            for (var header in options.headers) {
                if (options.headers.hasOwnProperty(header)) {
                    xhr.setRequestHeader(header, options.headers[header]);
                }
            }
        }

        // Include credentials (cookies) if requested
        if (options && options.withCredentials) {
            xhr.withCredentials = true;
        }

        xhr.onload = function () {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    // Attempt to parse JSON response
                    resolve(JSON.parse(xhr.responseText));
                } catch (e) {
                    // Handle cases where response is not JSON
                    console.warn("Response was not valid JSON for URL:", url);
                    resolve(xhr.responseText); // Resolve with raw text if not JSON
                }
            } else {
                // Reject on HTTP error status
                reject(new Error('HTTP error! Status: ' + xhr.status + ' ' + xhr.statusText));
            }
        };

        xhr.onerror = function () {
            // Reject on network errors
            reject(new Error('Network request failed for URL: ' + url));
        };

        // Send the request
        if (options && options.body) {
            xhr.send(options.body);
        } else {
            xhr.send();
        }
    });
}


// == Server Data Functions ==
function getServerData() {
    showLoadingIndicator();
    return fetchData(SERVER_DATA_URL, 'GET')
        .then(function (data) {
            hideLoadingIndicator();
            return data;
        })
        .catch(function (error) {
            console.error('Error fetching server data:', error);
            hideLoadingIndicator();
            alert('Failed to load server list. Please try again later.');
            return { servers: {} }; // Return default empty structure on error
        });
}

// == Webpage Data Functions ==
function getWebpageData() {
    return fetchData(WEBPAGE_DATA_URL, 'GET')
        .catch(function (error) {
            console.error('Error fetching webpage data:', error);
            // Don't show alert for webpage data - it's secondary
            return { webpages: [] }; // Return default empty structure on error
        });
}

// == Server Functions ==
function getAllServers(json) {
    var servers = {};
    if (!json) return servers; // Handle null/undefined json
    for (var key in json) {
        // Use hasOwnProperty for safer iteration
        if (json.hasOwnProperty(key) && key.toLowerCase().startsWith('server')) {
            servers[key] = json[key];
        }
    }
    return servers;
}

function populateServerDropdown(json) {
    var selectEl = document.getElementById('serverDropdown');
    // Ensure selectEl exists before proceeding
    if (!selectEl) {
        console.error("Element with ID 'serverDropdown' not found.");
        return '';
    }
    selectEl.innerHTML = ''; // Clear existing options
    var servers = getAllServers(json);
    var keys = Object.keys(servers);

    if (!keys.length) {
        var noServerOpt = document.createElement('option');
        noServerOpt.textContent = 'No servers available';
        noServerOpt.disabled = true; // Make it unselectable
        selectEl.appendChild(noServerOpt);
        return ''; // Indicate no initial URL
    }

    keys.forEach(function (key) {
        var opt = document.createElement('option');
        opt.value = servers[key];
        opt.textContent = key.replace('server', 'Server ');
        selectEl.appendChild(opt);
    });

    // Add change event listener only once
    selectEl.onchange = function (e) { // Use onchange or ensure addEventListener isn't called multiple times
        updatePlayerSource(e.target.value);
    };

    // Set first server as default and return its URL
    if (keys.length > 0) {
        selectEl.selectedIndex = 0;
        return servers[keys[0]];
    }

    return ''; // Should not be reached if keys.length > 0, but good practice
}

// == Webpage Functions ==
function populateWebpageDropdown(webpages) {
    var selectEl = document.getElementById('webpageDropdown');
    var gotoBtn = document.getElementById('gotoWebpageBtn');

    // Ensure elements exist
    if (!selectEl || !gotoBtn) {
        console.error("Webpage selection elements ('webpageDropdown' or 'gotoWebpageBtn') not found.");
        return;
    }

    // Keep the default "Select a webpage" option
    selectEl.innerHTML = '<option value="">Select a webpage</option>';

    if (!webpages || webpages.length === 0) {
        var noPageOpt = document.createElement('option');
        noPageOpt.textContent = 'No webpages available';
        noPageOpt.disabled = true;
        selectEl.appendChild(noPageOpt);
        gotoBtn.disabled = true;
        return;
    }

    webpages.forEach(function (page, index) {
        var opt = document.createElement('option');
        opt.value = page.url;
        // Use page name or generate a default one
        opt.textContent = page.name || ('Webpage ' + (index + 1));
        selectEl.appendChild(opt);
    });

    // Add change event listener to enable/disable button
    selectEl.onchange = function (e) { // Use onchange or ensure addEventListener isn't called multiple times
        gotoBtn.disabled = !e.target.value; // Disable if value is empty ("")
    };

    // Add click event for goto button
    gotoBtn.onclick = function () { // Use onclick or ensure addEventListener isn't called multiple times
        var selectedUrl = selectEl.value;
        if (selectedUrl) {
            // Check if URL is absolute (starts with http:// or https://)
            if (selectedUrl.startsWith('http://') || selectedUrl.startsWith('https://')) {
                window.open(selectedUrl, '_blank'); // Open absolute URL directly
            } else {
                // Assume relative URL, construct full URL based on current origin
                var baseUrl = window.location.origin;
                window.open(baseUrl + '/' + selectedUrl.replace(/^\//, ''), '_blank'); // Ensure single slash
            }
        }
    };
}


// == JW Player Functions ==
function initPlayer(initialURL) {
    if (typeof jwplayer === 'undefined') {
        console.error('JW Player library (jwplayer) not found.');
        alert('Video player could not be loaded. Please ensure you are connected to the internet or try refreshing the page.');
        hideLoadingIndicator(); // Hide loading if player fails
        return;
    }

    if (!initialURL) {
        console.error('Cannot initialize player: No initial URL provided.');
        alert('No video source available to play.');
        hideLoadingIndicator();
        return;
    }

    try {
        var playerInstance = jwplayer("video"); // Get instance
        if (!playerInstance) {
            console.error("Could not get JW Player instance for element #video.");
            alert("Failed to attach player to video element.");
            hideLoadingIndicator();
            return;
        }
        playerInstance.setup({
            file: initialURL,
            preload: 'auto',
            autostart: false, // Let user initiate play
            width: "100%",
            aspectratio: "16:9", // Common aspect ratio, adjust if needed
            logo: {
                file: "jaishreeram.png", // Ensure this image exists or remove logo
                hide: true,
                position: 'top-right'
            }
        });

        // Hide loading indicator when player is ready or starts playing
        playerInstance.on('ready', hideLoadingIndicator);
        playerInstance.on('play', hideLoadingIndicator);
        playerInstance.on('error', function (event) {
            console.error("JW Player Error:", event.message);
            // alert("Error loading video: " + event.message);
            hideLoadingIndicator();
        });

    } catch (error) {
        console.error("Error setting up JW Player:", error);
        // alert("Failed to initialize the video player.");
        hideLoadingIndicator();
    }
}

function updatePlayerSource(url) {
    if (typeof jwplayer === 'undefined') {
        console.error('JW Player library not loaded.');
        alert('Player not ready. Please wait or refresh.');
        return;
    }
    var playerInstance = jwplayer("video"); // Get instance
    if (!playerInstance || typeof playerInstance.load !== 'function') {
        console.error('JW Player not initialized or invalid instance, cannot update source.');
        alert('Player not ready. Please wait or refresh.');
        return;
    }
    if (!url) {
        console.warn('Attempted to update player with an empty URL.');
        return; // Don't try to load an empty URL
    }

    showLoadingIndicator(); // Show loading before changing source
    try {
        playerInstance.load([{ file: url }]);
        // Autoplay after loading the new source
        // Note: Autoplay might be blocked by browsers
        playerInstance.play();

        // Ensure loading indicator hides on play or if an error occurs during load
        playerInstance.once('play', hideLoadingIndicator); // Use 'once' to avoid multiple calls
        playerInstance.once('error', function (event) {
            console.error("JW Player Error on load:", event.message);
            alert("Error loading new video source: " + event.message);
            hideLoadingIndicator();
        });
        // Add a timeout fallback to hide indicator if play event doesn't fire
        setTimeout(function () {
            var loadingIndicator = document.getElementById('loading-indicator');
            // Check if indicator exists and is visible
            if (loadingIndicator && loadingIndicator.style.display === 'flex') {
                console.warn("Hiding loading indicator due to timeout (play event might not have fired).");
                hideLoadingIndicator();
            }
        }, 5000); // 5 seconds timeout

    } catch (error) {
        console.error("Error loading new source in JW Player:", error);
        alert("Failed to load the selected video source.");
        hideLoadingIndicator();
    }
}

// == Authentication Functions (Using Promises) ==
function checkAuthentication() {
    return new Promise(function (resolve, reject) {
        // Check if we have a token in the URL (for cross-domain auth)
        var urlParams;
        try {
            urlParams = new URLSearchParams(window.location.search);
        } catch (e) {
            console.warn("URLSearchParams not supported or failed. Proceeding without checking URL token.");
            performRegularAuthCheck(resolve, reject); // Skip URL token check
            return;
        }

        var authToken = urlParams.get('auth-token');

        if (authToken) {
            // We have a token from the callback, send it to verify
            fetchData(AUTH_API_URL + '/verify-token', 'POST', {
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: authToken }),
                withCredentials: true
            })
                .then(function (verificationData) { // Assuming verify returns some data on success
                    // Token verified, remove from URL
                    if (window.history && window.history.replaceState) {
                        window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
                    }
                    console.log("Token verified via URL parameter.");
                    resolve(true); // Resolve as authenticated
                })
                .catch(function (error) {
                    console.error('Token verification failed:', error);
                    // Even if verification fails, proceed to regular check
                    performRegularAuthCheck(resolve, reject);
                });
        } else {
            // No token in URL, perform regular authentication check
            performRegularAuthCheck(resolve, reject);
        }
    });
}

function performRegularAuthCheck(resolve, reject) {
    fetchData(AUTH_API_URL + '/check-auth', 'GET', { withCredentials: true })
        .then(function (data) {
            if (data && data.authenticated) {
                console.log("User is authenticated via session.");
                resolve(true); // Resolve as authenticated
            } else {
                console.log("User is not authenticated via session.");
                redirectToAuthPage();
                resolve(false); // Resolve as not authenticated (though redirection happens)
            }
        })
        .catch(function (error) {
            console.error('Authentication check failed:', error);
            redirectToAuthPage();
            // We reject here because the check itself failed, preventing app init
            reject(new Error('Authentication check failed, redirecting.'));
        });
}

function redirectToAuthPage() {
    // Redirect to the auth page, passing the current page as a return URL
    var currentUrl = window.location.href;
    // Remove existing auth-token or auth-return if present to avoid loops
    var cleanUrl = currentUrl.replace(/[\?&]auth-token=[^&]+/, '')
        .replace(/[\?&]auth-return=true/, '')
        .replace(/&$/, '').replace(/\?$/, '');
    // Add auth-return=true to signal the origin
    var separator = cleanUrl.indexOf('?') !== -1 ? '&' : '?';
    var returnUrl = encodeURIComponent(cleanUrl + separator + 'auth-return=true');

    window.location.href = AUTH_PAGE + '?returnUrl=' + returnUrl;
}


// == Telegram Notification Functions ==
// Make these functions globally accessible if called by inline onclick attributes
// Alternatively, attach event listeners in initializeApp
function showNotification() {
    // Check localStorage compatibility
    try {
        if (localStorage.getItem('telegramNotificationDismissed') === 'true') return;
        var notification = document.getElementById('telegram-notification');
        if (notification) {
            notification.classList.add('show');
        }
    } catch (e) {
        console.warn("localStorage is not available. Telegram notification check skipped.");
        // Optionally show it anyway if localStorage fails
        var notification = document.getElementById('telegram-notification');
        if (notification) {
            notification.classList.add('show');
        }
    }
}

function closeNotification() {
    var notification = document.getElementById('telegram-notification');
    if (notification) {
        notification.classList.remove('show');
    }
    // Check localStorage compatibility
    try {
        localStorage.setItem('telegramNotificationDismissed', 'true');
    } catch (e) {
        console.warn("localStorage is not available. Could not save notification dismissal state.");
    }
}

function dismissNotification() {
    var notification = document.getElementById('telegram-notification');
    if (notification) {
        notification.classList.remove('show');
    }
    // No need to save state here, just schedule next show
    setTimeout(showNotification, 30 * 60 * 1000); // Show again after 30 minutes
}

// == Session Management ==
function addSession() {
    // Check localStorage compatibility
    try {
        localStorage.setItem("accessTimestamp", Date.now());
    } catch (e) {
        console.warn("localStorage is not available. Session timestamp not recorded.");
    }
}

// == Main Initialization (Using Promises) ==
function initializeApp() {
    var serverDataResult; // To store server data for later use
    var urlParams;

    try {
        urlParams = new URLSearchParams(window.location.search);
    } catch (e) {
        console.warn("URLSearchParams not supported or failed. Proceeding with limited functionality.");
        urlParams = { // Create a dummy object with a 'get' method
            get: function () { return null; },
            has: function () { return false; }
        };
    }


    // Check for auth return flag first
    if (urlParams.has('auth-return')) {
        // Remove the parameter for cleaner browsing history
        if (window.history && window.history.replaceState) {
            window.history.replaceState({}, document.title, window.location.pathname + window.location.hash); // Keep hash if present
        }
    }

    // Start the chain: Check Authentication
    checkAuthentication()
        .then(function (isAuthenticated) {
            if (!isAuthenticated) {
                // If not authenticated, the checkAuthentication function handles redirection.
                // Throw an error here to stop the promise chain execution.
                throw new Error("Authentication required. Stopping initialization.");
            }
            console.log("Authentication successful. Proceeding...");
            // If authenticated, fetch server data
            return getServerData();
        })
        .then(function (serverData) {
            serverDataResult = serverData; // Store server data

            // Validate URL parameter 'v'
            var urlIdParam = urlParams.get('v');

            // Redirect if 'v' param is missing or doesn't match expected url_id
            var expectedUrlId = serverDataResult ? serverDataResult.url_id : undefined;

            if (!urlIdParam && expectedUrlId) {
                console.log("URL parameter 'v' missing, redirecting to add it.");
                window.location.href = '?v=' + encodeURIComponent(expectedUrlId) + window.location.hash; // Keep hash
                throw new Error("Redirecting to add URL parameter."); // Stop chain
            } else if (urlIdParam !== expectedUrlId) {
                console.warn("URL parameter 'v' (" + urlIdParam + ") does not match server data url_id (" + expectedUrlId + "). Redirecting to Telegram.");
                window.location.href = 'TELEGRAM_URL'; // Replace with actual Telegram URL
                throw new Error("Invalid URL parameter. Redirecting."); // Stop chain
            }

            // Populate servers and initialize player
            var firstServerURL = populateServerDropdown(serverDataResult);
            if (firstServerURL) {
                initPlayer(firstServerURL);
            } else {
                console.warn("No valid server URL found to initialize the player.");
                var videoElement = document.getElementById('video');
                if (videoElement) {
                    videoElement.innerHTML = '<p style="color:white; text-align:center; padding: 20px;">No video servers are currently available.</p>';
                }
                hideLoadingIndicator(); // Ensure loading is hidden
            }

            // Fetch webpage data (runs in parallel conceptually, but chained here for simplicity)
            return getWebpageData();
        })
        .then(function (webpageData) {
            // Populate webpage dropdown
            populateWebpageDropdown(webpageData ? webpageData.webpages : []);

            // Record session timestamp
            addSession();

            // Show Telegram notification after a delay
            setTimeout(showNotification, 3000);

            // Optional: Add event listeners for Telegram buttons here instead of inline JS
            var joinBtn = document.querySelector('.notification-btn.join-btn');
            var dismissBtn = document.querySelector('.notification-btn.dismiss-btn');
            var closeBtn = document.querySelector('.close-btn'); // Assuming this button exists

            if (joinBtn) {
                joinBtn.onclick = function () { window.open('TELEGRAM_URL', '_blank'); };
            }
            if (dismissBtn) {
                dismissBtn.onclick = dismissNotification; // Call the existing function
            }
            if (closeBtn) {
                closeBtn.onclick = closeNotification; // Call the existing function
            }


            console.log("Application initialized successfully.");
        })
        .catch(function (error) {
            // Catch errors from any part of the chain
            console.error('Initialization error:', error.message);
            // Avoid showing generic alert if it was an auth/redirect error
            if (!error.message.includes("Authentication") && !error.message.includes("Redirecting")) {
                alert('Failed to initialize the application fully. Please check your connection or try refreshing the page.');
            }
            hideLoadingIndicator(); // Ensure loading indicator is hidden on error
        });
}

// Start application initialization when the DOM is fully loaded
// Check if DOM is already loaded (interactive or complete)
if (document.readyState === "interactive" || document.readyState === "complete") {
    initializeApp();
} else {
    document.addEventListener('DOMContentLoaded', initializeApp);
}
