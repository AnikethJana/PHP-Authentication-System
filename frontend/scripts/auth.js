// Disable right-click on the entire page.
document.addEventListener('contextmenu', function (event) {
    event.preventDefault();
});

// Referrer check: Only allow access if coming from the allowed domain.
var allowedReferrer = ''; // Set this to the domain you want to allow access from mainly where frontend is hosted
if (!document.referrer.startsWith(allowedReferrer)) {
    document.body.innerHTML = '<p style="text-align:center; color:red; font-weight:bold;">Access Denied</p>';
    throw new Error('Access Denied: Unauthorized referrer.');
}

// Save original URL parameters from the referrer for later use.
function saveOriginalParams() {
    var referrer = document.referrer;
    if (referrer && referrer.indexOf(allowedReferrer) === 0) {
        var urlObj = new URL(referrer);
        var params = {};
        urlObj.searchParams.forEach(function (value, key) {
            params[key] = value;
        });
        localStorage.setItem('originalParams', JSON.stringify(params));
        console.log('Saved original parameters:', params);
    }
}

// Initiates the authentication process and returns the final redirect URL.
function initiateAuth() {
    var AUTH_API_URL = ''; // api url of your site where php file is hosted
    return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.withCredentials = true;
        xhr.open('GET', AUTH_API_URL + '/initiate-auth', true);
        xhr.onreadystatechange = function () {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                if (xhr.status >= 200 && xhr.status < 300) {
                    try {
                        var data = JSON.parse(xhr.responseText);
                        if (data.success && data.state) {
                            var stateWithParams = data.state;
                            var originalParams = localStorage.getItem('originalParams');
                            if (originalParams) {
                                var encodedParams = encodeURIComponent(originalParams);
                                stateWithParams = data.state + ':' + encodedParams;
                            }
                            // Build the final redirection URL.
                            var redirectUrl = 'use adlink url / the original domain of your site to return to' +
                                AUTH_API_URL + '/auth-callback?state=' + stateWithParams;
                            resolve(redirectUrl);
                        } else {
                            reject(new Error('Invalid response format'));
                        }
                    } catch (e) {
                        reject(new Error('Error parsing response: ' + e.message));
                    }
                } else {
                    reject(new Error('Authentication initiation failed. Status: ' + xhr.status));
                }
            }
        };
        xhr.onerror = function () {
            reject(new Error('Network error during auth initiation'));
        };
        xhr.send();
    });
}

// On DOM load, save parameters and bind the click handler.
document.addEventListener('DOMContentLoaded', function () {
    saveOriginalParams();
    var authButton = document.getElementById('myButton');
    authButton.addEventListener('click', function (e) {
        e.preventDefault();
        // Open a new tab with about:blank so that the initial URL isn’t revealed.
        var newWindow = window.open('about:blank', '_blank');
        if (!newWindow) {
            alert('Popup blocked. Please allow popups for this site.');
            return;
        }
        initiateAuth().then(function (redirectUrl) {
            if (redirectUrl) {
                newWindow.location.href = redirectUrl;
            }
        }).catch(function (error) {
            console.error('Auth initiation error:', error);
            alert('Authentication failed. Please try again later.');
        });
        // Save the current timestamp if needed.
        localStorage.setItem('authAttemptTime', Date.now());
    });
});