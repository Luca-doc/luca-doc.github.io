<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use League\OAuth2\Client\Provider\GenericProvider;

// @see https://oauth2-client.thephpleague.com/usage/

const APP_SESS_ID = 'AZPHPSID';

CONST TENNANT_ID               = "c6874728-71e6-41fe-a9e1-2e8c36776ad8";
const OAUTH_APP_ID             = '0ef992e8-fdbf-4f41-9f9d-bff4cdb09de4';
const OAUTH_APP_SECRET         = '';
const OAUTH_REDIRECT_URI       = '/auth.php?action=callback';

const OAUTH_SCOPES             = [
    'api://0ef992e8-fdbf-4f41-9f9d-bff4cdb09de4/user_impersonation', 
    'offline_access' // To get a refresh token
];
const OAUTH_AUTHORITY          = 'https://login.microsoftonline.com/' . TENNANT_ID;
const OAUTH_AUTHORIZE_ENDPOINT = '/oauth2/v2.0/authorize';
const OAUTH_TOKEN_ENDPOINT     = '/oauth2/v2.0/token';

$title = 'Hello public world!';


//
// THIS IS A PROOF OF CONCEPT! DO NOT USE IN PRODUCTION!!!
//

$https = false;
if (isset($_SERVER['HTTPS'])) {
    $https = true;
} elseif (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && 'https' === $_SERVER['HTTP_X_FORWARDED_PROTO']) {
    $https = true;
}

// Get the root op the application
$host = sprintf('%s://%s', ($https ? 'https' : 'http'), $_SERVER['HTTP_HOST']);

// Simple PHP routing
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$action = $_GET['action'] ?? '';

$user = null;

// If we run buit-in PHP web server, we want static files to be served directly
if ('cli-server' === php_sapi_name()) {
    $staticExtensions = ['jpg', 'jpeg', 'gif', 'png', 'ico', 'js', 'css'];
    $currentExtension = pathinfo($path, PATHINFO_EXTENSION);
    if (in_array($currentExtension, $staticExtensions)) {
        return false;
    }
}

session_name(APP_SESS_ID);
session_start();

// Checking for user
$user = [];
if (isset($_SESSION['user'])) {
    $user = unserialize($_SESSION['user']);
    $title = 'Hello private world';
}

// Checking for messages
$style = 'success';
$displayMessage = '';
if (isset($_GET['type']) && isset($_GET['message'])) {
    $styles = ['success', 'error'];
    if (in_array($_GET['type'], $styles)) {
        $style = $_GET['type'];
    }
    $displayMessage = $_GET['message'];
}

if ('logout' === $action) {
    session_destroy();
    setcookie(APP_SESS_ID, '', time() - 1000);
    header('Location: ' . $host . '/?type=success&message=Succesfully%20logged%20out');
}

if ('login' === $action) {
    $oAuthClient = new GenericProvider([
        'clientId'                => OAUTH_APP_ID,
        'clientSecret'            => OAUTH_APP_SECRET,
        'redirectUri'             => $host . OAUTH_REDIRECT_URI,
        'urlAuthorize'            => OAUTH_AUTHORITY . OAUTH_AUTHORIZE_ENDPOINT,
        'urlAccessToken'          => OAUTH_AUTHORITY . OAUTH_TOKEN_ENDPOINT,
        'urlResourceOwnerDetails' => '',
        'scopes'                  => implode(' ', OAUTH_SCOPES),
    ]);

    $authUrl = $oAuthClient->getAuthorizationUrl();
    $_SESSION['oauthState'] = $oAuthClient->getState();
    header('Location: ' . $authUrl);
}

if ('callback' === $action) {
    $expectedState = $_SESSION['oauthState'];
    unset($_SESSION['oauthState']);

    if (!isset($_GET['state']) || !isset($_GET['code'])) {
        header('Location: ' . $host . '/?type=error&message=No%20OAuth%20session');
    }

    $providedState = $_GET['state'];

    if (!isset($expectedState)) {
      // If there is no expected state in the session,
      // do nothing and redirect to the home page.
      header('Location: ' . $host . '/?type=error&message=Expected%20state%20not%20available');
    }

    if (!isset($providedState) || $expectedState != $providedState) {
      header('Location: ' . $host . '/?type=error&message=State%20does%20not%20match');
    }

    // Authorization code should be in the "code" query param
    $authCode = $_GET['code'];
    if (isset($authCode)) {
        // Initialize the OAuth client
        $oAuthClient = new GenericProvider([
            'clientId'                => OAUTH_APP_ID,
            'clientSecret'            => OAUTH_APP_SECRET,
            'redirectUri'             => $host . OAUTH_REDIRECT_URI,
            'urlAuthorize'            => OAUTH_AUTHORITY . OAUTH_AUTHORIZE_ENDPOINT,
            'urlAccessToken'          => OAUTH_AUTHORITY . OAUTH_TOKEN_ENDPOINT,
            'urlResourceOwnerDetails' => '',
            'scopes'                  => OAUTH_SCOPES,
        ]);

        $accessToken = null;
        try {
            // Make the token request
            $accessToken = $oAuthClient->getAccessToken('authorization_code', [
              'code' => $authCode
            ]);


        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            header('Location: ' . $host . '/?type=error&message=' . urlencode($e->getMessage()));
        }
    }

    $user = [];
    if (null !== $accessToken) {
        // error_log(print_r($accessToken->expires, true));


        // We have an access token, which we may use in authenticated
        // requests against the service provider's API.
        error_log('Access Token: ' . $accessToken->getToken() );
        error_log('Refresh Token: ' . $accessToken->getRefreshToken() );
        error_log('Expired in: ' . $accessToken->getExpires() );
        error_log('Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') );

    }
    header('Location: ' . $host . '/auth.php');
}
?>
<!DOCTYPE html>
<html lang="en_US">
    <head>
        <meta charset="UTF-8">
        <title><?php echo htmlentities($title, ENT_QUOTES, 'UTF-8') ?></title>
        <style type="text/css">
            html {
                font-family: Helvetica, Arial, sans-serif;
            }
            .error, .success {
                padding: 5px 15px;
            }
            .error {
                background-color: lightpink;
                border: 1px solid darkred;
                color: darkred;
            }
            .success {
                background-color: lightgreen;
                border: 1px solid darkgreen;
                color: darkgreen;
            }
        </style>
    </head>
    <body>
        <h1><?php echo htmlentities($title, ENT_QUOTES, 'UTF-8') ?></h1>
        <p>Welcome to PHP <strong><?php echo phpversion() ?></strong> on Azure App Service <strong><?php echo gethostname() ?></strong>.</p>
        <p>
            <a href="/">Home</a>
            <a href="?action=login">Login</a>
            <a href="?action=logout">Logout</a>
        </p>
        <?php if ('' !== $displayMessage): ?>
        <div class="<?php echo $style ?>">
            <p><?php echo htmlentities($displayMessage, ENT_QUOTES, 'UTF-8') ?></p>
        </div>
        <?php endif ?>
        <?php if ([] !== $user): ?>
            <p>User details</p>
            <ul>
                <li><strong>Name:</strong> <?php echo htmlentities($user['name'], ENT_QUOTES, 'UTF-8') ?></li>
                <li><strong>Email:</strong> <?php echo htmlentities($user['email'], ENT_QUOTES, 'UTF-8') ?></li>
            </ul>
        <?php endif ?>
    </body>
</html>