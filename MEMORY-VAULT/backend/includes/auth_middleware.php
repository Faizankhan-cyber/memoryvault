<?php
/**
 * MEMORY VAULT – Authentication & CSRF Verification Middleware
 */

declare(strict_types=1);

require_once __DIR__ . '/cors.php';

/**
 * Verify CSRF token on state-changing requests (POST, PUT, DELETE).
 */
function verifyCsrfToken(): void
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        return;
    }

    $providedToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $sessionToken  = $_SESSION['csrf_token'] ?? '';

    if ($sessionToken === '' || $providedToken === '' || !hash_equals($sessionToken, $providedToken)) {
        jsonResponse([
            'success' => false,
            'error'   => 'Invalid or missing CSRF security token. Please refresh the page and try again.',
        ], 403);
    }
}

/**
 * Enforce an authenticated vault owner session and return their numeric user_id.
 */
function requireUserAuth(): int
{
    if (empty($_SESSION['user_id'])) {
        jsonResponse([
            'success' => false,
            'error'   => 'Authentication required. Please sign in to access your vault.',
        ], 401);
    }

    return (int) $_SESSION['user_id'];
}

/**
 * Enforce an authenticated administrator session and return their numeric admin_id.
 */
function requireAdminAuth(): int
{
    if (empty($_SESSION['admin_id'])) {
        jsonResponse([
            'success' => false,
            'error'   => 'Administrator authentication required.',
        ], 401);
    }

    return (int) $_SESSION['admin_id'];
}

/**
 * Sanitize and trim string input safely.
 */
function cleanString($value, int $maxLength = 500): string
{
    $str = trim((string) ($value ?? ''));
    if (mb_strlen($str) > $maxLength) {
        $str = mb_substr($str, 0, $maxLength);
    }
    return $str;
}
