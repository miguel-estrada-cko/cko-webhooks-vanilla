<?php

/**
 * Config
 */
$authorizationKey = '2b664601-3603-49ad-bdac-839b08c18f24';
$signatureKey = 'addbd2ef-91c0-4ed8-b99d-e6d832df2f38';
$acceptedWebhooks = [
    'payment_captured',
    'payment_approved',
];

/**
 * Security
 */
try {
    // Do not allow non-post request
    if (($_SERVER['REQUEST_METHOD'] ?? null) !== 'POST')
        throw new ErrorException('Method Not Allowed', 405);

    // Check authorization header
    if (($_SERVER['HTTP_AUTHORIZATION'] ?? null) !== $authorizationKey)
        throw new ErrorException('Unauthorized', 401);

    // Verify signature
    $body = file_get_contents('php://input');
    if (($_SERVER['HTTP_CKO_SIGNATURE'] ?? null) !== hash_hmac('sha256', $body, $signatureKey))
        throw new ErrorException('Forbidden', 403);

    // Check webhook type
    $webhook = json_decode(file_get_contents('php://input'), true);
    if (!in_array($webhook['type'], $acceptedWebhooks))
        throw new ErrorException('Not Acceptable', 406);

} catch (ErrorException $t) {
    header(sprintf('HTTP/1.1 %s %s', $t->getCode(), $t->getMessage()));
    exit;
} catch (Throwable $t) {
    header('HTTP/1.1 500 Internal Server Error');
    exit;
}

/**
 * Execute
 */
try {
    // Handle the webhook at $webhook
    // echo json_encode($webhook, JSON_PRETTY_PRINT);
    $type = $webhook['type'];
    $data = $webhook['data'];

    $isHandled = match ($type) {
        'payment_approved' => handlePaymentApprovedWebhook($data),
        'payment_captured' => handlePaymentCapturedWebhook($data),
        default => throw new ErrorException(sprintf('Unable to find handler for: %s', $type)),
    };

    // Output
    printf('Webhook %s processed, status: %s', $type, $isHandled ? 'OK' : 'KO');

} catch (ErrorException $t) {
    printf($t->getMessage());
} catch (Throwable $t) {
    printf('Unable to process webhook: %s', $t->getMessage());
}

/**
 * Webhook handlers
 */

/**
 * Handles payment_approved webhook
 *
 * @param $data
 * @return bool
 */
function handlePaymentApprovedWebhook($data): bool
{
    printf('Processing payment_approved webhook for payment id: %s' . PHP_EOL, $data['id']);
    return true;
}

/**
 * Handles payment_captured webhook
 *
 * @param $data
 * @return bool
 */
function handlePaymentCapturedWebhook($data): bool
{
    printf('Processing payment_captured webhook for payment id: %s' . PHP_EOL, $data['id']);
    return true;
}