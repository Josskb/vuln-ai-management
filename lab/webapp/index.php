<?php
// MediConnect lab webapp — intentionally vulnerable for educational purposes

$redis_host = getenv('REDIS_HOST') ?: 'redis';
$redis_port = intval(getenv('REDIS_PORT') ?: 6379);

$redis = new Redis();
try {
    $redis->connect($redis_host, $redis_port);
    $cached = $redis->get('patients_count');
} catch (Exception $e) {
    $cached = null;
}

$db_host = getenv('DB_HOST') ?: 'mysql';
$db_user = getenv('DB_USER') ?: 'app_user';
$db_pass = getenv('DB_PASSWORD') ?: 'App2023!';
$db_name = getenv('DB_NAME') ?: 'mediconnect';

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name", $db_user, $db_pass);
    $count = $pdo->query("SELECT COUNT(*) FROM patients")->fetchColumn();
    if ($cached === null && $redis->isConnected()) {
        $redis->set('patients_count', $count, 300);
    }
} catch (Exception $e) {
    $count = "DB error: " . $e->getMessage();
}
?>
<!DOCTYPE html>
<html>
<head><title>MediConnect — Patient Portal</title></head>
<body style="font-family:sans-serif;padding:2rem;background:#0d1117;color:#c9d1d9">
  <h1 style="color:#58a6ff">MediConnect Corp — Patient Portal</h1>
  <p>Redis status: <strong><?= $redis->isConnected() ? 'Connected (no auth)' : 'Unavailable' ?></strong></p>
  <p>Total patients in database: <strong><?= htmlspecialchars((string)$count) ?></strong></p>
  <p style="color:#8b949e;font-size:0.8rem">Lab environment — intentionally misconfigured for security testing.</p>
</body>
</html>
