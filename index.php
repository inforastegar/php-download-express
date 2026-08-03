<?php
/**
 * PHP Simple Remote Downloader - Hardened & Optimized
 * Version: 3.0.0
 *
 * Fixes vs previous version:
 *  - Session-locking bug that blocked list/delete while a download was running
 *  - No CSRF protection on delete/download actions
 *  - No SSRF protection (could hit internal/private network addresses)
 *  - No execution protection for the downloads/ folder (RCE risk if a .php file is fetched)
 *  - No max file size guard (a huge file could fill shared-hosting disk quota)
 *  - Filename collisions could silently overwrite existing files
 *  - SSL peer verification disabled (MITM risk)
 *  - Filenames rendered with innerHTML (stored XSS risk)
 *  - Weak error/status handling on curl_exec()
 */

// ============================= CONFIGURATION =============================
// Leave empty to disable the login screen entirely.
define('ACCESS_PASSWORD', '');
// Always resolve relative to this file, not the current working directory.
define('DOWNLOAD_DIR', __DIR__ . '/downloads');
// Hard cap per downloaded file (bytes). 0 = no limit. Example: 500MB.
define('MAX_FILE_SIZE', 500 * 1024 * 1024);
// Total time (seconds) allowed for a single download before it's aborted.
define('DOWNLOAD_TIMEOUT', 0); // 0 = no timeout (rely on MAX_FILE_SIZE instead)
// Set to true only if you must fetch from servers with broken/self-signed certs.
define('ALLOW_INSECURE_SSL', false);
// ===========================================================================

// --- Server Settings (all wrapped with @ since shared hosts often lock these down) ---
@ini_set('max_execution_time', 0);
@set_time_limit(0);
@ini_set('memory_limit', '256M');
@ini_set('output_buffering', 0);
@ini_set('zlib.output_compression', 0);
@ini_set('display_errors', 0);
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);

// --- Ensure downloads dir exists and is locked down against script execution ---
if (!file_exists(DOWNLOAD_DIR)) {
    mkdir(DOWNLOAD_DIR, 0755, true);
}
ensureDownloadDirIsSafe();

function ensureDownloadDirIsSafe(): void {
    $htaccess = DOWNLOAD_DIR . '/.htaccess';
    if (!file_exists($htaccess)) {
        $rules = "Options -Indexes -ExecCGI -Includes\n"
               . "<IfModule mod_php.c>\n    php_flag engine off\n</IfModule>\n"
               . "<IfModule mod_php7.c>\n    php_flag engine off\n</IfModule>\n"
               . "<FilesMatch \"\\.(php|php[3-8]?|phtml|pl|py|cgi|sh|asp|aspx)$\">\n"
               . "    <IfModule mod_authz_core.c>\n        Require all denied\n    </IfModule>\n"
               . "    <IfModule !mod_authz_core.c>\n        Order allow,deny\n        Deny from all\n    </IfModule>\n"
               . "</FilesMatch>\n";
        @file_put_contents($htaccess, $rules);
    }
    $index = DOWNLOAD_DIR . '/index.html';
    if (!file_exists($index)) {
        @file_put_contents($index, '');
    }
}

// --- Secure session bootstrap ---
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

function checkCsrf(?string $token): bool {
    return isset($_SESSION['csrf_token']) && is_string($token) && hash_equals($_SESSION['csrf_token'], $token);
}

// --- Auth (simple slowdown against brute force) ---
if (ACCESS_PASSWORD !== '') {
    if (isset($_POST['password'])) {
        if (hash_equals(ACCESS_PASSWORD, (string)$_POST['password'])) {
            $_SESSION['logged_in'] = true;
        } else {
            usleep(500000); // 0.5s delay slows down brute-force attempts
            $error = 'رمز عبور اشتباه است.';
        }
    }
    if (empty($_SESSION['logged_in'])) {
        ?>
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;700&display=swap" rel="stylesheet">
            <style>body{font-family:'Vazirmatn',sans-serif;}</style>
        </head>
        <body class="bg-gray-900 text-gray-200 flex items-center justify-center h-screen">
            <form method="post" class="bg-gray-800 p-8 rounded-xl shadow-lg w-96 text-center">
                <h2 class="text-xl mb-4">Please enter password</h2>
                <?php if (isset($error)) echo '<p class="text-red-500 mb-2 text-sm">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</p>'; ?>
                <input type="password" name="password" class="w-full bg-gray-700 border border-gray-600 rounded p-2 mb-4 text-center focus:outline-none focus:border-blue-500 transition" placeholder="Password" autofocus>
                <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white p-2 rounded transition">Login</button>
            </form>
        </body>
        </html>
        <?php
        exit;
    }
}

// --- Helpers ---
function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1024 ** $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}

function sendSSE(array $data): void {
    echo 'data: ' . json_encode($data, JSON_UNESCAPED_UNICODE) . "\n\n";
    while (ob_get_level() > 0) { ob_end_flush(); }
    flush();
}

/**
 * Blocks obviously dangerous protocols/targets (loopback, private ranges, link-local)
 * to reduce SSRF risk. Not a full-proof network firewall, but stops the common cases.
 */
function isUrlAllowed(string $url): bool {
    $parts = @parse_url($url);
    if (!$parts || empty($parts['scheme']) || empty($parts['host'])) return false;
    if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) return false;

    $host = $parts['host'];
    $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
    if ($ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
        // DNS resolution failed entirely
        return false;
    }
    // Reject private, reserved, and loopback ranges
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    return true;
}

/** Sanitize a filename and guarantee it's non-empty and free of path traversal. */
function sanitizeFilename(string $raw): string {
    $name = basename(urldecode($raw));
    $name = preg_replace('/[^\w\-.]/u', '_', $name);
    $name = trim($name, '._');
    if ($name === '' || $name === '.' || $name === '..') {
        $name = 'downloaded_file_' . time() . '.dat';
    }
    return $name;
}

/** Avoid overwriting an existing file by appending a numeric suffix. */
function uniqueFilePath(string $dir, string $filename): string {
    $path = $dir . DIRECTORY_SEPARATOR . $filename;
    if (!file_exists($path)) return $path;

    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    $base = pathinfo($filename, PATHINFO_FILENAME);
    $i = 1;
    do {
        $candidate = $ext !== '' ? "{$base}_{$i}.{$ext}" : "{$base}_{$i}";
        $path = $dir . DIRECTORY_SEPARATOR . $candidate;
        $i++;
    } while (file_exists($path));
    return $path;
}

// --- API Handler ---
if (isset($_GET['action'])) {

    // 1. Download File (GET, but state-changing -> requires CSRF token)
    if ($_GET['action'] === 'download' && isset($_GET['url'])) {
        header('Content-Type: text/event-stream; charset=utf-8');
        header('Cache-Control: no-cache');
        header('X-Accel-Buffering: no'); // Nginx: disable proxy buffering
        header('Connection: keep-alive');
        while (ob_get_level() > 0) { ob_end_clean(); }

        // Session no longer needs to be held open (fixes the list/delete blocking bug)
        $csrfOk = checkCsrf($_GET['csrf'] ?? null);
        session_write_close();

        if (!$csrfOk) {
            sendSSE(['status' => 'error', 'message' => 'درخواست نامعتبر (CSRF). صفحه را رفرش کنید.']);
            exit;
        }

        $url = (string)$_GET['url'];
        if (!isUrlAllowed($url)) {
            sendSSE(['status' => 'error', 'message' => 'آدرس نامعتبر یا غیرمجاز است (فقط http/https و آدرس‌های عمومی مجاز است).']);
            exit;
        }

        $path = parse_url($url, PHP_URL_PATH);
        $filename = sanitizeFilename($path !== null && $path !== '' ? basename($path) : '');
        $filePath = uniqueFilePath(DOWNLOAD_DIR, $filename);

        $fp = fopen($filePath, 'w+b');
        if (!$fp) {
            sendSSE(['status' => 'error', 'message' => 'خطا در ایجاد فایل. مجوزهای پوشه را بررسی کنید.']);
            exit;
        }

        $aborted = false;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FILE => $fp,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            // Empty string enables curl's in-memory cookie engine (handles
            // cookies across redirects, e.g. the classic redirect-loop fix)
            // without ever touching disk, so there's no temp file to clean up.
            CURLOPT_COOKIEFILE => '',
            CURLOPT_AUTOREFERER => true,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
            CURLOPT_SSL_VERIFYPEER => !ALLOW_INSECURE_SSL,
            CURLOPT_SSL_VERIFYHOST => ALLOW_INSECURE_SSL ? 0 : 2,
            CURLOPT_ENCODING => '', // request gzip/deflate to save bandwidth, auto-decoded
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => DOWNLOAD_TIMEOUT,
            CURLOPT_NOPROGRESS => false,
            CURLOPT_BUFFERSIZE => 128 * 1024,
        ]);

        // Abort early via Content-Length header if it already exceeds the limit
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($curl, $header) use (&$aborted) {
            if (MAX_FILE_SIZE > 0 && stripos($header, 'Content-Length:') === 0) {
                $len = (int)trim(substr($header, 15));
                if ($len > MAX_FILE_SIZE) {
                    $aborted = true;
                }
            }
            return strlen($header);
        });

        curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, function ($resource, $download_size, $downloaded, $upload_size, $uploaded) use (&$aborted) {
            static $lastTime = 0;

            if ($aborted || (MAX_FILE_SIZE > 0 && $downloaded > MAX_FILE_SIZE)) {
                $aborted = true;
                return 1; // non-zero return aborts the transfer
            }

            $currentTime = microtime(true);
            if ($currentTime - $lastTime > 0.2 || ($download_size > 0 && $downloaded == $download_size)) {
                if ($download_size > 0) {
                    $percentage = round($downloaded / $download_size * 100, 1);
                    sendSSE([
                        'status' => 'progress',
                        'percent' => $percentage,
                        'downloaded' => formatBytes($downloaded),
                        'total' => formatBytes($download_size),
                    ]);
                } else {
                    sendSSE([
                        'status' => 'progress',
                        'percent' => 'Indeterminate',
                        'downloaded' => formatBytes($downloaded),
                        'total' => '?',
                    ]);
                }
                $lastTime = $currentTime;
            }
            return 0;
        });

        $success = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        fclose($fp);

        if ($aborted) {
            @unlink($filePath);
            sendSSE(['status' => 'error', 'message' => 'دانلود متوقف شد: حجم فایل از حد مجاز (' . formatBytes(MAX_FILE_SIZE) . ') بیشتر است.']);
            exit;
        }

        if ($success && $errno === 0) {
            if ($httpCode >= 200 && $httpCode < 300) {
                sendSSE(['status' => 'done', 'message' => 'دانلود با موفقیت تکمیل شد.']);
            } else {
                $fileSize = @filesize($filePath) ?: 0;
                if ($fileSize > 0 && $fileSize < 10240) {
                    $content = @file_get_contents($filePath, false, null, 0, 10240);
                    if ($content !== false && (stripos($content, '<html') !== false || stripos($content, '403 Forbidden') !== false)) {
                        @unlink($filePath);
                        sendSSE(['status' => 'error', 'message' => "خطا: سرور مبدا اجازه دانلود نداد (HTTP $httpCode). ممکن است لینک منقضی شده باشد."]);
                        exit;
                    }
                }
                sendSSE(['status' => 'done', 'message' => "دانلود شد، اما کد وضعیت HTTP برابر $httpCode بود."]);
            }
        } else {
            @unlink($filePath);
            sendSSE(['status' => 'error', 'message' => 'خطا: ' . ($error !== '' ? $error : 'دانلود ناموفق بود.')]);
        }
        exit;
    }

    // 2. List Files (read-only, no CSRF needed)
    if ($_GET['action'] === 'list') {
        session_write_close();
        $files = @scandir(DOWNLOAD_DIR) ?: [];
        $fileList = [];
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;
            if ($file === '.htaccess' || $file === 'index.html' || $file === basename(__FILE__)) continue;
            if ($file[0] === '.') continue;

            $path = DOWNLOAD_DIR . '/' . $file;
            if (!is_file($path)) continue;

            $fileList[] = [
                'name' => $file,
                'size' => formatBytes(filesize($path)),
                'date' => date('Y-m-d H:i', filemtime($path)),
                'url'  => 'downloads/' . rawurlencode($file),
            ];
        }
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($fileList, JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 3. Delete File (state-changing -> requires CSRF token)
    if ($_GET['action'] === 'delete' && isset($_POST['filename'])) {
        header('Content-Type: application/json; charset=utf-8');
        $csrfOk = checkCsrf($_POST['csrf'] ?? null);
        session_write_close();

        if (!$csrfOk) {
            echo json_encode(['status' => 'error', 'message' => 'درخواست نامعتبر (CSRF).']);
            exit;
        }

        $name = basename((string)$_POST['filename']);
        $fileToDelete = DOWNLOAD_DIR . '/' . $name;
        $realBase = realpath(DOWNLOAD_DIR);
        $realTarget = realpath($fileToDelete);

        if ($realTarget !== false && $realBase !== false && strpos($realTarget, $realBase) === 0 && is_file($realTarget)) {
            unlink($realTarget);
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'فایل یافت نشد.']);
        }
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>پی‌اچ‌پی دانلود اکسپرس</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>📥</text></svg>">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Vazirmatn', sans-serif; }
        .progress-stripe { background-image: linear-gradient(45deg,rgba(255,255,255,.15) 25%,transparent 25%,transparent 50%,rgba(255,255,255,.15) 50%,rgba(255,255,255,.15) 75%,transparent 75%,transparent); background-size: 1rem 1rem; }
        .anim-stripe { animation: progress-bar-stripes 1s linear infinite; }
        @keyframes progress-bar-stripes { from { background-position: 1rem 0; } to { background-position: 0 0; } }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1f2937; }
        ::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #6b7280; }
    </style>
</head>
<body class="bg-gray-900 text-gray-300 min-h-screen flex flex-col items-center py-10 px-4">

    <div class="w-full max-w-4xl space-y-8">

        <div class="bg-gray-800 rounded-2xl shadow-2xl overflow-hidden border border-gray-700">
            <div class="bg-gray-800 p-6 border-b border-gray-700 flex flex-col items-center">
                <h1 class="text-2xl font-bold text-white mb-1">🚀 پی‌اچ‌پی دانلود اکسپرس</h1>
                <p class="text-xs text-gray-500">انتقال سریع فایل بین سرورها (نسخه امن و بهینه)</p>
            </div>

            <div class="p-8">
                <form id="downloadForm" class="space-y-6">
                    <div>
                        <label class="block text-sm font-medium mb-2 text-gray-400">لینک دانلود مستقیم</label>
                        <div class="relative">
                            <input type="url" id="url" required placeholder="https://example.com/file.zip"
                                class="w-full bg-gray-700 border border-gray-600 rounded-xl p-4 pl-12 text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition text-left" dir="ltr">
                            <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                <svg class="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                                </svg>
                            </div>
                        </div>
                    </div>

                    <button type="submit" id="btnSubmit"
                            class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold py-4 rounded-xl shadow-lg transform transition active:scale-95 flex justify-center items-center text-lg">
                        <span>شروع عملیات دانلود</span>
                    </button>
                </form>

                <div id="progressContainer" class="hidden mt-8 p-6 bg-gray-700/30 rounded-xl border border-gray-600 backdrop-blur-sm">
                    <div class="flex justify-between text-sm mb-3 text-white font-medium">
                        <span id="statusText" class="flex items-center gap-2">
                            <span class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
                            در حال دریافت اطلاعات...
                        </span>
                        <span id="percentText">0%</span>
                    </div>
                    <div class="w-full bg-gray-700 rounded-full h-3 overflow-hidden shadow-inner">
                        <div id="progressBar" class="bg-gradient-to-r from-blue-500 to-indigo-400 h-3 rounded-full transition-all duration-200 progress-stripe anim-stripe" style="width: 0%"></div>
                    </div>
                    <div class="flex justify-between text-xs mt-3 text-gray-400 font-mono" dir="ltr">
                        <span id="downloadedSize">0 MB</span>
                        <span id="totalSize">? MB</span>
                    </div>
                </div>
            </div>

            <div class="bg-gray-800/50 p-6 border-t border-gray-700">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <span>📂</span> فایل‌های موجود
                    </h3>
                    <button onclick="loadFiles()" class="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-3 py-1.5 rounded-lg transition border border-gray-600">بروزرسانی لیست</button>
                </div>
                <div class="overflow-x-auto rounded-lg border border-gray-700">
                    <table class="w-full text-sm text-right">
                        <thead class="bg-gray-900/50 text-gray-400 uppercase text-xs">
                            <tr>
                                <th class="p-4">نام فایل</th>
                                <th class="p-4">حجم</th>
                                <th class="p-4 text-center">عملیات</th>
                            </tr>
                        </thead>
                        <tbody id="fileTableBody" class="text-gray-300 divide-y divide-gray-700 bg-gray-800"></tbody>
                    </table>
                    <p id="noFilesMsg" class="text-center py-8 text-gray-500 hidden">هیچ فایلی در سرور موجود نیست.</p>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-gray-800 p-6 rounded-2xl border border-gray-700 shadow-lg hover:border-blue-500/30 transition duration-300">
                <div class="flex items-center gap-3 mb-4">
                    <div class="p-3 bg-blue-500/10 rounded-lg text-blue-400">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                    <h3 class="text-lg font-bold text-white">درباره اسکریپت</h3>
                </div>
                <p class="text-gray-400 text-sm leading-relaxed text-justify">
                    این اسکریپت یک ابزار سبک برای انتقال فایل از سرور دیگر به این سرور است. این نسخه شامل محافظت در برابر CSRF، SSRF، اجرای فایل‌های خطرناک، و پر شدن فضای دیسک است.
                </p>
            </div>

            <div class="bg-gray-800 p-6 rounded-2xl border border-gray-700 shadow-lg hover:border-green-500/30 transition duration-300">
                <div class="flex items-center gap-3 mb-4">
                    <div class="p-3 bg-green-500/10 rounded-lg text-green-400">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                        </svg>
                    </div>
                    <h3 class="text-lg font-bold text-white">نحوه استفاده</h3>
                </div>
                <ul class="text-gray-400 text-sm space-y-3">
                    <li class="flex items-center gap-2"><span class="w-5 h-5 rounded-full bg-gray-700 flex items-center justify-center text-xs text-white">1</span>لینک مستقیم فایل را در کادر بالا وارد کنید.</li>
                    <li class="flex items-center gap-2"><span class="w-5 h-5 rounded-full bg-gray-700 flex items-center justify-center text-xs text-white">2</span>دکمه "شروع عملیات دانلود" را فشار دهید.</li>
                    <li class="flex items-center gap-2"><span class="w-5 h-5 rounded-full bg-gray-700 flex items-center justify-center text-xs text-white">3</span>منتظر بمانید تا نوار پیشرفت به 100% برسد.</li>
                </ul>
            </div>

            <div class="bg-gray-800 p-6 rounded-2xl border border-gray-700 shadow-lg hover:border-purple-500/30 transition duration-300">
                <div class="flex items-center gap-3 mb-4">
                    <div class="p-3 bg-purple-500/10 rounded-lg text-purple-400">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                        </svg>
                    </div>
                    <h3 class="text-lg font-bold text-white">ویژگی‌های فنی</h3>
                </div>
                <div class="grid grid-cols-2 gap-2 text-sm text-gray-400">
                    <div class="bg-gray-900/50 p-2 rounded flex items-center gap-2"><span class="text-green-400">✓</span> محافظت CSRF</div>
                    <div class="bg-gray-900/50 p-2 rounded flex items-center gap-2"><span class="text-green-400">✓</span> محافظت SSRF</div>
                    <div class="bg-gray-900/50 p-2 rounded flex items-center gap-2"><span class="text-green-400">✓</span> بدون قفل شدن سشن</div>
                    <div class="bg-gray-900/50 p-2 rounded flex items-center gap-2"><span class="text-green-400">✓</span> محدودیت حجم فایل</div>
                </div>
            </div>

            <div class="bg-gray-800 p-6 rounded-2xl border border-gray-700 shadow-lg hover:border-red-500/30 transition duration-300">
                <div class="flex items-center gap-3 mb-4">
                    <div class="p-3 bg-red-500/10 rounded-lg text-red-400">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                    </div>
                    <h3 class="text-lg font-bold text-white">قوانین استفاده</h3>
                </div>
                <p class="text-gray-400 text-sm leading-relaxed text-justify">
                    مسئولیت استفاده از این اسکریپت بر عهده کاربر است. لطفاً حتماً یک رمز عبور در بخش تنظیمات (ACCESS_PASSWORD) قرار دهید تا از دسترسی افراد ناشناس جلوگیری شود.
                </p>
            </div>
        </div>

        <div class="bg-gray-800 rounded-xl p-4 text-center text-sm text-gray-500 border border-gray-700">
            نسخه امن‌شده — لطفاً پس از نصب حتماً رمز عبور تنظیم کنید.
        </div>
    </div>

    <script>
        const CSRF_TOKEN = <?php echo json_encode($csrfToken); ?>;

        const form = document.getElementById('downloadForm');
        const progressContainer = document.getElementById('progressContainer');
        const progressBar = document.getElementById('progressBar');
        const percentText = document.getElementById('percentText');
        const statusText = document.getElementById('statusText');
        const downloadedSize = document.getElementById('downloadedSize');
        const totalSize = document.getElementById('totalSize');
        const btnSubmit = document.getElementById('btnSubmit');

        document.addEventListener('DOMContentLoaded', loadFiles);

        function escapeHtml(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }

        function loadFiles() {
            fetch('?action=list')
                .then(r => r.json())
                .then(files => {
                    const tbody = document.getElementById('fileTableBody');
                    tbody.innerHTML = '';
                    document.getElementById('noFilesMsg').classList.toggle('hidden', files.length !== 0);
                    files.forEach(file => {
                        const tr = document.createElement('tr');
                        tr.className = 'hover:bg-gray-700/50 transition group';

                        const tdName = document.createElement('td');
                        tdName.className = 'p-4';
                        tdName.setAttribute('dir', 'ltr');
                        tdName.innerHTML = `<div class="text-white font-medium truncate max-w-[200px] md:max-w-xs"></div><div class="text-xs text-gray-500 md:hidden mt-1"></div>`;
                        tdName.querySelector('div').textContent = file.name;
                        tdName.querySelectorAll('div')[0].title = file.name;
                        tdName.querySelectorAll('div')[1].textContent = file.date;

                        const tdSize = document.createElement('td');
                        tdSize.className = 'p-4 text-gray-400 whitespace-nowrap';
                        tdSize.textContent = file.size;

                        const tdActions = document.createElement('td');
                        tdActions.className = 'p-4 text-center';
                        const wrap = document.createElement('div');
                        wrap.className = 'flex items-center justify-center gap-2';

                        const dl = document.createElement('a');
                        dl.href = file.url;
                        dl.setAttribute('download', '');
                        dl.className = 'p-2 bg-gray-700 text-green-400 hover:bg-green-500 hover:text-white rounded-lg transition';
                        dl.title = 'دانلود';
                        dl.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>';

                        const del = document.createElement('button');
                        del.className = 'p-2 bg-gray-700 text-red-400 hover:bg-red-500 hover:text-white rounded-lg transition';
                        del.title = 'حذف';
                        del.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>';
                        del.onclick = () => deleteFile(file.name);

                        wrap.appendChild(dl);
                        wrap.appendChild(del);
                        tdActions.appendChild(wrap);

                        tr.appendChild(tdName);
                        tr.appendChild(tdSize);
                        tr.appendChild(tdActions);
                        tbody.appendChild(tr);
                    });
                });
        }

        function deleteFile(filename) {
            if (!confirm('آیا از حذف فایل اطمینان دارید؟\nاین عملیات غیرقابل بازگشت است.')) return;

            const formData = new FormData();
            formData.append('filename', filename);
            formData.append('csrf', CSRF_TOKEN);

            fetch('?action=delete', { method: 'POST', body: formData })
                .then(r => r.json())
                .then(res => {
                    if (res.status === 'success') loadFiles();
                    else alert(res.message);
                });
        }

        form.addEventListener('submit', function (e) {
            e.preventDefault();

            const url = document.getElementById('url').value;
            if (!url) return;

            progressContainer.classList.remove('hidden');
            progressBar.style.width = '0%';
            progressBar.classList.remove('animate-pulse');
            progressBar.classList.remove('from-green-500', 'to-green-400', 'from-red-500', 'to-red-400');
            progressBar.classList.add('from-blue-500', 'to-indigo-400');
            percentText.innerText = '0%';
            statusText.innerHTML = '<span class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span> اتصال به سرور...';
            statusText.className = 'text-blue-400 flex items-center gap-2';
            btnSubmit.disabled = true;
            btnSubmit.classList.add('opacity-50', 'cursor-not-allowed', 'grayscale');

            const eventSourceUrl = `?action=download&url=${encodeURIComponent(url)}&csrf=${encodeURIComponent(CSRF_TOKEN)}`;
            const evtSource = new EventSource(eventSourceUrl);

            evtSource.onmessage = function (event) {
                const data = JSON.parse(event.data);

                if (data.status === 'progress') {
                    if (data.percent === 'Indeterminate') {
                        progressBar.style.width = '100%';
                        progressBar.classList.add('animate-pulse');
                        percentText.innerText = '...';
                    } else {
                        progressBar.style.width = data.percent + '%';
                        progressBar.classList.remove('animate-pulse');
                        percentText.innerText = data.percent + '%';
                    }
                    downloadedSize.innerText = data.downloaded;
                    totalSize.innerText = data.total;
                    statusText.innerHTML = '<span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> در حال دانلود...';
                } else if (data.status === 'done') {
                    progressBar.style.width = '100%';
                    progressBar.classList.replace('from-blue-500', 'from-green-500');
                    progressBar.classList.replace('to-indigo-400', 'to-green-400');
                    statusText.innerText = data.message;
                    statusText.className = 'text-green-400 font-bold';
                    evtSource.close();
                    resetFormState();
                    loadFiles();
                } else if (data.status === 'error') {
                    progressBar.classList.replace('from-blue-500', 'from-red-500');
                    progressBar.classList.replace('to-indigo-400', 'to-red-400');
                    statusText.innerText = data.message;
                    statusText.className = 'text-red-400 font-bold';
                    evtSource.close();
                    resetFormState();
                }
            };

            evtSource.onerror = function () {
                statusText.innerText = 'قطع ارتباط با سرور. ممکن است دانلود تمام شده باشد.';
                statusText.className = 'text-yellow-400';
                evtSource.close();
                resetFormState();
                loadFiles();
            };
        });

        function resetFormState() {
            btnSubmit.disabled = false;
            btnSubmit.classList.remove('opacity-50', 'cursor-not-allowed', 'grayscale');
        }
    </script>
</body>
</html>
