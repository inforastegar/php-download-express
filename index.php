<?php
/**
 * PHP Simple Remote Downloader - Minimal & Robust
 * Version: 2.5.0 Pro
 * Refactored for better performance on shared hosts.
 */

// --- Configuration ---
// Access password (leave empty to disable)
define('ACCESS_PASSWORD', ''); 
// Storage directory
define('DOWNLOAD_DIR', 'downloads'); 

// --- Server Settings ---
@ini_set('max_execution_time', 0);
@set_time_limit(0);
@ini_set('memory_limit', '256M');
@ini_set('output_buffering', 0);
@ini_set('zlib.output_compression', 0);

// Create directory if not exists
if (!file_exists(DOWNLOAD_DIR)) {
    mkdir(DOWNLOAD_DIR, 0755, true);
}

// --- Auth ---
session_start();
if (defined('ACCESS_PASSWORD') && ACCESS_PASSWORD !== '') {
    if (isset($_POST['password'])) {
        if ($_POST['password'] === ACCESS_PASSWORD) {
            $_SESSION['logged_in'] = true;
        } else {
            $error = "رمز عبور اشتباه است.";
        }
    }
    if (!isset($_SESSION['logged_in'])) {
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
                <?php if(isset($error)) echo "<p class='text-red-500 mb-2 text-sm'>$error</p>"; ?>
                <input type="password" name="password" class="w-full bg-gray-700 border border-gray-600 rounded p-2 mb-4 text-center focus:outline-none focus:border-blue-500 transition" placeholder="Password">
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
    $units = array('B', 'KB', 'MB', 'GB', 'TB'); 
    $bytes = max($bytes, 0); 
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024)); 
    $pow = min($pow, count($units) - 1); 
    $bytes /= pow(1024, $pow); 
    return round($bytes, $precision) . ' ' . $units[$pow]; 
}

function sendSSE($data) {
    echo "data: " . json_encode($data) . "\n\n";
    if (ob_get_level() > 0) ob_end_flush();
    flush();
}

// --- API Handler ---
if (isset($_GET['action'])) {
    
    // 1. Download File
    if ($_GET['action'] === 'download' && isset($_GET['url'])) {
        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('X-Accel-Buffering: no'); // For Nginx

        $url = $_GET['url'];
        // Auto-detect filename from URL
        $path = parse_url($url, PHP_URL_PATH);
        $customName = basename($path);
        
        // If URL doesn't end with filename, generate one
        if (empty($customName) || $customName === '/') {
            $customName = 'downloaded_file_' . time() . '.dat';
        }

        // Sanitize filename
        $filename = preg_replace('/[^\w\-\.]/', '_', urldecode($customName));
        
        // Ensure extension exists (fallback)
        if (empty(pathinfo($filename, PATHINFO_EXTENSION))) {
             // Try to get header content-type logic here if needed, but for minimal script, keep it simple
        }
        
        $filePath = DOWNLOAD_DIR . DIRECTORY_SEPARATOR . $filename;
        
        $fp = fopen($filePath, 'w+');
        if (!$fp) {
            sendSSE(['status' => 'error', 'message' => 'Error creating file. Check permissions.']);
            exit;
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); 
        curl_setopt($ch, CURLOPT_NOPROGRESS, false);
        
        // Progress Callback
        curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, function($resource, $download_size, $downloaded, $upload_size, $uploaded) {
            static $lastTime = 0;
            $currentTime = microtime(true);
            
            // Throttle updates (200ms)
            if ($currentTime - $lastTime > 0.2 || ($download_size > 0 && $downloaded == $download_size)) {
                if ($download_size > 0) {
                    $percentage = round($downloaded / $download_size * 100, 1);
                    sendSSE([
                        'status' => 'progress', 
                        'percent' => $percentage, 
                        'downloaded' => formatBytes($downloaded), 
                        'total' => formatBytes($download_size)
                    ]);
                } else {
                    // Indeterminate size
                    sendSSE([
                        'status' => 'progress', 
                        'percent' => 'Indeterminate', 
                        'downloaded' => formatBytes($downloaded), 
                        'total' => '?'
                    ]);
                }
                $lastTime = $currentTime;
            }
        });

        $success = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);
        fclose($fp);

        if ($success) {
            sendSSE(['status' => 'done', 'message' => 'دانلود با موفقیت تکمیل شد.']);
        } else {
            sendSSE(['status' => 'error', 'message' => 'Error: ' . $error]);
            @unlink($filePath);
        }
        exit;
    }

    // 2. List Files
    if ($_GET['action'] === 'list') {
        $files = array_diff(scandir(DOWNLOAD_DIR), array('.', '..', '.htaccess', 'index.php'));
        $fileList = [];
        foreach ($files as $file) {
            $path = DOWNLOAD_DIR . '/' . $file;
            $fileList[] = [
                'name' => $file,
                'size' => formatBytes(filesize($path)),
                'date' => date("Y-m-d H:i", filemtime($path)),
                'path' => $path
            ];
        }
        echo json_encode($fileList);
        exit;
    }

    // 3. Delete File
    if ($_GET['action'] === 'delete' && isset($_POST['filename'])) {
        $fileToDelete = DOWNLOAD_DIR . '/' . basename($_POST['filename']);
        if (file_exists($fileToDelete)) {
            unlink($fileToDelete);
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'File not found']);
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
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1f2937; }
        ::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #6b7280; }
    </style>
</head>
<body class="bg-gray-900 text-gray-300 min-h-screen flex flex-col items-center py-10 px-4">

    <!-- Main Container -->
    <div class="w-full max-w-4xl space-y-8">
        
        <!-- Downloader Card -->
        <div class="bg-gray-800 rounded-2xl shadow-2xl overflow-hidden border border-gray-700">
            <!-- Header -->
            <div class="bg-gray-800 p-6 border-b border-gray-700 flex flex-col items-center">
                <h1 class="text-2xl font-bold text-white mb-1">🚀 پی‌اچ‌پی دانلود اکسپرس</h1>
                <p class="text-xs text-gray-500">انتقال سریع فایل بین سرورها</p>
            </div>

            <!-- Form Section -->
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

                <!-- Progress Area -->
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

            <!-- File List Section -->
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
                        <tbody id="fileTableBody" class="text-gray-300 divide-y divide-gray-700 bg-gray-800">
                            <!-- Files will be injected here -->
                        </tbody>
                    </table>
                    <p id="noFilesMsg" class="text-center py-8 text-gray-500 hidden">هیچ فایلی در سرور موجود نیست.</p>
                </div>
            </div>
        </div>

        <!-- Documentation & Guide Section -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            <!-- Intro Card -->
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
                    این اسکریپت یک ابزار سبک و قدرتمند برای انتقال فایل از یک سرور به سرور دیگر (Remote Upload) است. با استفاده از این ابزار می‌توانید بدون مصرف ترافیک اینترنت شخصی، فایل‌های حجیم را مستقیماً روی هاست خود دانلود کنید. این نسخه برای کارکرد بهینه روی هاست‌های اشتراکی بهینه‌سازی شده است.
                </p>
            </div>

            <!-- How to use Card -->
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
                    <li class="flex items-center gap-2">
                        <span class="w-5 h-5 rounded-full bg-gray-700 flex items-center justify-center text-xs text-white">1</span>
                        لینک مستقیم فایل را در کادر بالا وارد کنید.
                    </li>
                    <li class="flex items-center gap-2">
                        <span class="w-5 h-5 rounded-full bg-gray-700 flex items-center justify-center text-xs text-white">2</span>
                        دکمه "شروع عملیات دانلود" را فشار دهید.
                    </li>
                    <li class="flex items-center gap-2">
                        <span class="w-5 h-5 rounded-full bg-gray-700 flex items-center justify-center text-xs text-white">3</span>
                        منتظر بمانید تا نوار پیشرفت به 100% برسد.
                    </li>
                    <li class="flex items-center gap-2">
                        <span class="w-5 h-5 rounded-full bg-gray-700 flex items-center justify-center text-xs text-white">4</span>
                        فایل در پوشه <code class="bg-gray-700 px-1 rounded text-yellow-400 mx-1">downloads</code> ذخیره می‌شود.
                    </li>
                </ul>
            </div>

            <!-- Features Card -->
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
                    <div class="bg-gray-900/50 p-2 rounded flex items-center gap-2">
                        <span class="text-green-400">✓</span> دور زدن Timeout
                    </div>
                    <div class="bg-gray-900/50 p-2 rounded flex items-center gap-2">
                        <span class="text-green-400">✓</span> بهینه برای Shared Host
                    </div>
                    <div class="bg-gray-900/50 p-2 rounded flex items-center gap-2">
                        <span class="text-green-400">✓</span> نام‌گذاری خودکار
                    </div>
                    <div class="bg-gray-900/50 p-2 rounded flex items-center gap-2">
                        <span class="text-green-400">✓</span> نمایش Real-time
                    </div>
                </div>
            </div>

            <!-- Terms Card -->
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
                    مسئولیت استفاده از این اسکریپت بر عهده کاربر است. لطفاً از دانلود فایل‌های دارای کپی‌رایت، مخرب یا خلاف قوانین سرور خودداری کنید. این اسکریپت صرفاً جهت مقاصد آموزشی و مدیریت شخصی فایل‌ها توسعه داده شده است.
                </p>
            </div>

        </div>

        <!-- Footer -->
        <div class="bg-gray-800 rounded-xl p-4 text-center text-sm text-gray-500 border border-gray-700">
            طراحی و توسعه با ❤️ توسط <a href="https://rastegar.info" target="_blank" class="text-blue-400 hover:text-blue-300 transition-colors font-bold">رضا رستگار</a>
        </div>
    </div>

    <script>
        const form = document.getElementById('downloadForm');
        const progressContainer = document.getElementById('progressContainer');
        const progressBar = document.getElementById('progressBar');
        const percentText = document.getElementById('percentText');
        const statusText = document.getElementById('statusText');
        const downloadedSize = document.getElementById('downloadedSize');
        const totalSize = document.getElementById('totalSize');
        const btnSubmit = document.getElementById('btnSubmit');

        // Init
        document.addEventListener('DOMContentLoaded', () => {
            loadFiles();
        });

        // Load files list
        function loadFiles() {
            fetch('?action=list')
                .then(r => r.json())
                .then(files => {
                    const tbody = document.getElementById('fileTableBody');
                    tbody.innerHTML = '';
                    if (files.length === 0) {
                        document.getElementById('noFilesMsg').classList.remove('hidden');
                    } else {
                        document.getElementById('noFilesMsg').classList.add('hidden');
                        files.forEach(file => {
                            const tr = document.createElement('tr');
                            tr.className = 'hover:bg-gray-700/50 transition group';
                            tr.innerHTML = `
                                <td class="p-4" dir="ltr">
                                    <div class="text-white font-medium truncate max-w-[200px] md:max-w-xs" title="${file.name}">${file.name}</div>
                                    <div class="text-xs text-gray-500 md:hidden mt-1">${file.date}</div>
                                </td>
                                <td class="p-4 text-gray-400 whitespace-nowrap">${file.size}</td>
                                <td class="p-4 text-center">
                                    <div class="flex items-center justify-center gap-2">
                                        <a href="${file.path}" download class="p-2 bg-gray-700 text-green-400 hover:bg-green-500 hover:text-white rounded-lg transition" title="دانلود">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                            </svg>
                                        </a>
                                        <button onclick="deleteFile('${file.name}')" class="p-2 bg-gray-700 text-red-400 hover:bg-red-500 hover:text-white rounded-lg transition" title="حذف">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                            </svg>
                                        </button>
                                    </div>
                                </td>
                            `;
                            tbody.appendChild(tr);
                        });
                    }
                });
        }

        // Delete file
        function deleteFile(filename) {
            if(!confirm('آیا از حذف فایل اطمینان دارید؟\nاین عملیات غیرقابل بازگشت است.')) return;
            
            const formData = new FormData();
            formData.append('filename', filename);
            
            fetch('?action=delete', { method: 'POST', body: formData })
                .then(r => r.json())
                .then(res => {
                    if(res.status === 'success') {
                        loadFiles();
                    } else {
                        alert(res.message);
                    }
                });
        }

        // Form Submit
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            
            const url = document.getElementById('url').value;
            if (!url) return;

            // Reset UI
            progressContainer.classList.remove('hidden');
            progressBar.style.width = '0%';
            percentText.innerText = '0%';
            statusText.innerHTML = '<span class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span> اتصال به سرور...';
            statusText.className = 'text-blue-400 flex items-center gap-2';
            btnSubmit.disabled = true;
            btnSubmit.classList.add('opacity-50', 'cursor-not-allowed', 'grayscale');

            // Start SSE (removed name parameter)
            const eventSourceUrl = `?action=download&url=${encodeURIComponent(url)}`;
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
                    
                    // Cleanup
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
            setTimeout(() => {
                // Optional: Hide progress after delay
            }, 5000);
        }
    </script>
</body>
</html>
