<?php
/**
 * FaceIQ.NET - Contact Page (anti-spam hardened)
 * - Single file: renders form + handles POST
 * - Protections: CSRF, honeypot, timing gate, IP rate limit, URL/keyword checks, header-injection prevention
 *
 * Requirements: PHP 7.4+
 */

declare(strict_types=1);
session_start();

/* ------------------------- Basic security headers ------------------------- */
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none';");

/* ------------------------------ Configuration ----------------------------- */
$SITE_NAME   = 'your-site';
$SITE_URL    = 'https://your-domain.domain';
$TO_EMAIL    = 'you@your-domain.domain';   // TODO: change to your support email
$FROM_EMAIL  = 'you@your-domain.domain';  // TODO: set to an address on your domain (improves deliverability)

/**
 * Rate limit:
 * - Max submissions per IP per window
 */
$RATE_MAX   = 5;
$RATE_WINDOW_SECONDS = 3600; // 1 hour

/**
 * Timing gate:
 * - Must take at least MIN_SECONDS after page load
 * - Must be submitted within MAX_SECONDS
 */
$MIN_SECONDS = 4;
$MAX_SECONDS = 3600;

/* ------------------------------- Helpers --------------------------------- */
function h(string $s): string {
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function client_ip(): string {
  // If you're behind Cloudflare / reverse proxy, adapt this carefully.
  return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function load_rate_state(string $key): array {
  if (!is_file($key)) return ['ts' => time(), 'count' => 0];
  $raw = @file_get_contents($key);
  $json = json_decode((string)$raw, true);
  if (!is_array($json)) return ['ts' => time(), 'count' => 0];
  return $json + ['ts' => time(), 'count' => 0];
}

function save_rate_state(string $key, array $state): void {
  @file_put_contents($key, json_encode($state), LOCK_EX);
}

function too_many_urls(string $text, int $max = 1): bool {
  preg_match_all('~https?://|www\.~i', $text, $m);
  return count($m[0]) > $max;
}

function contains_header_injection(string $s): bool {
  return (bool)preg_match("/[\r\n]/", $s);
}

function strip_invisible(string $s): string {
  // Remove ASCII control chars except \n \r \t
  $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $s) ?? $s;
  // Remove common zero-width chars
  $s = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $s) ?? $s;
  return $s;
}

function looks_spammy(string $message): bool {
  $lower = mb_strtolower($message, 'UTF-8');

  // Common spam cues
  $badKeywords = [
    'bitcoin', 'crypto', 'casino', 'loan', 'viagra', 'cialis',
    'backlink', 'seo service', 'guest post', 'traffic', 'marketing offer',
  ];
  foreach ($badKeywords as $kw) {
    if (str_contains($lower, $kw)) return true;
  }

  // Too many repeated chars / nonsense
  if (preg_match('/(.)\1{12,}/u', $message)) return true;

  // Too many URLs is usually spam
  if (too_many_urls($message, 1)) return true;

  return false;
}

/* ---------------------------- CSRF + timing ------------------------------ */
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
if (empty($_SESSION['contact_form_issued_at'])) {
  $_SESSION['contact_form_issued_at'] = time();
}

/* -------------------------------- Handling ------------------------------- */
$errors = [];
$success = false;

$name = '';
$email = '';
$topic = '';
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Pull values
  $name    = trim((string)($_POST['name'] ?? ''));
  $email   = trim((string)($_POST['email'] ?? ''));
  $topic   = trim((string)($_POST['topic'] ?? ''));
  $message = trim((string)($_POST['message'] ?? ''));

  // Anti-spam fields
  $csrf    = (string)($_POST['csrf'] ?? '');
  $hp      = (string)($_POST['company'] ?? ''); // honeypot (must be empty)
  $issued  = (int)($_POST['issued_at'] ?? 0);
  $js      = (string)($_POST['js_enabled'] ?? '0');

  // Normalize message
  $name    = strip_invisible($name);
  $email   = strip_invisible($email);
  $topic   = strip_invisible($topic);
  $message = strip_invisible($message);

  // CSRF
  if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
    $errors[] = 'Invalid session token. Please refresh and try again.';
  }

  // Honeypot
  if ($hp !== '') {
    $errors[] = 'Spam detected.';
  }

  // Timing gate
  $now = time();
  $age = $now - $issued;
  if ($issued <= 0 || $age < $MIN_SECONDS || $age > $MAX_SECONDS) {
    $errors[] = 'Submission timing invalid. Please try again.';
  }

  // Basic rate limiting per IP
  $ip = client_ip();
  $rateFile = sys_get_temp_dir() . '/dir_contact_' . hash('sha256', $ip) . '.json';
  $state = load_rate_state($rateFile);

  if (($now - (int)$state['ts']) > $RATE_WINDOW_SECONDS) {
    $state = ['ts' => $now, 'count' => 0];
  }
  $state['count'] = (int)$state['count'] + 1;
  save_rate_state($rateFile, $state);

  if ($state['count'] > $RATE_MAX) {
    $errors[] = 'Too many requests. Please try again later.';
  }

  // Validate fields
  if ($name === '' || mb_strlen($name, 'UTF-8') < 2 || mb_strlen($name, 'UTF-8') > 60) {
    $errors[] = 'Please enter your name (2–60 characters).';
  }

  if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Please enter a valid email address.';
  }
  if (contains_header_injection($email) || contains_header_injection($name)) {
    $errors[] = 'Invalid input.';
  }

  if (mb_strlen($topic, 'UTF-8') > 80) {
    $errors[] = 'Topic is too long.';
  }

  if ($message === '' || mb_strlen($message, 'UTF-8') < 10 || mb_strlen($message, 'UTF-8') > 2000) {
    $errors[] = 'Message must be 10–2000 characters.';
  }

  if (looks_spammy($message) || too_many_urls($name . ' ' . $topic, 0)) {
    $errors[] = 'Your message looks like spam. Please remove links/marketing text and try again.';
  }

  // If ok: send mail
  if (!$errors) {
    $safeTopic = $topic !== '' ? $topic : 'Contact message';
    $subject = "[{$SITE_NAME}] {$safeTopic}";

    $body = "New contact submission from {$SITE_NAME}\n\n";
    $body .= "Name: {$name}\n";
    $body .= "Email: {$email}\n";
    $body .= "Topic: {$safeTopic}\n";
    $body .= "IP: {$ip}\n";
    $body .= "User-Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? '') . "\n";
    $body .= "Referrer: " . ($_SERVER['HTTP_REFERER'] ?? '') . "\n";
    $body .= "JS Enabled: {$js}\n";
    $body .= "\nMessage:\n{$message}\n";

    // Safer headers: fixed From + Reply-To user
    $headers = [];
    $headers[] = "MIME-Version: 1.0";
    $headers[] = "Content-Type: text/plain; charset=UTF-8";
    $headers[] = "From: {$SITE_NAME} <{$FROM_EMAIL}>";
    $headers[] = "Reply-To: {$name} <{$email}>";

    // Envelope sender helps deliverability (if allowed by server)
    $params = "-f {$FROM_EMAIL}";

    $sent = @mail($TO_EMAIL, $subject, $body, implode("\r\n", $headers), $params);

    if ($sent) {
      $success = true;
      // rotate tokens to prevent resubmits
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
      $_SESSION['contact_form_issued_at'] = time();

      // Minimal log (optional)
      $logLine = date('c') . " OK ip={$ip} email={$email}\n";
      @file_put_contents(__DIR__ . '/contact.log', $logLine, FILE_APPEND | LOCK_EX);

      // Clear form values
      $name = $email = $topic = $message = '';
    } else {
      $errors[] = 'We could not send your message right now. Please try again later.';
      $logLine = date('c') . " FAIL ip={$ip} email={$email}\n";
      @file_put_contents(__DIR__ . '/contact.log', $logLine, FILE_APPEND | LOCK_EX);
    }
  }
}

// New issued_at for each render
$issuedAt = time();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Contact - <?= h($SITE_NAME) ?></title>
  <meta name="robots" content="noindex, nofollow" />
  <style>
    :root{
      --bg:#0b1020;
      --card:#101a33;
      --text:#e8ecff;
      --muted:#b8c0e6;
      --border:rgba(255,255,255,.12);
      --accent:#6ea8ff;
      --danger:#ff6b6b;
      --ok:#2ee59d;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background: radial-gradient(900px 500px at 10% 10%, rgba(110,168,255,.20), transparent),
                  radial-gradient(800px 500px at 90% 30%, rgba(46,229,157,.12), transparent),
                  var(--bg);
      color:var(--text);
    }
    a{color:var(--accent); text-decoration:none}
    a:hover{text-decoration:underline}
    header{
      border-bottom:1px solid var(--border);
      padding:18px 16px;
    }
    .nav{
      max-width:960px; margin:0 auto;
      display:flex; align-items:center; justify-content:space-between; gap:12px;
    }
    .brand{
      font-weight:700; letter-spacing:.2px;
    }
    .brand span{opacity:.85; font-weight:600}
    main{max-width:960px; margin:0 auto; padding:26px 16px 40px;}
    .card{
      background:linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius:16px;
      padding:18px;
      box-shadow: 0 12px 30px rgba(0,0,0,.25);
    }
    h1{margin:0 0 6px; font-size:28px}
    p{margin:0 0 14px; color:var(--muted); line-height:1.5}
    .grid{
      display:grid;
      grid-template-columns:1fr;
      gap:12px;
    }
    @media (min-width:820px){
      .grid{grid-template-columns: 1fr 1fr;}
      .span2{grid-column:1 / -1;}
    }
    label{display:block; font-size:13px; margin:0 0 6px; color:var(--muted)}
    input, textarea, select{
      width:100%;
      padding:12px 12px;
      border-radius:12px;
      border:1px solid var(--border);
      background:rgba(0,0,0,.25);
      color:var(--text);
      outline:none;
    }
    input:focus, textarea:focus, select:focus{
      border-color: rgba(110,168,255,.6);
      box-shadow: 0 0 0 3px rgba(110,168,255,.15);
    }
    textarea{min-height:140px; resize:vertical}
    .btn{
      display:inline-flex; align-items:center; justify-content:center;
      padding:12px 16px;
      border-radius:12px;
      border:1px solid rgba(110,168,255,.35);
      background:rgba(110,168,255,.18);
      color:var(--text);
      cursor:pointer;
      font-weight:650;
    }
    .btn:hover{background:rgba(110,168,255,.25)}
    .btn:disabled{opacity:.6; cursor:not-allowed}
    .note{font-size:12px; color:var(--muted)}
    .alert{
      border-radius:12px;
      padding:12px;
      border:1px solid var(--border);
      margin: 0 0 14px;
      background: rgba(255,255,255,.03);
    }
    .alert.ok{border-color: rgba(46,229,157,.35); }
    .alert.err{border-color: rgba(255,107,107,.35); }
    .alert ul{margin:8px 0 0 18px; color:var(--muted)}
    footer{
      max-width:960px; margin:18px auto 0; padding:0 16px 30px;
      color:var(--muted); font-size:12px;
      display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;
    }

    /* Honeypot should be invisible to humans */
    .hp-wrap{position:absolute; left:-9999px; width:1px; height:1px; overflow:hidden;}
  </style>
</head>
<body>
<header>
  <div class="nav">
    <div class="brand"><a href="<?= h($SITE_URL) ?>">Your Site <span>.com</span></a></div>
    <div class="note">
      <a href="/terms.html">Terms</a> · <a href="/privacy.html">Privacy</a>
    </div>
  </div>
</header>

<main>
  <div class="card">
    <h1>Contact</h1>
    <p>Send us a message and we’ll get back to you. (No marketing links please — they get blocked.)</p>

    <?php if ($success): ?>
      <div class="alert ok">
        <strong>Message sent.</strong>
        <div class="note">Thanks! If you don’t hear back, check your spam folder or try again later.</div>
      </div>
    <?php endif; ?>

    <?php if ($errors): ?>
      <div class="alert err">
        <strong>Couldn’t send your message.</strong>
        <ul>
          <?php foreach ($errors as $e): ?>
            <li><?= h($e) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>

    <form id="contactForm" method="post" action="" novalidate>
      <!-- CSRF -->
      <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf_token']) ?>" />
      <!-- timing -->
      <input type="hidden" name="issued_at" value="<?= (int)$issuedAt ?>" />
      <!-- JS flag -->
      <input type="hidden" name="js_enabled" id="js_enabled" value="0" />

      <!-- Honeypot -->
      <div class="hp-wrap" aria-hidden="true">
        <label for="company">Company</label>
        <input type="text" name="company" id="company" autocomplete="off" tabindex="-1" />
      </div>

      <div class="grid">
        <div>
          <label for="name">Name</label>
          <input id="name" name="name" autocomplete="name" required maxlength="60" value="<?= h($name) ?>" />
        </div>

        <div>
          <label for="email">Email</label>
          <input id="email" name="email" type="email" autocomplete="email" required maxlength="120" value="<?= h($email) ?>" />
        </div>

        <div class="span2">
          <label for="topic">Topic (optional)</label>
          <input id="topic" name="topic" maxlength="80" value="<?= h($topic) ?>" placeholder="Support, billing, privacy request…" />
        </div>

        <div class="span2">
          <label for="message">Message</label>
          <textarea id="message" name="message" required maxlength="2000" placeholder="Write your message here… (avoid links)"><?= h($message) ?></textarea>
          <div class="note">Tip: messages with links or promotional text are often blocked by the spam filter.</div>
        </div>

        <div class="span2" style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
          <button class="btn" id="submitBtn" type="submit">Send Message</button>
          <span class="note" id="statusNote"></span>
        </div>
      </div>
    </form>
  </div>
</main>

<footer>
  <div>© <?= date('Y') ?> <?= h($SITE_NAME) ?>. All Rights Reserved.</div>
  <div><a href="<?= h($SITE_URL) ?>">Home</a></div>
</footer>

<script>
(function(){
  // mark JS enabled
  document.getElementById('js_enabled').value = '1';

  const form = document.getElementById('contactForm');
  const btn  = document.getElementById('submitBtn');
  const note = document.getElementById('statusNote');

  function hasTooManyLinks(text) {
    const matches = text.match(/https?:\/\/|www\./gi);
    return matches && matches.length > 1;
  }

  form.addEventListener('submit', function(e){
    // Simple client-side checks (server-side is authoritative)
    const name = (document.getElementById('name').value || '').trim();
    const email = (document.getElementById('email').value || '').trim();
    const msg = (document.getElementById('message').value || '').trim();

    if (name.length < 2 || email.length < 5 || msg.length < 10) {
      e.preventDefault();
      note.textContent = 'Please fill in name, email, and a longer message.';
      return;
    }
    if (hasTooManyLinks(msg)) {
      e.preventDefault();
      note.textContent = 'Please remove extra links from the message.';
      return;
    }

    // prevent double-submit
    btn.disabled = true;
    note.textContent = 'Sending…';
  });
})();
</script>
</body>
</html>
