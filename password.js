const $ = id => document.getElementById(id);
const COMMON = ['password','123456','12345678','qwerty','abc123','letmein','111111','iloveyou','admin','welcome','monkey','dragon','football','123456789','password1','qwerty123'];
const CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_?';

function assess(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(pool);
  const tips = [];

  if (COMMON.some(c => pw.toLowerCase().includes(c))) { bits = Math.min(bits, 20); tips.push('Contains a very common password.'); }
  if (/(.)\1{2,}/.test(pw)) { bits *= 0.7; tips.push('Avoid repeated characters like “aaa”.'); }
  if (/(abc|bcd|cde|123|234|345|456|567|678|789|qwe|asd|zxc)/i.test(pw)) { bits *= 0.8; tips.push('Avoid predictable sequences like “123” or “qwe”.'); }
  if (pw.length < 12) tips.push('Use at least 12 characters.');
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw)) tips.push('Mix upper and lower case letters.');
  if (!/\d/.test(pw)) tips.push('Add a number.');
  if (!/[^a-zA-Z0-9]/.test(pw)) tips.push('Add a symbol.');
  return { bits, tips };
}

function crackTime(bits) {
  // Assumes an attacker making 10 billion guesses per second on average
  let v = Math.pow(2, bits) / 1e10 / 2;
  if (v < 1) return 'instantly';
  const units = [['seconds', 60], ['minutes', 60], ['hours', 24], ['days', 365], ['years', 100]];
  for (const [name, div] of units) {
    if (v < div) return Math.round(v) + ' ' + name;
    v /= div;
  }
  return 'centuries';
}

function render() {
  const pw = $('pw').value;
  $('leak').textContent = '';
  $('tips').replaceChildren();
  if (!pw) { $('bar').style.width = '0'; $('verdict').textContent = ''; $('crack').textContent = ''; return; }

  const { bits, tips } = assess(pw);
  const lvl = bits < 28 ? ['Weak', 'high', 'var(--bad)'] : bits < 45 ? ['Fair', 'med', 'var(--mid)'] : bits < 60 ? ['Good', 'low', 'var(--ok)'] : ['Strong', 'low', 'var(--ok)'];
  $('bar').style.width = Math.max(6, Math.min(100, bits / 80 * 100)) + '%';
  $('bar').style.background = lvl[2];
  $('verdict').textContent = lvl[0];
  $('verdict').className = 'verdict ' + lvl[1];
  $('crack').textContent = 'Estimated time to crack: ' + crackTime(bits);
  tips.forEach(t => { const li = document.createElement('li'); li.textContent = t; $('tips').append(li); });
}

async function sha1(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function checkLeak() {
  const pw = $('pw').value;
  const out = $('leak');
  if (!pw) { out.textContent = 'Type a password first.'; return; }
  out.textContent = 'Checking…';
  try {
    const h = await sha1(pw);
    const res = await fetch('https://api.pwnedpasswords.com/range/' + h.slice(0, 5));
    if (!res.ok) throw new Error('bad response');
    const line = (await res.text()).split('\n').find(l => l.startsWith(h.slice(5)));
    out.textContent = line
      ? 'Found in ' + Number(line.split(':')[1]).toLocaleString() + ' known leaks. Don’t use this password.'
      : 'Not found in known leaks. That’s good, but it doesn’t make a weak password strong.';
  } catch {
    out.textContent = 'Couldn’t run the check. You need internet, and the page must be opened over https (like your GitHub Pages link).';
  }
}

function rnd(n) {
  const max = Math.floor(2 ** 32 / n) * n;
  let x;
  do { x = crypto.getRandomValues(new Uint32Array(1))[0]; } while (x >= max);
  return x % n;
}

function generate() {
  const n = Number($('len').value);
  $('out').textContent = Array.from({ length: n }, () => CHARS[rnd(CHARS.length)]).join('');
}

$('pw').addEventListener('input', render);
$('breach').addEventListener('click', checkLeak);
$('toggle').addEventListener('click', () => {
  const hidden = $('pw').type === 'password';
  $('pw').type = hidden ? 'text' : 'password';
  $('toggle').textContent = hidden ? 'Hide' : 'Show';
});
$('len').addEventListener('input', () => { $('lenv').textContent = $('len').value; generate(); });
$('gen').addEventListener('click', generate);
$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('out').textContent); $('copy').textContent = 'Copied'; }
  catch { $('copy').textContent = 'Copy failed'; }
  setTimeout(() => { $('copy').textContent = 'Copy'; }, 1500);
});
generate();
