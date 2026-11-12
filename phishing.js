const $ = id => document.getElementById(id);
const SHORT = ['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','ow.ly','cutt.ly','rb.gy','shorturl.at'];
const BRANDS = ['paypal','google','facebook','instagram','apple','microsoft','amazon','netflix','whatsapp','mtn','gtbank','opay','paystack','binance'];
const WORDS = ['login','verify','secure','account','update','confirm','password','wallet','bonus','free','gift'];
const BAD_TLD = ['zip','top','xyz','click','tk','ml','gq','cf','icu'];

function analyze(raw) {
  let u;
  try { u = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : 'https://' + raw); }
  catch { return null; }

  const host = u.hostname.toLowerCase();
  const full = u.href.toLowerCase();
  const parts = host.split('.');
  const flags = [];
  const add = (pts, title, why) => flags.push({ pts, title, why });

  if (u.protocol !== 'https:') add(20, 'No HTTPS', 'The connection isn’t encrypted, so data you type can be intercepted.');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(30, 'IP address instead of a domain', 'Real companies use names, not raw IP addresses.');
  if (raw.includes('@')) add(25, '“@” in the link', 'Browsers ignore everything before @, which can hide the real destination.');
  if (host.includes('xn--')) add(25, 'Punycode domain', 'Lookalike characters can imitate a real site’s name.');
  if (parts.length > 4) add(15, 'Too many subdomains', 'Long chains like a.b.c.d.com are used to bury the real domain.');
  if (raw.length > 75) add(10, 'Very long link', 'Long links can hide suspicious parts.');
  if (SHORT.includes(host)) add(20, 'Shortened link', 'You can’t see where it leads until you open it.');
  if ((host.match(/-/g) || []).length >= 3) add(10, 'Many hyphens in the domain', 'Scam domains often chain words with hyphens.');
  if (u.port && !['80', '443'].includes(u.port)) add(10, 'Unusual port ' + u.port, 'Legit sites rarely use custom ports.');
  if (BAD_TLD.includes(parts[parts.length - 1])) add(10, 'Risky domain ending .' + parts[parts.length - 1], 'Cheap endings like this are common in scams.');

  const kw = WORDS.filter(w => full.includes(w));
  if (kw.length) add(Math.min(5 + kw.length * 5, 15), 'Pressure words: ' + kw.join(', '), 'Phishing links push you to log in, verify or claim something.');

  const brand = BRANDS.find(b => host.includes(b) && !new RegExp('(^|\\.)' + b + '\\.(com|org|net|ng)$').test(host));
  if (brand) add(25, 'Imitates “' + brand + '”', 'The brand name is in the link, but the real domain belongs to someone else.');

  const score = Math.min(100, flags.reduce((s, f) => s + f.pts, 0));
  return { flags, score };
}

function show(r) {
  const level = r.score < 20 ? ['Low risk', 'low', 'var(--ok)'] : r.score < 50 ? ['Suspicious', 'med', 'var(--mid)'] : ['High risk: likely phishing', 'high', 'var(--bad)'];
  const v = $('verdict');
  v.textContent = level[0] + ' (' + r.score + '/100)';
  v.className = 'verdict ' + level[1];
  $('bar').style.width = Math.max(r.score, 4) + '%';
  $('bar').style.background = level[2];

  const list = $('flags');
  list.replaceChildren();
  if (!r.flags.length) {
    const li = document.createElement('li');
    li.textContent = 'No common red flags found. Still check the domain spelling yourself.';
    list.append(li);
  }
  r.flags.forEach(f => {
    const li = document.createElement('li');
    const b = document.createElement('b');
    b.textContent = f.title;
    li.append(b, ' — ' + f.why);
    list.append(li);
  });
  $('result').hidden = false;
}

function run() {
  const raw = $('url').value.trim();
  if (!raw) return;
  const r = analyze(raw);
  if (!r) {
    $('verdict').textContent = 'That doesn’t look like a valid link.';
    $('verdict').className = 'verdict med';
    $('bar').style.width = '0';
    $('flags').replaceChildren();
    $('result').hidden = false;
    return;
  }
  show(r);
}

$('check').addEventListener('click', run);
$('url').addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
$('clear').addEventListener('click', () => { $('url').value = ''; $('result').hidden = true; $('url').focus(); });
