"""
Stage D -- IOC Extraction

Extracts Indicators of Compromise (IOCs) from normalized email data.

Input:
    - all_headers: Stage A normalized headers
    - body_text: plain-text email body
    - body_html: HTML email body
    - attachment_analysis: optional Stage B2 output
    - header_analysis: optional Stage B output

Output:
    {
        "ips": [...],
        "domains": [...],
        "urls": [...],
        "hashes": [...]
    }

Design goals:
    - Offline / no external APIs
    - Fast regex + standard-library parsing
    - No threat-intelligence lookups
    - No maliciousness verdicts
    - Deduplicated and normalized output
    - Can run independently for unit testing
    - Can consume useful normalized indicators from Stages B/B2

Stage D is extraction only. Stage E is responsible for external
threat-intelligence enrichment, and later stages can handle correlation
and risk scoring.

--------------------------------------------------------------------------
NOISE-REDUCTION NOTES (read this if you're wondering why something that
looks like a "domain" or "hash" isn't showing up anymore)
--------------------------------------------------------------------------
A first pass at this module treated "any dotted alphanumeric token" as a
candidate domain and "any bare hex string of the right length" as a
candidate hash. Against a real inbox that produced a lot of garbage:

  * Authentication-Results / DKIM-Signature tag names being mistaken for
    domains ("header.b", "header.i", "smtp.mailfrom", ...) -- these are
    RFC 8601/6376 tag=value labels, not hostnames.
  * Message-ID / campaign-tracking local-parts ("<hash.hash.hash@real
    domain>") being matched as a "domain" because the regex didn't check
    whether the match was immediately followed by "@".
  * CSS selectors, filenames, and other dotted tokens with no real TLD
    ("a.mcnbutton", "image123.png") being accepted as domains because
    nothing checked that the final label was an actual TLD.
  * Internal/loopback/6to4 addresses that show up in Received headers
    (127.0.0.1, Gmail's internal "2002:..." queue identifiers, which are
    syntactically valid IPv6 but non-routable) being reported as "IPs".
  * Tracking parameters embedded in URLs (Mailchimp "c2id=<32 hex
    chars>", cache-busting tokens, etc.) being reported as MD5 hashes,
    because the hash regex scanned raw text/HTML without excluding the
    URLs that had already been extracted.
  * XML/HTML boilerplate ("http://www.w3.org/1999/xhtml", present in
    virtually every HTML email) being reported as if it were an
    attacker-controlled resource.

Fixes applied below, in order of how much noise they remove:
  1. `_KNOWN_TLDS` -- a real (as of this writing) snapshot of the IANA
     root zone. `_is_valid_domain` now requires the final label of a
     domain candidate to be a real TLD. This alone kills most of the
     auth-header-tag, CSS-selector, and filename false positives, since
     none of "b", "i", "s", "from", "mailfrom", "png", "mcnbutton" etc.
     are real TLDs.
  2. `_DOMAIN_RE` no longer matches a candidate that's immediately
     followed by "@" -- that's the signature of an email/Message-ID
     local-part, not a domain.
  3. `_extract_ips` now requires the address to be globally routable
     (reusing Stage B's own `is_public_ip`, rather than re-implementing
     it) -- loopback/private/link-local/6to4-internal addresses are
     dropped.
  4. Hash extraction masks out URLs first, so tracking parameters and
     other URL-embedded hex tokens can't be mistaken for file hashes.
     Degenerate low-entropy hex strings (e.g. all the same repeated
     character) are also dropped.
  5. A small, explicit boilerplate-host allowlist (`_BOILERPLATE_HOSTS`)
     drops a handful of universally-present, non-indicator infrastructure
     hosts (XML namespaces, Office schema URLs) that show up in almost
     every HTML email and are never themselves the observable of
     interest.

None of this is a semantic parse of every header -- it's still
regex-based extraction -- but between the TLD check and the "not
followed by @" rule, the auth-header and Message-ID false positives are
gone without needing bespoke tag=value parsing for
Authentication-Results/DKIM-Signature.

This module also now pulls a little more out of Stage B's *already
computed* results (`header_analysis`) rather than re-deriving things from
raw headers: the DKIM signing domain Stage B parsed out of DKIM-Signature
live-DNS checks, and the canonical From-domain Stage B already resolved.
Stage D still does not duplicate Stage B's detection logic -- it only
reads Stage B's output dict.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit, unquote

from .received_chain import is_public_ip


# ---------------------------------------------------------------------------
# Known TLDs (for domain-candidate validation)
# ---------------------------------------------------------------------------

# A snapshot of IANA's root zone TLD list (data.iana.org/TLD/tlds-alpha-
# by-domain.txt). Used only to reject dotted tokens whose final label
# obviously isn't a real TLD (message-id fragments, CSS class names,
# filenames, auth-header tag names, etc.) -- NOT to validate that a
# domain is registered or resolvable. New TLDs get added occasionally;
# that only means a handful of very new TLDs won't validate until this
# list is refreshed, which is an acceptable trade-off for the noise this
# removes.
_KNOWN_TLDS: frozenset[str] = frozenset({
    'aaa', 'aarp', 'abb', 'abbott', 'abbvie', 'abc', 'able', 'abogado', 'abudhabi', 'ac',
    'academy', 'accenture', 'accountant', 'accountants', 'aco', 'actor', 'ad', 'ads', 'adult',
    'ae', 'aeg', 'aero', 'aetna', 'af', 'afl', 'africa', 'ag', 'agakhan', 'agency', 'ai',
    'aig', 'airbus', 'airforce', 'airtel', 'akdn', 'al', 'alibaba', 'alipay', 'allfinanz',
    'allstate', 'ally', 'alsace', 'alstom', 'am', 'amazon', 'americanexpress',
    'americanfamily', 'amex', 'amfam', 'amica', 'amsterdam', 'analytics', 'android', 'anquan',
    'anz', 'ao', 'aol', 'apartments', 'app', 'apple', 'aq', 'aquarelle', 'ar', 'arab',
    'aramco', 'archi', 'army', 'arpa', 'art', 'arte', 'as', 'asda', 'asia', 'associates', 'at',
    'athleta', 'attorney', 'au', 'auction', 'audi', 'audible', 'audio', 'auspost', 'author',
    'auto', 'autos', 'aw', 'aws', 'ax', 'axa', 'az', 'azure', 'ba', 'baby', 'baidu', 'banamex',
    'band', 'bank', 'bar', 'barcelona', 'barclaycard', 'barclays', 'barefoot', 'bargains',
    'baseball', 'basketball', 'bauhaus', 'bayern', 'bb', 'bbc', 'bbt', 'bbva', 'bcg', 'bcn',
    'bd', 'be', 'beats', 'beauty', 'beer', 'berlin', 'best', 'bestbuy', 'bet', 'bf', 'bg',
    'bh', 'bharti', 'bi', 'bible', 'bid', 'bike', 'bing', 'bingo', 'bio', 'biz', 'bj', 'black',
    'blackfriday', 'blockbuster', 'blog', 'bloomberg', 'blue', 'bm', 'bms', 'bmw', 'bn',
    'bnpparibas', 'bo', 'boats', 'boehringer', 'bofa', 'bom', 'bond', 'boo', 'book', 'booking',
    'bosch', 'bostik', 'boston', 'bot', 'boutique', 'box', 'br', 'bradesco', 'bridgestone',
    'broadway', 'broker', 'brother', 'brussels', 'bs', 'bt', 'build', 'builders', 'business',
    'buy', 'buzz', 'bv', 'bw', 'by', 'bz', 'bzh', 'ca', 'cab', 'cafe', 'cal', 'call',
    'calvinklein', 'cam', 'camera', 'camp', 'canon', 'capetown', 'capital', 'capitalone',
    'car', 'caravan', 'cards', 'care', 'career', 'careers', 'cars', 'casa', 'case', 'cash',
    'casino', 'cat', 'catering', 'catholic', 'cba', 'cbn', 'cbre', 'cc', 'cd', 'center', 'ceo',
    'cern', 'cf', 'cfa', 'cfd', 'cg', 'ch', 'chanel', 'channel', 'charity', 'chase', 'chat',
    'cheap', 'chintai', 'christmas', 'chrome', 'church', 'ci', 'cipriani', 'circle', 'cisco',
    'citadel', 'citi', 'citic', 'city', 'ck', 'cl', 'claims', 'cleaning', 'click', 'clinic',
    'clinique', 'clothing', 'cloud', 'club', 'clubmed', 'cm', 'cn', 'co', 'coach', 'codes',
    'coffee', 'college', 'cologne', 'com', 'commbank', 'community', 'company', 'compare',
    'computer', 'comsec', 'condos', 'construction', 'consulting', 'contact', 'contractors',
    'cooking', 'cool', 'coop', 'corsica', 'country', 'coupon', 'coupons', 'courses', 'cpa',
    'cr', 'credit', 'creditcard', 'creditunion', 'cricket', 'crown', 'crs', 'cruise',
    'cruises', 'cu', 'cuisinella', 'cv', 'cw', 'cx', 'cy', 'cymru', 'cyou', 'cz', 'dad',
    'dance', 'data', 'date', 'dating', 'datsun', 'day', 'dclk', 'dds', 'de', 'deal', 'dealer',
    'deals', 'degree', 'delivery', 'dell', 'deloitte', 'delta', 'democrat', 'dental',
    'dentist', 'desi', 'design', 'dev', 'dhl', 'diamonds', 'diet', 'digital', 'direct',
    'directory', 'discount', 'discover', 'dish', 'diy', 'dj', 'dk', 'dm', 'dnp', 'do', 'docs',
    'doctor', 'dog', 'domains', 'dot', 'download', 'drive', 'dtv', 'dubai', 'dupont', 'durban',
    'dvag', 'dvr', 'dz', 'earth', 'eat', 'ec', 'eco', 'edeka', 'edu', 'education', 'ee', 'eg',
    'email', 'emerck', 'energy', 'engineer', 'engineering', 'enterprises', 'epson',
    'equipment', 'er', 'ericsson', 'erni', 'es', 'esq', 'estate', 'et', 'eu', 'eurovision',
    'eus', 'events', 'exchange', 'expert', 'exposed', 'express', 'extraspace', 'fage', 'fail',
    'fairwinds', 'faith', 'family', 'fan', 'fans', 'farm', 'farmers', 'fashion', 'fast',
    'fedex', 'feedback', 'ferrari', 'ferrero', 'fi', 'fidelity', 'fido', 'film', 'final',
    'finance', 'financial', 'fire', 'firestone', 'firmdale', 'fish', 'fishing', 'fit',
    'fitness', 'fj', 'fk', 'flickr', 'flights', 'flir', 'florist', 'flowers', 'fly', 'fm',
    'fo', 'foo', 'food', 'football', 'ford', 'forex', 'forsale', 'forum', 'foundation', 'fox',
    'fr', 'free', 'fresenius', 'frl', 'frogans', 'frontier', 'ftr', 'fujitsu', 'fun', 'fund',
    'furniture', 'futbol', 'fyi', 'ga', 'gal', 'gallery', 'gallo', 'gallup', 'game', 'games',
    'gap', 'garden', 'gay', 'gb', 'gbiz', 'gd', 'gdn', 'ge', 'gea', 'gent', 'genting',
    'george', 'gf', 'gg', 'ggee', 'gh', 'gi', 'gift', 'gifts', 'gives', 'giving', 'gl',
    'glass', 'gle', 'global', 'globo', 'gm', 'gmail', 'gmbh', 'gmo', 'gmx', 'gn', 'godaddy',
    'gold', 'goldpoint', 'golf', 'goodyear', 'goog', 'google', 'gop', 'got', 'gov', 'gp', 'gq',
    'gr', 'grainger', 'graphics', 'gratis', 'green', 'gripe', 'grocery', 'group', 'gs', 'gt',
    'gu', 'gucci', 'guge', 'guide', 'guitars', 'guru', 'gw', 'gy', 'hair', 'hamburg',
    'hangout', 'haus', 'hbo', 'hdfc', 'hdfcbank', 'health', 'healthcare', 'help', 'helsinki',
    'here', 'hermes', 'hiphop', 'hisamitsu', 'hitachi', 'hiv', 'hk', 'hkt', 'hm', 'hn',
    'hockey', 'holdings', 'holiday', 'homedepot', 'homegoods', 'homes', 'homesense', 'honda',
    'horse', 'hospital', 'host', 'hosting', 'hot', 'hotels', 'hotmail', 'house', 'how', 'hr',
    'hsbc', 'ht', 'hu', 'hughes', 'hyatt', 'hyundai', 'ibm', 'icbc', 'ice', 'icu', 'id', 'ie',
    'ieee', 'ifm', 'ikano', 'il', 'im', 'imamat', 'imdb', 'immo', 'immobilien', 'in', 'inc',
    'industries', 'infiniti', 'info', 'ing', 'ink', 'institute', 'insurance', 'insure', 'int',
    'international', 'intuit', 'investments', 'io', 'ipiranga', 'iq', 'ir', 'irish', 'is',
    'ismaili', 'ist', 'istanbul', 'it', 'itau', 'itv', 'jaguar', 'java', 'jcb', 'je', 'jeep',
    'jetzt', 'jewelry', 'jio', 'jll', 'jm', 'jmp', 'jnj', 'jo', 'jobs', 'joburg', 'jot', 'joy',
    'jp', 'jpmorgan', 'jprs', 'juegos', 'juniper', 'kaufen', 'kddi', 'ke', 'kerryhotels',
    'kerryproperties', 'kfh', 'kg', 'kh', 'ki', 'kia', 'kids', 'kim', 'kindle', 'kitchen',
    'kiwi', 'km', 'kn', 'koeln', 'komatsu', 'kosher', 'kp', 'kpmg', 'kpn', 'kr', 'krd', 'kred',
    'kuokgroup', 'kw', 'ky', 'kyoto', 'kz', 'la', 'lacaixa', 'lamborghini', 'lamer', 'land',
    'landrover', 'lanxess', 'lasalle', 'lat', 'latino', 'latrobe', 'law', 'lawyer', 'lb', 'lc',
    'lds', 'lease', 'leclerc', 'lefrak', 'legal', 'lego', 'lexus', 'lgbt', 'li', 'lidl',
    'life', 'lifeinsurance', 'lifestyle', 'lighting', 'like', 'lilly', 'limited', 'limo',
    'lincoln', 'link', 'live', 'living', 'lk', 'llc', 'llp', 'loan', 'loans', 'locker',
    'locus', 'lol', 'london', 'lotte', 'lotto', 'love', 'lpl', 'lplfinancial', 'lr', 'ls',
    'lt', 'ltd', 'ltda', 'lu', 'lundbeck', 'luxe', 'luxury', 'lv', 'ly', 'ma', 'madrid',
    'maif', 'maison', 'makeup', 'man', 'management', 'mango', 'map', 'market', 'marketing',
    'markets', 'marriott', 'marshalls', 'mattel', 'mba', 'mc', 'mckinsey', 'md', 'me', 'med',
    'media', 'meet', 'melbourne', 'meme', 'memorial', 'men', 'menu', 'merck', 'merckmsd', 'mg',
    'mh', 'miami', 'microsoft', 'mil', 'mini', 'mint', 'mit', 'mitsubishi', 'mk', 'ml', 'mlb',
    'mls', 'mm', 'mma', 'mn', 'mo', 'mobi', 'mobile', 'moda', 'moe', 'moi', 'mom', 'monash',
    'money', 'monster', 'mormon', 'mortgage', 'moscow', 'moto', 'motorcycles', 'mov', 'movie',
    'mp', 'mq', 'mr', 'ms', 'msd', 'mt', 'mtn', 'mtr', 'mu', 'museum', 'music', 'mv', 'mw',
    'mx', 'my', 'mz', 'na', 'nab', 'nagoya', 'name', 'navy', 'nba', 'nc', 'ne', 'nec', 'net',
    'netbank', 'netflix', 'network', 'neustar', 'new', 'news', 'next', 'nextdirect', 'nexus',
    'nf', 'nfl', 'ng', 'ngo', 'nhk', 'ni', 'nico', 'nike', 'nikon', 'ninja', 'nissan',
    'nissay', 'nl', 'no', 'nokia', 'norton', 'now', 'nowruz', 'nowtv', 'np', 'nr', 'nra',
    'nrw', 'ntt', 'nu', 'nyc', 'nz', 'obi', 'observer', 'office', 'okinawa', 'olayan',
    'olayangroup', 'ollo', 'om', 'omega', 'one', 'ong', 'onl', 'online', 'ooo', 'open',
    'oracle', 'orange', 'org', 'organic', 'origins', 'osaka', 'otsuka', 'ott', 'ovh', 'pa',
    'page', 'panasonic', 'paris', 'pars', 'partners', 'parts', 'party', 'pay', 'pccw', 'pe',
    'pet', 'pf', 'pfizer', 'pg', 'ph', 'pharmacy', 'phd', 'philips', 'phone', 'photo',
    'photography', 'photos', 'physio', 'pics', 'pictet', 'pictures', 'pid', 'pin', 'ping',
    'pink', 'pioneer', 'pizza', 'pk', 'pl', 'place', 'play', 'playstation', 'plumbing', 'plus',
    'pm', 'pn', 'pnc', 'pohl', 'poker', 'politie', 'porn', 'post', 'pr', 'praxi', 'press',
    'prime', 'pro', 'prod', 'productions', 'prof', 'progressive', 'promo', 'properties',
    'property', 'protection', 'pru', 'prudential', 'ps', 'pt', 'pub', 'pw', 'pwc', 'py', 'qa',
    'qpon', 'quebec', 'quest', 'racing', 'radio', 're', 'read', 'realestate', 'realtor',
    'realty', 'recipes', 'red', 'redumbrella', 'rehab', 'reise', 'reisen', 'reit', 'reliance',
    'ren', 'rent', 'rentals', 'repair', 'report', 'republican', 'rest', 'restaurant', 'review',
    'reviews', 'rexroth', 'rich', 'the teamrdli', 'ricoh', 'ril', 'rio', 'rip', 'ro', 'rocks',
    'rodeo', 'rogers', 'room', 'rs', 'rsvp', 'ru', 'rugby', 'ruhr', 'run', 'rw', 'rwe',
    'ryukyu', 'sa', 'saarland', 'safe', 'safety', 'sakura', 'sale', 'salon', 'samsclub',
    'samsung', 'sandvik', 'sandvikcoromant', 'sanofi', 'sap', 'sarl', 'sas', 'save', 'saxo',
    'sb', 'sbi', 'sbs', 'sc', 'scb', 'schaeffler', 'schmidt', 'scholarships', 'school',
    'schule', 'schwarz', 'science', 'scot', 'sd', 'se', 'search', 'seat', 'secure', 'security',
    'seek', 'select', 'sener', 'services', 'seven', 'sew', 'sex', 'sexy', 'sfr', 'sg', 'sh',
    'shangrila', 'sharp', 'shell', 'shia', 'shiksha', 'shoes', 'shop', 'shopping', 'shouji',
    'show', 'si', 'silk', 'sina', 'singles', 'site', 'sj', 'sk', 'ski', 'skin', 'sky', 'skype',
    'sl', 'sling', 'sm', 'smart', 'smile', 'sn', 'sncf', 'so', 'soccer', 'social', 'softbank',
    'software', 'sohu', 'solar', 'solutions', 'song', 'sony', 'soy', 'spa', 'space', 'sport',
    'spot', 'sr', 'srl', 'ss', 'st', 'stada', 'staples', 'star', 'statebank', 'statefarm',
    'stc', 'stcgroup', 'stockholm', 'storage', 'store', 'stream', 'studio', 'study', 'style',
    'su', 'sucks', 'supplies', 'supply', 'support', 'surf', 'surgery', 'suzuki', 'sv',
    'swatch', 'swiss', 'sx', 'sy', 'sydney', 'systems', 'sz', 'tab', 'taipei', 'talk',
    'taobao', 'target', 'tatamotors', 'tatar', 'tattoo', 'tax', 'taxi', 'tc', 'tci', 'td',
    'tdk', 'team', 'tech', 'technology', 'tel', 'temasek', 'tennis', 'teva', 'tf', 'tg', 'th',
    'thd', 'theater', 'theatre', 'tiaa', 'tickets', 'tienda', 'tips', 'tires', 'tirol', 'tj',
    'tjmaxx', 'tjx', 'tk', 'tkmaxx', 'tl', 'tm', 'tmall', 'tn', 'to', 'today', 'tokyo',
    'tools', 'top', 'toray', 'toshiba', 'total', 'tours', 'town', 'toyota', 'toys', 'tr',
    'trade', 'trading', 'training', 'travel', 'travelers', 'travelersinsurance', 'trust',
    'trv', 'tt', 'tube', 'tui', 'tunes', 'tushu', 'tv', 'tvs', 'tw', 'tz', 'ua', 'ubank',
    'ubs', 'ug', 'uk', 'unicom', 'university', 'uno', 'uol', 'ups', 'us', 'uy', 'uz', 'va',
    'vacations', 'vana', 'vanguard', 'vc', 've', 'vegas', 'ventures', 'verisign',
    'versicherung', 'vet', 'vg', 'vi', 'viajes', 'video', 'vig', 'viking', 'villas', 'vin',
    'vip', 'virgin', 'visa', 'vision', 'viva', 'vivo', 'vlaanderen', 'vn', 'vodka', 'volvo',
    'vote', 'voting', 'voto', 'voyage', 'vu', 'wales', 'walmart', 'walter', 'wang', 'wanggou',
    'watch', 'watches', 'weather', 'weatherchannel', 'web', 'webcam', 'weber', 'website',
    'wed', 'wedding', 'weibo', 'weir', 'wf', 'whoswho', 'wien', 'wiki', 'williamhill', 'win',
    'windows', 'wine', 'winners', 'wme', 'woodside', 'work', 'works', 'world', 'wow', 'ws',
    'wtc', 'wtf', 'xbox', 'xerox', 'xihuan', 'xin', 'xn--11b4c3d', 'xn--1ck2e1b',
    'xn--1qqw23a', 'xn--2scrj9c', 'xn--30rr7y', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e',
    'xn--3hcrj9c', 'xn--3pxu8k', 'xn--42c2d9a', 'xn--45br5cyl', 'xn--45brj9c', 'xn--45q11c',
    'xn--4dbrk0ce', 'xn--4gbrim', 'xn--54b7fta0cc', 'xn--55qw42g', 'xn--55qx5d',
    'xn--5su34j936bgsg', 'xn--5tzm5g', 'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80adxhks',
    'xn--80ao21a', 'xn--80aqecdr1a', 'xn--80asehdb', 'xn--80aswg', 'xn--8y0a063a',
    'xn--90a3ac', 'xn--90ae', 'xn--90ais', 'xn--9dbq2a', 'xn--9et52u', 'xn--9krt00a',
    'xn--b4w605ferd', 'xn--bck1b9a5dre4c', 'xn--c1avg', 'xn--c2br7g', 'xn--cck2b3b',
    'xn--cckwcxetd', 'xn--cg4bki', 'xn--clchc0ea0b2g2a9gcd', 'xn--czr694b', 'xn--czrs0t',
    'xn--czru2d', 'xn--d1acj3b', 'xn--d1alf', 'xn--e1a4c', 'xn--eckvdtc9d', 'xn--efvy88h',
    'xn--fct429k', 'xn--fhbei', 'xn--fiq228c5hs', 'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s',
    'xn--fjq720a', 'xn--flw351e', 'xn--fpcrj9c3d', 'xn--fzc2c9e2c', 'xn--fzys8d69uvgm',
    'xn--g2xx48c', 'xn--gckr3f0f', 'xn--gecrj9c', 'xn--gk3at1e', 'xn--h2breg3eve',
    'xn--h2brj9c', 'xn--h2brj9c8c', 'xn--hxt814e', 'xn--i1b6b1a6a2e', 'xn--imr513n',
    'xn--io0a7i', 'xn--j1aef', 'xn--j1amh', 'xn--j6w193g', 'xn--jlq480n2rg', 'xn--jvr189m',
    'xn--kcrx77d1x4a', 'xn--kprw13d', 'xn--kpry57d', 'xn--kput3i', 'xn--l1acc',
    'xn--lgbbat1ad8j', 'xn--mgb9awbf', 'xn--mgba3a3ejt', 'xn--mgba3a4f16a', 'xn--mgba7c0bbn0a',
    'xn--mgbaam7a8h', 'xn--mgbab2bd', 'xn--mgbah1a3hjkrd', 'xn--mgbai9azgqp6j',
    'xn--mgbayh7gpa', 'xn--mgbbh1a', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgbca7dzdo',
    'xn--mgbcpq6gpa1a', 'xn--mgberp4a5d4ar', 'xn--mgbgu82a', 'xn--mgbi4ecexp', 'xn--mgbpl2fh',
    'xn--mgbt3dhd', 'xn--mgbtx2b', 'xn--mgbx4cd0ab', 'xn--mix891f', 'xn--mk1bu44c',
    'xn--mxtq1m', 'xn--ngbc5azd', 'xn--ngbe9e0a', 'xn--ngbrx', 'xn--node', 'xn--nqv7f',
    'xn--nqv7fs00ema', 'xn--nyqy26a', 'xn--o3cw4h', 'xn--ogbpf8fl', 'xn--otu796d', 'xn--p1acf',
    'xn--p1ai', 'xn--pgbs0dh', 'xn--pssy2u', 'xn--q7ce6a', 'xn--q9jyb4c', 'xn--qcka1pmc',
    'xn--qxa6a', 'xn--qxam', 'xn--rhqv96g', 'xn--rovu88b', 'xn--rvc1e0am3e', 'xn--s9brj9c',
    'xn--ses554g', 'xn--t60b56a', 'xn--tckwe', 'xn--tiq49xqyj', 'xn--unup4y',
    'xn--vermgensberater-ctb', 'xn--vermgensberatung-pwb', 'xn--vhquv', 'xn--vuq861b',
    'xn--w4r85el8fhu5dnra', 'xn--w4rs40l', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xhq521b',
    'xn--xkc2al3hye2a', 'xn--xkc2dl3a5ee0h', 'xn--y9a3aq', 'xn--yfro4i67o', 'xn--ygbi2ammx',
    'xn--zfr164b', 'xxx', 'xyz', 'yachts', 'yahoo', 'yamaxun', 'yandex', 'ye', 'yodobashi',
    'yoga', 'yokohama', 'you', 'youtube', 'yt', 'yun', 'za', 'zappos', 'zara', 'zero', 'zip',
    'zm', 'zone', 'zuerich', 'zw',
})


# A very small, explicit set of universally-present, non-indicator
# infrastructure hosts that show up in ordinary HTML/XML boilerplate
# (namespaces, schema references) rather than as anything
# attacker-controlled. Kept deliberately tiny -- this is NOT a general
# "trusted domains" allowlist, just a targeted fix for boilerplate that
# would otherwise show up in the IOC list of almost every HTML email.
_BOILERPLATE_HOSTS: frozenset[str] = frozenset({
    "w3.org",
    "www.w3.org",
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "purl.org",
})


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# URLs explicitly present in an email. We intentionally support HTTP(S)
# rather than trying to classify every URI scheme as an IOC.
_URL_RE = re.compile(
    r"(?i)\bhttps?://[^\s<>'\"`\]\[(){}]+"
)

# Common defanged URL form used in security reports / suspicious emails.
# Example: hxxps://evil[.]example/login
_DEFANGED_URL_RE = re.compile(
    r"(?i)\bhxxps?://[^\s<>'\"`\]\[(){}]+"
)

# IPv4 candidates. Validation is performed with ipaddress.ip_address()
# afterwards, so values such as 999.999.999.999 are rejected.
_IPV4_RE = re.compile(
    r"(?<![\d.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\d.])"
)

# IPv6 candidates. The regex is intentionally permissive; ipaddress
# performs the actual validation.
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:.]+"
    r"(?![0-9A-Fa-f:])"
)

# MD5 / SHA-1 / SHA-256. Boundaries prevent extracting a 32-character
# substring from a longer hexadecimal token.
_HASH_RE = re.compile(
    r"(?i)(?<![0-9a-f])"
    r"(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})"
    r"(?![0-9a-f])"
)

# A deliberately conservative domain pattern:
#   example.com
#   sub.example.co.uk
#   xn--example-9za.com
#
# We require at least one dot because single words such as "localhost",
# "invoice", etc. are usually not useful domain IOCs.
#
# The trailing lookahead also excludes "@" (in addition to \w and "-").
# Without that, a dotted token that's actually the LOCAL PART of an email
# address or Message-ID (e.g. "<track.id.hash@real-domain.com>") gets
# matched as if it were a standalone domain, because nothing previously
# checked whether the very next character was "@". Real email/Message-ID
# domains are still captured correctly via _EMAIL_RE elsewhere.
_DOMAIN_RE = re.compile(
    r"(?i)(?<![@\w-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?![\w@-])"
)

# Email addresses. Used to derive their domains without treating the
# complete address as a domain IOC.
_EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z](?:[A-Z0-9-]{0,61}[A-Z0-9])?\b"
)

# URL/domain punctuation that commonly surrounds an indicator in prose.
_TRAILING_PUNCTUATION = ".,;:!?)]}>\"'`"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _clean_indicator(value: Any) -> str:
    """Convert an arbitrary value to a trimmed string."""
    if value is None:
        return ""
    return str(value).strip()


def _iter_strings(value: Any) -> Iterable[str]:
    """
    Yield strings from common header/container shapes.

    Stage A may represent a header as a string, list, tuple, or a small
    nested structure depending on parser/version. This keeps Stage D
    tolerant without depending on a particular parser implementation.
    """
    if value is None:
        return

    if isinstance(value, str):
        yield value
        return

    if isinstance(value, dict):
        for nested_value in value.values():
            yield from _iter_strings(nested_value)
        return

    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_strings(item)
        return

    yield str(value)


def _strip_wrapping_punctuation(value: str) -> str:
    """Remove punctuation commonly attached to an IOC in prose."""
    return value.strip().strip(_TRAILING_PUNCTUATION).strip()


def _defang(value: str) -> str:
    """
    Normalize common security-report/email defanging.

    Examples:
        hxxp://evil[.]example -> http://evil.example
        evil[.]example         -> evil.example
        evil(.)example         -> evil.example
        evil[dot]example       -> evil.example

    This is used internally for extraction/normalization. The returned
    IOC is the usable normalized form, which is what later TI stages want.
    """
    normalized = value.strip()

    normalized = re.sub(r"(?i)^hxxps://", "https://", normalized)
    normalized = re.sub(r"(?i)^hxxp://", "http://", normalized)

    normalized = normalized.replace("[.]", ".")
    normalized = normalized.replace("(.)", ".")
    normalized = re.sub(r"(?i)\[\s*dot\s*\]", ".", normalized)
    normalized = re.sub(r"(?i)\(\s*dot\s*\)", ".", normalized)

    return normalized


def _is_valid_ip(value: str) -> bool:
    """Return True only for a syntactically valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_routable_ip(value: str) -> bool:
    """
    Return True only for a syntactically valid, globally-routable IP.

    Reuses Stage B's own `is_public_ip` (received_chain.py) rather than
    re-implementing the private/loopback/link-local/reserved checks --
    this is the same notion of "actually meaningful as an IOC" that Stage
    B already relies on when picking the originating IP out of a Received
    chain. Without this, loopback hops (127.0.0.1) and non-routable
    addresses that show up in relay headers (e.g. 6to4/internal-use
    IPv6 identifiers some providers stamp into Received lines) get
    reported as if they were observed external IPs.
    """
    return is_public_ip(value)


def _is_valid_domain(value: str) -> bool:
    """
    Apply conservative domain validation.

    We intentionally do not perform DNS resolution. A domain IOC does not
    need to resolve right now to be worth extracting -- but its final
    label DOES need to be a real TLD (see `_KNOWN_TLDS`). That single
    check eliminates the large majority of false positives that come
    from treating arbitrary dotted tokens (filenames, CSS selectors,
    Authentication-Results/DKIM-Signature tag names, Message-ID
    fragments) as if they were domains.
    """
    domain = value.strip().rstrip(".").lower()

    if not domain or len(domain) > 253:
        return False

    if "." not in domain:
        return False

    # Reject things that are clearly IP addresses.
    if _is_valid_ip(domain):
        return False

    labels = domain.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False

    # RFC-style hostname labels: letters/digits/hyphens, no leading or
    # trailing hyphen. Punycode labels (xn--) naturally pass.
    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label, flags=re.IGNORECASE):
            return False

    # Avoid treating a bare numeric dotted value as a domain.
    if all(label.isdigit() for label in labels):
        return False

    # The final label must be a real, currently-delegated TLD. This is
    # the main noise-reduction check: rejects filename extensions,
    # auth-header tag names, CSS class fragments, Message-ID remnants,
    # etc. that happen to be dot-separated but aren't actually a domain.
    if labels[-1] not in _KNOWN_TLDS:
        return False

    return True


def _extract_domain_from_email(value: str) -> Optional[str]:
    """Return the domain part of a normal/formatted email address."""
    # parseaddr would also work, but the regex approach lets us extract
    # multiple addresses from arbitrary header strings.
    match = _EMAIL_RE.search(value)
    if not match:
        return None

    address = match.group(0)
    domain = address.rsplit("@", 1)[1].lower()
    return domain if _is_valid_domain(domain) else None


def _domain_from_url(url: str) -> Optional[str]:
    """Extract and validate the hostname from an HTTP(S) URL."""
    normalized = _defang(url)

    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname
    except ValueError:
        return None

    if not hostname:
        return None

    hostname = hostname.rstrip(".").lower()

    # URL may contain an IP address; it belongs in ips, not domains.
    if _is_valid_ip(hostname):
        return None

    return hostname if _is_valid_domain(hostname) else None


# ---------------------------------------------------------------------------
# HTML extraction
# ---------------------------------------------------------------------------

class _HTMLIOCParser(HTMLParser):
    """
    Pull URL-bearing attributes from HTML.

    We specifically inspect href/src/action/poster/data rather than trying
    to interpret the HTML as a browser would.
    """

    URL_ATTRIBUTES = {
        "href",
        "src",
        "action",
        "poster",
        "data",
        "formaction",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        for name, value in attrs:
            if name.lower() in self.URL_ATTRIBUTES and value:
                self.urls.append(value)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, Optional[str]]],
    ) -> None:
        self.handle_starttag(tag, attrs)


def _extract_html_attribute_values(body_html: str) -> list[str]:
    """Safely extract URL-bearing attribute values from HTML."""
    if not body_html:
        return []

    parser = _HTMLIOCParser()

    try:
        parser.feed(body_html)
        parser.close()
    except Exception:
        # Malformed HTML should never crash Stage D. Regex extraction over
        # the raw HTML still happens elsewhere.
        return parser.urls

    return parser.urls


# ---------------------------------------------------------------------------
# Individual IOC extractors
# ---------------------------------------------------------------------------

def _extract_urls(text: str) -> set[str]:
    """Extract HTTP(S) and common defanged HTTP(S) URLs."""
    urls: set[str] = set()

    if not text:
        return urls

    for regex in (_URL_RE, _DEFANGED_URL_RE):
        for match in regex.finditer(text):
            raw = _strip_wrapping_punctuation(match.group(0))
            normalized = _defang(raw)

            # Validate that it really is an HTTP(S) URL with a hostname.
            try:
                parsed = urlsplit(normalized)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    continue
            except ValueError:
                continue

            urls.add(normalized)

    return urls


def _extract_ips(text: str) -> set[str]:
    """Extract globally-routable IPv4 and IPv6 addresses from arbitrary text.

    Loopback/private/link-local/reserved/non-routable addresses (e.g. a
    127.0.0.1 relay hop, or 6to4/internal-use IPv6 identifiers some mail
    providers stamp into Received headers) are intentionally excluded --
    they're never externally-actionable indicators.
    """
    ips: set[str] = set()

    if not text:
        return ips

    for match in _IPV4_RE.finditer(text):
        candidate = match.group(0)
        if _is_routable_ip(candidate):
            ips.add(candidate)

    for match in _IPV6_RE.finditer(text):
        candidate = match.group(0)
        if _is_routable_ip(candidate):
            ips.add(candidate.lower())

    return ips


def _mask_urls(text: str) -> str:
    """
    Blank out URL spans (plain and defanged) before hash-scanning.

    Query-string/path tokens inside URLs are a major source of false
    "hash" hits -- tracking/campaign IDs, cache-busting values, session
    tokens -- that happen to be 32/40/64 hex characters but aren't file
    hashes at all (e.g. a Mailchimp "c2id=<32 hex chars>" parameter).
    Masking URLs out before running the hash regex removes this whole
    class of false positive without needing to guess which specific
    tracking systems are in use.
    """
    if not text:
        return text

    masked = _URL_RE.sub(" ", text)
    masked = _DEFANGED_URL_RE.sub(" ", masked)
    return masked


def _mask_emails(text: str) -> str:
    """
    Blank out email-address spans before the standalone domain regex runs.

    Without this, an email address like "user@yahoo.co.kr" is correctly
    captured as a domain by the dedicated email-address path in
    _extract_domains(), but the standalone _DOMAIN_RE scan *also* re-scans
    the same text and can match a trailing fragment of the same domain on
    its own (e.g. "co.kr" out of "yahoo.co.kr") as a spurious extra
    "domain". Masking already-claimed email spans first removes this
    duplicate/garbage entry without touching the real capture.
    """
    if not text:
        return text
    return _EMAIL_RE.sub(" ", text)


def _is_low_entropy_hex(candidate: str) -> bool:
    """
    Reject degenerate hex strings that are almost certainly not a real
    hash (e.g. all zeros, or only 2-3 distinct characters repeated) --
    placeholder/test values, not something worth surfacing as an IOC.
    """
    return len(set(candidate.lower())) <= 3


def _extract_hashes(text: str) -> set[str]:
    """Extract MD5, SHA-1, and SHA-256 hexadecimal hashes.

    URLs are masked out first (see `_mask_urls`) so hex-looking tracking
    parameters embedded in query strings aren't reported as file hashes.
    """
    if not text:
        return set()

    masked = _mask_urls(text)

    hashes: set[str] = set()
    for match in _HASH_RE.finditer(masked):
        candidate = match.group(0).lower()
        if _is_low_entropy_hex(candidate):
            continue
        hashes.add(candidate)

    return hashes


def _strip_style_and_script_blocks(html: str) -> str:
    """
    Remove <style>...</style> and <script>...</script> content before any
    other extraction runs on HTML body text.

    CSS selectors can accidentally look exactly like a real domain to the
    standalone domain regex -- e.g. "a.mobile{...}" structurally matches
    "a.mobile", and .mobile is a real, active gTLD (Dish DBS Corporation),
    so it isn't even filtered out by the TLD-validity check. Rather than
    trying to special-case every CSS selector pattern that happens to
    collide with a real TLD, it's simpler and more robust to just not feed
    <style>/<script> content into the IOC extractors at all -- neither
    block type is a place real indicators legitimately appear.
    """
    if not html:
        return html
    html = re.sub(r"<style\b[^>]*>.*?</style>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"<script\b[^>]*>.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    return html


def _fully_unquote(text: str, max_passes: int = 5) -> str:
    """
    Repeatedly percent-decode text until it stops changing (or max_passes
    is hit). A single unquote() pass isn't always enough: URLs embedded as
    a parameter value inside another URL are sometimes encoded twice --
    e.g. an unsubscribe link's own querystring re-appearing, re-encoded,
    inside a "subject=" parameter of a second copy of the same link. One
    pass turns "...%2540gmail.com" into "...%40gmail.com" -- still
    encoded, no "@" revealed yet -- leaving a bare "40gmail.com" for
    _DOMAIN_RE to match as a bogus domain once the real domain is masked
    out from underneath it. Looping until stable resolves any depth of
    nesting actually present, and the max_passes cap keeps this bounded
    even against adversarial input designed to loop forever.
    """
    for _ in range(max_passes):
        unquoted = unquote(text)
        if unquoted == text:
            break
        text = unquoted
    return text


def _extract_domains(text: str) -> set[str]:
    """
    Extract standalone domains and domains contained in email addresses.

    URL domains are also added separately by extract_iocs(), which means
    callers can get the domain even when it appears only inside a URL.
    """
    domains: set[str] = set()

    if not text:
        return domains

    # Domains appearing as email addresses.
    for match in _EMAIL_RE.finditer(text):
        domain = match.group(0).rsplit("@", 1)[1].lower()
        if _is_valid_domain(domain):
            domains.add(domain)

    # Standalone domains.
    #
    # URL-percent-encoding is unescaped FIRST: click-tracking/redirect URLs
    # (AWS SES, Mailchimp, etc.) commonly embed their real destination as
    # "...%2Fapi.example.com%2Fpath..." -- if left encoded, "%2F" sits
    # directly against the following hostname with no real separator, so
    # the regex swallows the literal characters "2f" onto the front of the
    # real domain, producing garbage like "2fapi.example.com" instead of
    # (or alongside) "api.example.com". Unescaping restores the actual "/"
    # separator so only the real hostname matches. This is done in a loop
    # (_fully_unquote) rather than a single pass, since a URL embedded as
    # a parameter value inside another URL can be encoded more than once.
    #
    # Email masking runs AFTER unquoting, not before. A query-string value
    # like "...&email=user%40gmail.com..." doesn't look like an email
    # until it's unquoted to "...user@gmail.com..." -- masking emails on
    # the still-encoded text can't catch it, and the regex then matches a
    # garbage fragment like "40gmail.com" off the revealed "@". Masking
    # after unquoting catches both this case and plain unencoded emails
    # (e.g. "<user@yahoo.co.kr>" in a raw header, unaffected by unquoting
    # either way), so a real domain already captured above via the
    # email-address path doesn't also produce a spurious duplicate
    # fragment when the standalone regex re-scans the same text.
    text_for_domains = _fully_unquote(text)

    text_for_domains = _mask_emails(text_for_domains)
    defanged_text = _defang(text_for_domains)
    for match in _DOMAIN_RE.finditer(defanged_text):
        domain = _strip_wrapping_punctuation(match.group(0)).lower()

        # Don't return a domain if this candidate is actually an IP.
        if _is_valid_domain(domain):
            domains.add(domain)

    return domains


# ---------------------------------------------------------------------------
# Header / Stage B / Stage B2 integration
# ---------------------------------------------------------------------------

def _extract_from_headers(all_headers: Any) -> tuple[set[str], set[str], set[str]]:
    """
    Extract indicators directly from Stage A's all_headers.

    Returns:
        (ips, domains, urls)

    Header values are treated as raw text. This deliberately complements,
    rather than replaces, Stage B's deeper Received-chain/authentication
    analysis. Note that Authentication-Results/DKIM-Signature/Received-SPF
    headers are still scanned here (for IPs and URLs, which are low-risk),
    but any domain-shaped tokens that slip through are filtered out by
    `_is_valid_domain`'s TLD check -- their tag names ("header.b",
    "smtp.mailfrom", etc.) don't end in a real TLD.
    """
    ips: set[str] = set()
    domains: set[str] = set()
    urls: set[str] = set()

    for header_value in _iter_strings(all_headers):
        ips.update(_extract_ips(header_value))
        urls.update(_extract_urls(header_value))
        domains.update(_extract_domains(header_value))

    return ips, domains, urls


def _extract_from_header_analysis(header_analysis: Any) -> tuple[set[str], set[str]]:
    """
    Consume useful normalized indicators from Stage B.

    We use explicit fields Stage B has already computed/validated:
        - originating_ip           (Received-chain walk, already
                                     restricted to a public IP)
        - sender_email / reply_to  (parsed From/Reply-To addresses)
        - domain_analysis.domain   (Stage B's own canonical From-domain,
                                     kept as a safety net in case
                                     sender_email is missing/malformed)
        - auth_details.dkim.details.signing_domain
                                    (the DKIM `d=` domain Stage B already
                                     parsed out during its live-DNS DKIM
                                     check -- reusing this is preferable
                                     to re-regexing the raw DKIM-Signature
                                     header ourselves)

    No Stage B detection logic is duplicated here -- only its output dict
    is read.
    """
    ips: set[str] = set()
    domains: set[str] = set()

    if not isinstance(header_analysis, dict):
        return ips, domains

    originating_ip = header_analysis.get("originating_ip")
    if originating_ip and _is_routable_ip(str(originating_ip).strip()):
        ips.add(str(originating_ip).strip().lower())

    for field in ("sender_email", "reply_to"):
        value = header_analysis.get(field)
        if value:
            domain = _extract_domain_from_email(str(value))
            if domain:
                domains.add(domain)

    domain_analysis = header_analysis.get("domain_analysis")
    if isinstance(domain_analysis, dict):
        canonical_domain = domain_analysis.get("domain")
        if canonical_domain:
            candidate = str(canonical_domain).strip().lower()
            if _is_valid_domain(candidate):
                domains.add(candidate)

    auth_details = header_analysis.get("auth_details")
    if isinstance(auth_details, dict):
        dkim_details = (auth_details.get("dkim") or {}).get("details")
        if isinstance(dkim_details, dict):
            signing_domain = dkim_details.get("signing_domain")
            if signing_domain:
                candidate = str(signing_domain).strip().lower()
                if _is_valid_domain(candidate):
                    domains.add(candidate)

    return ips, domains


def _extract_from_attachment_analysis(attachment_analysis: Any) -> set[str]:
    """
    Consume SHA-256 values already calculated by Stage B2.

    D does not recalculate attachment hashes; B2 already owns that work.
    """
    hashes: set[str] = set()

    if not isinstance(attachment_analysis, dict):
        return hashes

    attachments = attachment_analysis.get("attachments", [])
    if not isinstance(attachments, list):
        return hashes

    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue

        sha256 = attachment.get("sha256")
        if not sha256:
            continue

        candidate = str(sha256).strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", candidate):
            hashes.add(candidate)

    return hashes


def _drop_boilerplate(domains: set[str], urls: set[str]) -> tuple[set[str], set[str]]:
    """Remove the small set of universally-present boilerplate hosts
    (see `_BOILERPLATE_HOSTS`) from the final domains/urls output."""
    filtered_domains = {d for d in domains if d not in _BOILERPLATE_HOSTS}

    filtered_urls: set[str] = set()
    for url in urls:
        try:
            hostname = urlsplit(_defang(url)).hostname
        except ValueError:
            hostname = None
        hostname = (hostname or "").rstrip(".").lower()
        if hostname in _BOILERPLATE_HOSTS:
            continue
        filtered_urls.add(url)

    return filtered_domains, filtered_urls


# ---------------------------------------------------------------------------
# Public Stage D API
# ---------------------------------------------------------------------------

def extract_iocs(
    all_headers: Optional[dict[str, Any]] = None,
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
    attachment_analysis: Optional[dict[str, Any]] = None,
    header_analysis: Optional[dict[str, Any]] = None,
    extra_urls: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Stage D entry point.

    Parameters
    ----------
    all_headers:
        Stage A normalized headers. All header values are scanned.

    body_text:
        Plain-text email body.

    body_html:
        HTML email body. Both raw HTML and URL-bearing attributes such as
        href/src are inspected.

    attachment_analysis:
        Optional Stage B2 output from analyze_attachments(). Existing
        SHA-256 values are included in the hashes IOC list.

    header_analysis:
        Optional Stage B output from analyze_headers(). The normalized
        originating IP, sender/reply-to domains, canonical From-domain,
        and DKIM signing domain are included (see
        `_extract_from_header_analysis`).

    Returns
    -------
    dict
        JSON-serializable IOC collection with four keys:
            ips, domains, urls, hashes

    Notes
    -----
    - No internet access is performed.
    - No DNS lookups are performed.
    - No threat-intelligence APIs are called.
    - No maliciousness verdict is generated.
    - Values are deduplicated and sorted for deterministic tests/output.
    - Domain candidates must end in a real TLD (`_KNOWN_TLDS`); IP
      candidates must be globally routable; hashes are extracted with
      URLs masked out first. See the module docstring for the full
      rationale.
    """
    ips: set[str] = set()
    domains: set[str] = set()
    urls: set[str] = set()
    hashes: set[str] = set()
    ioc_metadata: dict[str, dict[str, Any]] = {}

    # 1. Stage A headers.
    header_ips, header_domains, header_urls = _extract_from_headers(all_headers)
    ips.update(header_ips)
    domains.update(header_domains)
    urls.update(header_urls)

    # 2. Stage A body text.
    if body_text:
        ips.update(_extract_ips(body_text))
        domains.update(_extract_domains(body_text))
        urls.update(_extract_urls(body_text))
        hashes.update(_extract_hashes(body_text))

    # 3. Stage A body HTML.
    if body_html:
        body_html = _strip_style_and_script_blocks(body_html)
        ips.update(_extract_ips(body_html))
        domains.update(_extract_domains(body_html))
        urls.update(_extract_urls(body_html))
        hashes.update(_extract_hashes(body_html))

        # Parse actual HTML attributes so URLs hidden in href/src/etc.
        # are still captured even when the surrounding HTML is unusual.
        for attribute_value in _extract_html_attribute_values(body_html):
            normalized = _defang(_strip_wrapping_punctuation(attribute_value))

            # Absolute HTTP(S) URL.
            try:
                parsed = urlsplit(normalized)
            except ValueError:
                parsed = None

            if parsed and parsed.scheme in {"http", "https"} and parsed.hostname:
                urls.add(normalized)

                hostname = parsed.hostname.rstrip(".").lower()
                if _is_valid_ip(hostname):
                    if _is_routable_ip(hostname):
                        ips.add(hostname)
                elif _is_valid_domain(hostname):
                    domains.add(hostname)

            # A relative attribute value may still contain a domain/IP-like
            # indicator in malformed/suspicious HTML.
            domains.update(_extract_domains(attribute_value))
            ips.update(_extract_ips(attribute_value))

    # 4. Stage B normalized header information.
    stage_b_ips, stage_b_domains = _extract_from_header_analysis(header_analysis)
    ips.update(stage_b_ips)
    domains.update(stage_b_domains)

    # 5. Stage B2 attachment hashes and QR code URLs with provenance tagging.
    hashes.update(_extract_from_attachment_analysis(attachment_analysis))

    if attachment_analysis and isinstance(attachment_analysis, dict):
        for att in attachment_analysis.get("attachments", []):
            if isinstance(att, dict):
                att_name = att.get("filename") or "unnamed_payload"
                for q_url in att.get("qr_urls", []):
                    if q_url:
                        urls.add(q_url)
                        ioc_metadata[q_url] = {
                            "source": "qr_code",
                            "provenance": f"QR in {att_name}",
                            "attachment": att_name,
                        }

    # 6. Extra injected URLs (if supplied).
    if extra_urls:
        for ex_url in extra_urls:
            if ex_url:
                urls.add(ex_url)
                if ex_url not in ioc_metadata:
                    ioc_metadata[ex_url] = {"source": "injected", "provenance": "external"}

    # 7. Any URL host is inherently a domain/IP IOC as well.
    for url in urls:
        hostname: Optional[str]
        try:
            hostname = urlsplit(_defang(url)).hostname
        except ValueError:
            hostname = None

        if not hostname:
            continue

        hostname = hostname.rstrip(".").lower()

        if _is_valid_ip(hostname):
            if _is_routable_ip(hostname):
                ips.add(hostname)
        elif _is_valid_domain(hostname):
            domains.add(hostname)

    # 8. Drop boilerplate hosts
    domains, urls = _drop_boilerplate(domains, urls)

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "hashes": sorted(hashes),
        "ioc_metadata": ioc_metadata,
    }


__all__ = ["extract_iocs"]
