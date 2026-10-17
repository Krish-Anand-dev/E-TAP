// E-TAP Gmail prototype -- Quick Content Check (click-to-analyze).
//
// Nothing is read from the message or sent anywhere until the user clicks
// "Analyze this email". Page watching below only adds an idle banner with a
// button; it never extracts text or makes a request.
//
// Change this URL when deploying the frontend.
const ETAP_APP_BASE_URL = 'https://e-tap-lac.vercel.app';

const ETAP_BODY_SELECTOR = '.ii.gt';

const ETAP_ERROR_MESSAGES = {
    timeout: 'The analysis service did not answer in time. It may be waking up — try again in a minute.',
    rate_limited: 'Too many analyses in a short time. Wait a minute, then try again.',
    too_large: 'This email is too large to analyze.',
    server_error: 'The analysis service reported an error. Try again shortly.',
    http_error: 'The analysis service rejected the request.',
    network: 'Could not reach the analysis service. Check your connection and try again.',
};

// File types that commonly carry a payload (HTML smuggling, scripts, shortcuts,
// disk images, executables, macro documents, archives). Matching one of these
// is a reason for caution on its own, whatever the visible text says.
const ETAP_RISKY_EXT = new Set([
    'html', 'htm', 'xhtml', 'svg', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'hta', 'lnk', 'iso', 'img',
    'exe', 'scr', 'com', 'bat', 'cmd', 'ps1', 'msi', 'jar', 'dll', 'docm', 'xlsm', 'pptm', 'one',
    'zip', 'rar', '7z', 'cab', 'ace',
]);

// Gmail shows attachment chips under the body. We can only see their names here,
// never their contents, so they are reported as "not inspected".
function extractAttachments(emailContainer) {
    const names = new Set();
    emailContainer.querySelectorAll('.aQH span.aV3, .aZo span.aV3, span.aV3').forEach((n) => {
        const t = (n.innerText || n.textContent || '').trim();
        if (t) names.add(t);
    });
    emailContainer.querySelectorAll('[download_url]').forEach((n) => {
        // Format: "mime:filename:url"
        const parts = String(n.getAttribute('download_url') || '').split(':');
        if (parts.length >= 3 && parts[1]) names.add(parts[1].trim());
    });
    return Array.from(names).map((name) => {
        const ext = (name.split('.').pop() || '').toLowerCase();
        return { name, ext, risky: name.includes('.') && ETAP_RISKY_EXT.has(ext) };
    });
}

function extractEmailData(emailContainer) {
    // Gmail uses obfuscated classes, but these selectors have been stable enough for a prototype.
    const subjectEl = document.querySelector('h2[data-thread-perm-id]');
    const bodyEl = emailContainer.querySelector(ETAP_BODY_SELECTOR);

    if (!bodyEl) return null;

    // Prefer the sender shown for this particular message (threads contain many).
    const scope = bodyEl.closest('.gs') || emailContainer;
    const senderEl = scope.querySelector('span[email]') || emailContainer.querySelector('span[email]');

    return {
        subject: subjectEl ? subjectEl.innerText : 'No Subject',
        sender: senderEl ? senderEl.getAttribute('email') : 'Unknown Sender',
        body: bodyEl.innerText,
        attachments: extractAttachments(bodyEl.closest('.gs') || emailContainer),
    };
}

// Identifies "which email is this banner for". Deliberately excludes the
// sender and the full body length: Gmail containers nest (several can resolve
// to the same message body) and quoted text expands, so a looser key keeps
// one stable banner per message instead of replacing it repeatedly.
function emailKey(data) {
    return `${data.subject}|${data.body.slice(0, 200)}`;
}

// A banner belongs to a message body when it is the element right before it.
function bannerFor(container) {
    const body = container.querySelector(ETAP_BODY_SELECTOR);
    const prev = body && body.previousElementSibling;
    return prev && prev.classList.contains('etap-banner') ? prev : null;
}

function insertBanner(container, banner) {
    const bodyContainer = container.querySelector(ETAP_BODY_SELECTOR);
    if (bodyContainer) bodyContainer.parentNode.insertBefore(banner, bodyContainer);
}

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function newBanner(stateClass, key) {
    const banner = el('div', `etap-banner ${stateClass}`);
    banner.dataset.etapKey = key;
    return banner;
}

function replaceBanner(container, oldBanner, newOne) {
    if (oldBanner && oldBanner.parentNode) oldBanner.parentNode.removeChild(oldBanner);
    insertBanner(container, newOne);
}

// ---------------------------------------------------------------------------
// Banner states
// ---------------------------------------------------------------------------

function renderIdle(container, existing, key) {
    const banner = newBanner('banner-idle', key);
    const text = el('div', 'etap-row');
    text.append(
        el('strong', null, '🛡️ E-TAP Quick Content Check'),
        el('span', 'etap-sub', ' — nothing is sent until you click Analyze.')
    );
    const button = el('button', 'etap-btn etap-btn-primary', 'Analyze this email');
    button.type = 'button';
    button.addEventListener('click', () => runAnalysis(container, banner, key));
    banner.append(text, button);
    replaceBanner(container, existing, banner);
}

function renderLoading(container, existing, key) {
    const banner = newBanner('banner-loading', key);
    banner.append(el('strong', null, '🛡️ Analyzing the visible text of this email…'));
    replaceBanner(container, existing, banner);
    return banner;
}

function renderError(container, existing, key, code) {
    const banner = newBanner('banner-error', key);
    const text = el('div', 'etap-row');
    text.append(
        el('strong', null, '⚠️ Analysis did not complete'),
        el('span', 'etap-sub', ` — ${ETAP_ERROR_MESSAGES[code] || ETAP_ERROR_MESSAGES.network} No result is not the same as “safe”.`)
    );
    const retry = el('button', 'etap-btn etap-btn-primary', 'Try again');
    retry.type = 'button';
    retry.addEventListener('click', () => runAnalysis(container, banner, key));
    banner.append(text, retry);
    replaceBanner(container, existing, banner);
}

function chip(tone, text) {
    return el('span', `etap-chip etap-chip-${tone}`, text);
}

function provenanceChips(report, attachmentsSeen) {
    const p = report.analysis_provenance || {};
    const chips = [];

    // The extension only ever sends a reconstruction, so say so regardless of
    // what the server reports.
    chips.push(chip('caution', 'Headers: not available (Gmail view only)'));
    if (attachmentsSeen && attachmentsSeen.length) {
        chips.push(chip('caution', `Attachments: ${attachmentsSeen.length} not inspected`));
    }

    if (p.threat_intel_mode === 'live') {
        if (p.threat_intel_unavailable > 0) {
            chips.push(chip('caution', `Threat intel: live, ${p.threat_intel_unavailable}/${p.threat_intel_lookups} lookups unavailable`));
        } else {
            chips.push(chip('ok', 'Threat intel: live'));
        }
    } else if (p.threat_intel_mode === 'offline_placeholder') {
        chips.push(chip('caution', 'Threat intel: OFFLINE — reputation not checked'));
    } else {
        chips.push(chip('neutral', 'Threat intel: unknown'));
    }

    const providerStatus = report.provider_status || {};
    if (providerStatus.summary) {
        const hasCoverageGap = Number(providerStatus.unavailable_count || 0) > 0 ||
            Number(providerStatus.partial_count || 0) > 0 || providerStatus.coverage_status !== 'complete';
        const coverageLabel = providerStatus.unavailable_count
            ? `Provider coverage: ${providerStatus.unavailable_count} unavailable`
            : (providerStatus.partial_count ? 'Provider coverage: partial' : `Provider coverage: ${providerStatus.coverage_status || 'unknown'}`);
        chips.push(chip(hasCoverageGap ? 'caution' : 'ok', coverageLabel));
    }

    if (p.gemini_skipped_by_triage) {
        chips.push(chip('neutral', 'AI: triage only'));
    } else if (p.fallback_used) {
        const why = p.fallback_reason ? ` (${p.fallback_reason})` : '';
        chips.push(chip('caution', `AI: offline fallback${why}`));
    } else if (p.assessment_provider) {
        const model = p.assessment_model ? ` · ${p.assessment_model}` : '';
        chips.push(chip('ok', `AI: ${p.assessment_provider}${model}`));
    }
    return chips;
}

function renderResult(container, existing, key, report, attachments) {
    attachments = attachments || [];
    const riskyAtt = attachments.filter((a) => a.risky);
    // `verdict_band` is decided by the backend (backend/verdicts.py); the
    // extension does not keep its own thresholds.
    let band = report.verdict_band;
    // Never show an all-clear when a file was attached: its contents were not read.
    if (band === 'safe' && attachments.length) band = 'caution';
    const bandClass = { danger: 'banner-red', caution: 'banner-yellow', safe: 'banner-green' }[band] || 'banner-neutral';
    const verdict = report.verdict || 'Unclassified';
    const attName = (a) => (a.name.length > 40 ? a.name.slice(0, 37) + '…' : a.name);
    const headings = {
        danger: `🚨 High risk: ${verdict}`,
        caution: `⚠️ ${verdict}`,
        // Not a green check: "nothing found" in a partial view is not "safe".
        safe: 'ℹ️ No high-risk signals found in the visible text',
    };

    const assessment = (report.ai_analysis && report.ai_analysis.final_assessment) || {};
    const er = report.evidence_report || null;
    const explanation = (er && er.headline) || assessment.explanation || 'No explanation provided.';

    const banner = newBanner(`${bandClass} etap-banner-rich`, key);

    const head = el('div', 'etap-row');
    head.append(
        el('span', 'etap-tag', 'QUICK CONTENT CHECK'),
        el('strong', null, headings[band] || `ℹ️ ${verdict}`)
    );
    banner.append(head);
    if (riskyAtt.length) {
        head.lastChild.textContent = `⚠️ Risky attachment type, not inspected: ${riskyAtt.map(attName).join(', ')}`;
        banner.append(el('div', 'etap-explanation',
            'This file type is commonly used to deliver malware or phishing pages (for example HTML smuggling). ' +
            'The attachment contents were NOT read by this check. Do not open it unless you trust the sender and expected it; ' +
            'upload the original .eml in the full app for attachment forensics.'));
    } else if (attachments.length) {
        head.lastChild.textContent = `⚠️ ${attachments.length} attachment${attachments.length === 1 ? '' : 's'} not inspected`;
        banner.append(el('div', 'etap-explanation',
            `Attachments (${attachments.map(attName).join(', ')}) were not read by this check, so the text result below does not cover them.`));
    }
    banner.append(el('div', 'etap-explanation', explanation));

    if (er && Array.isArray(er.evidence)) {
        const KIND = { observed: 'Observed', reputation: 'Reputation', ai_inferred: 'AI-inferred' };
        const byId = {};
        er.evidence.forEach((i) => { byId[i.id] = i; });
        const reasons = (er.top_reasons || []).map((id) => byId[id]).filter(Boolean);

        if (reasons.length) {
            const details = el('details', 'etap-details');
            details.append(el('summary', null, `Why (${reasons.length} point${reasons.length === 1 ? '' : 's'})`));
            const list = el('ul');
            reasons.forEach((i) => list.append(el('li', null, `[${KIND[i.kind] || i.kind}] ${i.title}`)));
            details.append(list);
            banner.append(details);
        }

        const limits = (er.conclusion && er.conclusion.limitations) || [];
        if (limits.length) {
            const details = el('details', 'etap-details');
            details.append(el('summary', null, `Not checked (${limits.length}). Unknown is not safe.`));
            const list = el('ul');
            limits.forEach((l) => list.append(el('li', null, String(l))));
            details.append(list);
            banner.append(details);
        }

        const steps = (er.what_to_do && er.what_to_do.steps) || [];
        if (steps.length) {
            banner.append(el('div', 'etap-explanation', `Next step: ${steps[0].text}`));
        }
    } else {
        // Older backend without evidence_report: keep the previous behaviour.
        const evidence = Array.isArray(assessment.supporting_evidence) ? assessment.supporting_evidence.slice(0, 4) : [];
        if (evidence.length) {
            const details = el('details', 'etap-details');
            details.append(el('summary', null, `Why (${evidence.length} point${evidence.length === 1 ? '' : 's'})`));
            const list = el('ul');
            evidence.forEach((item) => list.append(el('li', null, String(item))));
            details.append(list);
            banner.append(details);
        }
    }

    const chips = el('div', 'etap-chips');
    provenanceChips(report, attachments).forEach((c) => chips.append(c));
    banner.append(chips);

    const providerStatus = report.provider_status;
    if (providerStatus && providerStatus.providers && Object.keys(providerStatus.providers).length) {
        const details = el('details', 'etap-details');
        details.append(el('summary', null, providerStatus.summary || 'Provider status'));
        const list = el('ul');
        Object.entries(providerStatus.providers).forEach(([id, provider]) => {
            list.append(el('li', null, `${provider.name || id}: ${String(provider.status || 'unknown').replaceAll('_', ' ')} — ${provider.summary || 'No details returned.'}`));
        });
        details.append(list);
        banner.append(details);
    }

    const foot = el('div', 'etap-row etap-foot');
    foot.append(
        el('span', 'etap-sub', 'Based on visible text only: original headers, link targets and attachments were not inspected. For full forensics, upload the original .eml.')
    );
    const link = el('a', 'etap-btn', 'View Full Report');
    link.href = report.email_id
        ? `${ETAP_APP_BASE_URL}/?dossier=${encodeURIComponent(report.email_id)}`
        : ETAP_APP_BASE_URL;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    foot.append(link);
    banner.append(foot);

    replaceBanner(container, existing, banner);
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

function runAnalysis(container, currentBanner, key) {
    // Extract only now, at click time, so we send what is on screen right now.
    const data = extractEmailData(container);
    if (!data || data.body.length <= 10) {
        renderError(container, currentBanner, key, 'http_error');
        return;
    }
    const loading = renderLoading(container, currentBanner, key);

    chrome.runtime.sendMessage({ action: 'analyzeEmail', data }, (response) => {
        if (chrome.runtime.lastError || !response) {
            renderError(container, loading, key, 'network');
        } else if (response.success) {
            renderResult(container, loading, key, response.report, data.attachments);
        } else {
            renderError(container, loading, key, response.code);
        }
    });
}

// Adds (or refreshes) the idle banner. Reads text only to tell emails apart;
// nothing leaves the page.
function syncBanners() {
    document.querySelectorAll('.adO, .gs, .nH.hx').forEach((container) => {
        const data = extractEmailData(container);
        if (!data || data.body.length <= 10) return;

        const key = emailKey(data);
        const existing = bannerFor(container);
        if (existing && existing.dataset.etapKey === key) return;
        // Same body element now shows a different email (Gmail reuses nodes): reset.
        // Never interrupt a request that is in flight.
        if (existing && existing.classList.contains('banner-loading')) return;
        renderIdle(container, existing, key);
    });
}

let etapSyncTimer = null;
const etapObserver = new MutationObserver(() => {
    clearTimeout(etapSyncTimer);
    etapSyncTimer = setTimeout(syncBanners, 400);
});
etapObserver.observe(document.body, { childList: true, subtree: true });
syncBanners();
