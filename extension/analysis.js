const jobId = new URLSearchParams(location.search).get('job');
const heading = document.getElementById('heading');
const statusText = document.getElementById('status');
const coverage = document.getElementById('coverage');
const retry = document.getElementById('retry');
const limited = document.getElementById('limited');
const originalInput = document.getElementById('original');
document.getElementById('platform').href = ETAP_CONFIG.appBaseUrl;

let selectedJob = null;
let busy = false;
let useVisibleText = false;
let manualOverride = false;
let controller = null;

async function run(job) {
    if (busy) return;
    busy = true;
    selectedJob = job;
    retry.hidden = true;
    limited.hidden = true;
    originalInput.disabled = true;
    const original = Boolean(job.rawEmailBase64);
    heading.textContent = original ? 'Analyzing the original email' : 'Analyzing available email content';
    statusText.textContent = 'Analysis is running. Your full report will open here when it is ready.';
    coverage.textContent = original
        ? 'The original .eml is included. Available headers and MIME attachments go through the full forensic pipeline.'
        : 'Gmail did not provide the original message. This report will clearly mark sender authentication, routing and attachment contents as unavailable. Upload the original .eml for those checks.';
    controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ETAP_CONFIG.requestTimeoutMs);
    try {
        if (jobId) await EtapHandoffStore.update(jobId, (current) => ({ ...current, ...job, state: 'uploading' }));
        const report = await EtapAnalysis.submit(job, controller.signal);
        const destination = EtapAnalysis.reportUrl(report);
        // Cleanup must not prevent a completed report from opening.
        if (jobId) await EtapHandoffStore.remove(jobId).catch(() => {});
        statusText.textContent = 'Analysis complete. Opening your report…';
        location.replace(destination);
    } catch (error) {
        heading.textContent = 'Your analysis needs another try';
        statusText.textContent = error.name === 'AbortError'
            ? 'The service did not answer in time. It may be waking up. Retry here or open E-TAP.'
            : error.message || 'Analysis could not complete. Retry here or open E-TAP.';
        retry.hidden = false;
    } finally {
        clearTimeout(timer);
        busy = false;
        originalInput.disabled = false;
    }
}

async function initialize() {
    try {
        let job = jobId ? await EtapHandoffStore.get(jobId) : null;
        if (!job) throw new Error('This email handoff has expired. Select an original .eml below, reopen analysis from Gmail, or open E-TAP.');
        selectedJob = job;
        document.getElementById('subject').textContent = job.data?.subject || 'Selected Gmail message';
        limited.hidden = false;
        const deadline = Date.now() + 35000;
        while (job.state === 'retrieving' && Date.now() < deadline && !useVisibleText) {
            await new Promise((resolve) => setTimeout(resolve, 250));
            job = await EtapHandoffStore.get(jobId);
            if (!job) throw new Error('This email handoff expired. Select an original .eml below or open E-TAP.');
        }
        if (!manualOverride) await run(job);
    } catch (error) {
        heading.textContent = 'Open your email in E-TAP';
        statusText.textContent = error.message;
        limited.hidden = true;
    }
}

limited.addEventListener('click', () => { useVisibleText = true; });
retry.addEventListener('click', () => { if (selectedJob) run(selectedJob); });
originalInput.addEventListener('change', async () => {
    const file = originalInput.files[0];
    if (!file || busy) return;
    try {
        if (file.size > EtapGmailOriginal.MAX_BYTES) throw new Error('This email exceeds the 25 MB upload limit.');
        if (!file.name.toLowerCase().endsWith('.eml')) throw new Error('Select a downloaded .eml email file.');
        const bytes = new Uint8Array(await file.arrayBuffer());
        if (!EtapGmailOriginal.isOriginal(bytes)) throw new Error('This file does not contain a valid original email. Download the original .eml from Gmail.');
        manualOverride = true;
        useVisibleText = true;
        await run({ ...(selectedJob || {}), rawEmailBase64: EtapGmailOriginal.encode(bytes), state: 'ready' });
    } catch (error) {
        statusText.textContent = error.message;
    }
});

window.addEventListener('pagehide', () => controller?.abort());
initialize();
