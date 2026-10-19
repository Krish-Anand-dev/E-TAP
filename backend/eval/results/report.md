> **POST-FIX, OFFLINE-ONLY RUN (24-message debugging fixture) — NOT A BENCHMARK.** Generated after the B2 offline-fallback and charset fixes, with no Gemini and no live threat intel. The sample is tiny and mostly 2002-era bulk spam, not link-based phishing. Do not quote these numbers as E-TAP's detection rate.

# B2 baseline: false positives / false negatives

Corpus: `../docs/extracted`: 24 unique messages (3 exact duplicate(s) dropped, 0 skipped).

**Configuration measured:** offline only. Assessment provider: {'offline_fallback': 24}; XGBoost triage available: {True: 24}; threat intel: {'offline_placeholder': 24}.

Positive class = spam (`malicious`). No thresholds were changed.

> **Sample size:** Only 15 benign and 9 malicious messages. The confidence intervals are the honest reading; do not quote these as detection rates.

## flagged (band=danger, score>=65)

- False positives: **1 / 15** ham (FPR 7%, 95% CI 1%-30%)
- False negatives: **9 / 9** spam (FNR 100%, 95% CI 70%-100%); **2 of those had an empty body (parser failure)**

| category | label | n | flagged |
|---|---|---|---|
| easy_ham | benign | 6 | 0 |
| easy_ham_2 | benign | 3 | 0 |
| hard_ham | benign | 6 | 1 |
| spam | malicious | 6 | 0 |
| spam_2 | malicious | 3 | 0 |

## flagged-or-review (band>=caution, score>=40)

- False positives: **6 / 15** ham (FPR 40%, 95% CI 20%-64%)
- False negatives: **8 / 9** spam (FNR 89%, 95% CI 56%-98%); **2 of those had an empty body (parser failure)**

| category | label | n | flagged |
|---|---|---|---|
| easy_ham | benign | 6 | 2 |
| easy_ham_2 | benign | 3 | 1 |
| hard_ham | benign | 6 | 3 |
| spam | malicious | 6 | 0 |
| spam_2 | malicious | 3 | 1 |

## evidence_state=high_risk_evidence

- False positives: **1 / 15** ham (FPR 7%, 95% CI 1%-30%)
- False negatives: **9 / 9** spam (FNR 100%, 95% CI 70%-100%); **2 of those had an empty body (parser failure)**

| category | label | n | flagged |
|---|---|---|---|
| easy_ham | benign | 6 | 0 |
| easy_ham_2 | benign | 3 | 0 |
| hard_ham | benign | 6 | 1 |
| spam | malicious | 6 | 0 |
| spam_2 | malicious | 3 | 0 |

## Per-message results

| sample | label | score | verdict | evidence state | subject |
|---|---|---|---|---|---|
| 20021010_easy_ham/0049.bda43370915afa1f557f7edab6913e04.json | benign | 19 | LIKELY LEGITIMATE | no_high_risk_found | Re: hauns_froehlingsdorf@infinetivity.com |
| 20021010_easy_ham/0051.9281d3f8a3faf47d09a7fafdf2caf26e.json | benign | 19 | LIKELY LEGITIMATE | no_high_risk_found | [ILUG] Re: Sun Solaris |
| 20021010_easy_ham/0091.3bdd7b578973ee005733480a8b6c9b54.json | benign | 28 | LOW RISK | no_high_risk_found | Re: [scoop] Scoop MS Word .doc file into something that plucker or oth |
| 20021010_hard_ham/0001.f0cf04027e74802f09f723cb8916b48e.json | benign | 57 | SUSPICIOUS | suspicious_uncertain | CNET NEWS.COM: Cable companies cracking down on Wi-Fi |
| 20021010_hard_ham/0002.2fe846db6e3249836abdbfcae459bf2a.json | benign | 28 | LOW RISK | no_high_risk_found | Save an extra $50 on the iPaq 3835 PDA (CNET SHOPPER) |
| 20021010_hard_ham/0004.409015be23edf1c42f319a870114664c.json | benign | 57 | SUSPICIOUS | suspicious_uncertain | Reg Headlines Wednesday July 10 |
| 20021010_spam/0001.bfc8d64d12b325ff385cca8d07b84288.json | malicious | 23 | LOW RISK | no_high_risk_found | Life Insurance - Why Pay More? |
| 20021010_spam/0003.4b3d943b8df71af248d12f8b2e7a224a.json | malicious | 28 | LOW RISK | no_high_risk_found | Guaranteed to lose 10-12 lbs in 30 days                          11.15 |
| 20021010_spam/0005.1f42bb885de0ef7fc5cd09d34dc2ba54.json | malicious | 27 | LOW RISK | no_high_risk_found | [ILUG-Social] re: Guaranteed to lose 10-12 lbs in 30 days 10.148 |
| 20030228_easy_ham/00001.7c53336b37003a9286aba55d2945844c.json | benign | 21 | LOW RISK | no_high_risk_found | Re: New Sequences Window |
| 20030228_easy_ham/00002.9c4069e25e1ef370c078db7ee85ff9ac.json | benign | 40 | SUSPICIOUS | suspicious_uncertain | [zzzzteana] RE: Alexander |
| 20030228_easy_ham/00003.860e3c3cee1b42ead714c5c874fe25f7.json | benign | 63 | SUSPICIOUS | suspicious_uncertain | [zzzzteana] Moscow bomber |
| 20030228_easy_ham_2/00002.5a587ae61666c5aa097c8e866aedcc59.json | benign | 24 | LOW RISK | no_high_risk_found | Re: New Sequences Window |
| 20030228_easy_ham_2/00003.19be8acd739ad589cd00d8425bac7115.json | benign | 24 | LOW RISK | no_high_risk_found | Re: New Sequences Window |
| 20030228_easy_ham_2/00004.b2ed6c3c62bbdfab7683d60e214d1445.json | benign | 51 | SUSPICIOUS | suspicious_uncertain | Re: New Sequences Window |
| 20030228_hard_ham/00001.7c7d6921e671bbe18ebb5f893cd9bb35.json | benign | 73 | LIKELY PHISHING | high_risk_evidence | Personal Finance: Resolutions You Can Keep |
| 20030228_hard_ham/00002.ca96f74042d05c1a1d29ca30467cfcd5.json | benign | 16 | LIKELY LEGITIMATE | no_high_risk_found | Malcolm in the Middle Sweepstakes Prize Notification |
| 20030228_hard_ham/00003.268fd170a3fc73bee2739d8204856a53.json | benign | 10 | LIKELY LEGITIMATE | no_high_risk_found | Automated 30 day renewal reminder 2002-05-27 |
| 20030228_spam/00001.7848dde101aa985090474a91ec93fcf0.json | malicious | 23 | LOW RISK | no_high_risk_found | Life Insurance - Why Pay More? |
| 20030228_spam/00002.d94f1b97e48ed3b553b3508d116e6a09.json | malicious | 28 | LOW RISK | no_high_risk_found | [ILUG] Guaranteed to lose 10-12 lbs in 30 days 10.206 |
| 20030228_spam/00003.2ee33bc6eacdb11f38d052c44819ba6c.json | malicious | 28 | LOW RISK | no_high_risk_found | Guaranteed to lose 10-12 lbs in 30 days                          11.15 |
| 20030228_spam_2/00001.317e78fa8ee2f54cd4890fdc09ba8176.json | malicious | 46 | SUSPICIOUS | suspicious_uncertain | [ILUG] STOP THE MLM INSANITY |
| 20030228_spam_2/00002.9438920e9a55591b18e60d1ed37d992b.json | malicious | 16 | LIKELY LEGITIMATE | no_high_risk_found | Real Protection, Stun Guns!  Free Shipping! Time:2:01:35 PM |
| 20030228_spam_2/00003.590eff932f8704d8b0fcbe69d023b54d.json | malicious | 12 | LIKELY LEGITIMATE | no_high_risk_found | New Improved Fat Burners, Now With TV Fat Absorbers! Time:6:25:49 PM |

Messages that reached the pipeline with an empty body (parser could not decode): `20030228_spam_2/00002.9438920e9a55591b18e60d1ed37d992b.json`, `20030228_spam_2/00003.590eff932f8704d8b0fcbe69d023b54d.json`
