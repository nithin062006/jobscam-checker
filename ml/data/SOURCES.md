# Where the rows in messages.csv come from

- `scamshield_in`: 3 job-scam SMS from the ScamShield IN dataset (huggingface.co/datasets/haxrits/ScamShield-IN, openrail).
- `synthetic`: written by the assistant to test the pipeline. Never use for evaluation.
- `advisory:*`: scam messages quoted verbatim in public articles (phone numbers scrubbed):
  - businesstoday.in, "Got job offer on WhatsApp? Think hard before you reply or accept", 17 Aug 2022
  - thequint.com, Scamguard guide to online job scams (undated)
  - scamdekho.in, "Fake work from home job scam India" (20 Mar 2026). Presented as an example message, possibly illustrative rather than a captured one.
  - newsmeter.in, "Hyderabad: Student lured by WhatsApp message promising part-time job, loses Rs 1.18 L", 12 Sep 2024. Four quoted segments joined into one message.

Checked but contained no verbatim scam wording: canarabank.bank.in (404), NewsMeter 2023 article, Deccan Chronicle fake-RBI article, Free Press Journal Mumbai cyber cell article, Telangana Today (one truncated, anonymised SMS only), publicservicesmap.in (unreachable).

## Added from Hugging Face (training pool only, NOT real data)
- `hf_unverified:Cata-Risk-Lab/recruiter-harvesting-dataset-v1` (MIT): 12 labeled recruiter messages (harvesting = predatory/spam, legitimate = professional). Provenance unclear, probably authored examples.
- `hf_synthetic_llm:Ridham115/indian-scam-sms-synthetic-audited` (CC-BY-4.0): written by LLMs (Gemini, GPT-OSS) then audited. Only English rows with topic job_offer or everyday are used; rows the audit flipped are dropped.
- Not used: `sohaibdevv/Tech-Job-Scams-and-Predatory-Recruitment` (CC-BY-4.0): 1,000 scam-only template-style rows about software-engineer scams, no genuine class.
- Not downloadable: `useKled/scam-messages-you-received` (real messages, but gated/commercial licence).
