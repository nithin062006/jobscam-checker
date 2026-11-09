"""Plain-language answers to questions people search when they get a suspicious job message.
Each guide: slug -> dict(title, description, question, short, sections[(heading, [paragraphs])], related[slugs])."""

GUIDES = {
    "is-job-registration-fee-legit": {
        "title": "Is a registration fee for a job legit? (India)",
        "description": "Asked to pay a registration, training or security fee before joining? Here is why that is the biggest red flag in Indian job scams, and what to do.",
        "question": "Is it normal to pay a registration fee to get a job?",
        "short": "No. A genuine employer pays you; it does not charge you to be hired. A fee for registration, training, a laptop, a kit, background verification or a security deposit is the classic advance-fee job scam.",
        "sections": [
            ("The names the fee goes by", [
                "Scammers rarely call it a fee for the job. You will see 'registration amount', 'refundable security deposit', 'training kit', 'laptop courier charge', 'ID card fee', 'verification charge' or 'onboarding fee'. The promise is always that it will be refunded with your first salary.",
                "It is never refunded. After the first payment there is usually a second one: 'GST', 'insurance', 'courier hold'. Each payment is presented as the last step.",
            ]),
            ("What about genuine exceptions?", [
                "A few things look similar but are different. Paying an exam or certification body for a test you choose to take is not the employer charging you for the job. Paying a government form fee for a public-sector exam goes to the official portal, not to a person on WhatsApp.",
                "The test: is the money going to a named, official body through its own website, for something you chose, or to a personal UPI ID or bank account to 'confirm your offer'? The second is a scam.",
            ]),
            ("What to do", [
                "Do not pay. Ask for the offer in writing from an official company email, then look the company up on the MCA registry and its own website.",
                "If you already paid, call 1930 (the national cyber crime helpline) immediately and report at cybercrime.gov.in. Tell your bank at once, and keep every chat, receipt and phone number.",
            ]),
        ],
        "related": ["whatsapp-job-offer-is-it-real", "what-to-do-if-you-paid-a-job-scam"],
    },
    "whatsapp-job-offer-is-it-real": {
        "title": "Job offer on WhatsApp or Telegram: is it real?",
        "description": "Got a job offer from an unknown number on WhatsApp or Telegram? Learn the warning signs of fake recruiters and how to verify before you reply.",
        "question": "A recruiter messaged me on WhatsApp. Is the job real?",
        "short": "Real recruiters do sometimes use WhatsApp, but only after you have applied or been contacted through an official channel. An unknown number offering a job you never applied for, with high pay for easy work, is how most job scams start.",
        "sections": [
            ("Signs it is probably a scam", [
                "You did not apply, and they found you 'from a job portal' without naming which one.",
                "High pay for part-time or simple work: typing, liking videos, rating places, 'work from home 2 hours a day'.",
                "They push you to a Telegram group, or send a link to 'join the team'.",
                "No interview, or a 'chat interview' on WhatsApp only, then an immediate offer.",
                "A Gmail or other free email address, or a company name with a slightly different spelling.",
            ]),
            ("How to check", [
                "Ask for an email from the company's own domain and check that the domain matches the real website. Look-alikes such as a hyphen or an extra word are common.",
                "Search the company on its official site and LinkedIn, and find the same job on the company's careers page. Phone the number listed on the official site, not the one in the message.",
                "Check the company in the MCA company master data. A real, registered company will be listed; a new domain registered a few weeks ago is a warning sign.",
            ]),
            ("Safe next step", [
                "Do not click links or join groups. Do not send Aadhaar, PAN, bank details or any OTP. Paste the message into the checker on this site to see which warning signs it contains.",
            ]),
        ],
        "related": ["how-to-check-if-a-company-is-real-india", "task-scam-earn-money-liking-videos"],
    },
    "how-to-check-if-a-company-is-real-india": {
        "title": "How to check if a company is real before you accept (India)",
        "description": "A step-by-step way to verify a company in India: MCA registry, official website, email domain, LinkedIn, and domain age.",
        "question": "How do I check if a company that offered me a job is genuine?",
        "short": "Check five things: the company is on the MCA registry, its website and careers page list the job, the recruiter's email uses the company's own domain, the company has a real LinkedIn presence, and the domain is not brand new.",
        "sections": [
            ("The five checks", [
                "1. MCA registry. Search the exact company name in the Ministry of Corporate Affairs company master data. Registered companies have a CIN. Note that a registered shell company can still scam, so this check alone is not enough.",
                "2. Official website and careers page. Find the website yourself through a search engine, not through a link in the message. See whether the same role is listed.",
                "3. Email domain. A recruiter at a real company writes from its own domain. Gmail, Yahoo, or a domain that differs by a letter or hyphen from the real one is a red flag.",
                "4. LinkedIn. Real companies have employees, history and posts. Check that the recruiter's profile exists and matches the company.",
                "5. Domain age. A scam domain is often only weeks old. A public lookup (RDAP or WHOIS) shows when a domain was registered. This tool does that for domains it finds in your message.",
            ]),
            ("If something does not match", [
                "Contact the company through the number or email on its official website and ask if the offer is genuine. Do not use contact details from the message itself.",
            ]),
        ],
        "related": ["fake-offer-letter-signs", "whatsapp-job-offer-is-it-real"],
    },
    "fake-offer-letter-signs": {
        "title": "How to spot a fake offer letter",
        "description": "Fake offer letters look professional. These are the signs that give them away: no interview, email domain mismatch, fee demands, and pressure to accept.",
        "question": "How can I tell if my offer letter is fake?",
        "short": "A fake offer letter usually arrives with no real interview, from a free or look-alike email address, with unusually high pay, and is followed by a request for money or personal documents.",
        "sections": [
            ("Warning signs", [
                "You were never interviewed, or the 'interview' was a short chat. Real offers follow a hiring process.",
                "The sender's email is Gmail/Yahoo, or a domain that does not match the company's real website.",
                "The pay, joining bonus or perks are far above the market rate for the role.",
                "The letter contains spelling errors, a generic greeting, or a vague role and location.",
                "Right after the letter, you are asked to pay for a kit, laptop, verification or training, or to share bank details and an OTP.",
                "You are told to accept within hours or lose the opportunity.",
            ]),
            ("How to confirm", [
                "Find the HR contact on the company's official website and ask them directly. Check that the role appears on the careers page.",
                "A logo and signature prove nothing. Anyone can copy them.",
            ]),
        ],
        "related": ["is-job-registration-fee-legit", "how-to-check-if-a-company-is-real-india"],
    },
    "task-scam-earn-money-liking-videos": {
        "title": "Task scams: 'earn money by liking videos' explained",
        "description": "How the like-videos, rate-hotels and prepaid-task scams work, why the first payouts are real, and why you can never withdraw the big money.",
        "question": "Is earning money by liking videos or rating products real?",
        "short": "It is a scam. You are paid small real amounts at first to build trust, then asked to deposit money for 'higher tasks'. The deposits never come back.",
        "sections": [
            ("How it works", [
                "A message offers easy part-time money for liking YouTube videos, rating hotels or restaurants, or completing simple tasks. You are paid a small amount, such as Rs 100 to Rs 500.",
                "You are then added to a Telegram group with others who 'earn' much more, and are told to deposit money to unlock a premium task that pays back with a commission.",
                "The tasks escalate. Eventually the 'balance' cannot be withdrawn until you pay tax, a fee or a deposit. The group members showing earnings are part of the scam.",
            ]),
            ("What to do", [
                "Stop completing tasks and do not deposit money. Report the account to Telegram or WhatsApp, and file a complaint at cybercrime.gov.in.",
                "If you sent money, call 1930 immediately.",
            ]),
        ],
        "related": ["whatsapp-job-offer-is-it-real", "what-to-do-if-you-paid-a-job-scam"],
    },
    "what-to-do-if-you-paid-a-job-scam": {
        "title": "I paid in a fake job scam. What do I do now? (India)",
        "description": "Immediate steps if you lost money to a job scam in India: call 1930, report on cybercrime.gov.in, inform your bank, and preserve evidence.",
        "question": "I paid money to a fake recruiter. What should I do?",
        "short": "Act fast. Call 1930, report at cybercrime.gov.in, tell your bank to try to block the transaction, and save all evidence. The sooner you report, the better the chance of freezing the money.",
        "sections": [
            ("In the first hour", [
                "Call 1930, the national cyber crime helpline, and give the transaction details. Speed matters because it can help freeze the receiving account.",
                "Contact your bank or UPI app support, report a fraudulent transaction and ask them to try to block or hold it.",
                "Do not pay anything more, even if they say it will release your money.",
            ]),
            ("Then", [
                "File a complaint at cybercrime.gov.in with the chat screenshots, receipts, phone numbers, UPI IDs and any website links.",
                "Stop talking to the scammer and block them after you have saved the evidence. Change passwords and PINs if you shared any.",
                "Beware of 'recovery agents' who contact you offering to get your money back for a fee. Those are usually a second scam.",
            ]),
        ],
        "related": ["is-job-registration-fee-legit", "fake-offer-letter-signs"],
    },
}
