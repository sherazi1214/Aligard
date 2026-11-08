# AliGuard detection layers (v3)

| Layer | Kya karta hai | Default | Network? |
|---|---|---|---|
| Heuristics | Sender spoof, urgency, lookalike domain, SPF/DKIM/DMARC, filename tricks | ON | nahi |
| ML text model | Phishing-jaisa text pattern (akela PHISHING nahi bana sakta) | ON | nahi |
| Attachment content | Asli file type (magic bytes), PDF JS/links, Office macros, remote template, encrypted/exe zip, HTML login form | ON | nahi |
| QR-code (quishing) | Image ke QR se chhupa link nikalna (opencv optional) | ON agar opencv ho | nahi |
| Reputation | VirusTotal / threat feeds | key ho to | haan |
| Link sandbox | Link headless browser mein kholna, postmortem | `SANDBOX_ENABLED` | haan |
| Domain age | RDAP se domain kitna naya hai | `DOMAIN_INTEL_ENABLED` | haan (rdap.org) |
| LLM | Sirf borderline mails, sirf asar (hukm nahi) | key ho to | haan |

Postmortem (`scans.postmortem`, migration 0006): sandbox/attachments/domain/QR ka DEFANGED khulasa. Raw URL, page text,
screenshot, attachment bytes kabhi store nahi hote. Dashboard par "Scan report" mein dikhta hai.

Privacy: sandbox aur domain-age external requests bhejte hain (link ka host / domain naam). Privacy Policy mein likhein
aur default OFF rehne dein jab tak user/org consent na de.
