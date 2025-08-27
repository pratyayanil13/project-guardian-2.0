\# Project Guardian 2.0 – PII Detection \& Redaction



This repository contains my solution for the \*\*Echo of a Breach\*\* security challenge.  

The goal is to detect and redact \*\*PII (Personally Identifiable Information)\*\* from data streams in order to prevent data leaks and fraud.



---



\## 🛠 How It Works



1\. \*\*Input\*\*:  

&nbsp;  A CSV file with two columns:

&nbsp;  - `record\_id` (unique identifier)

&nbsp;  - `Data\_json` (JSON string containing various fields)



2\. \*\*Detection Rules\*\*:

&nbsp;  - \*\*Standalone PII\*\* → Always sensitive

&nbsp;    - Phone numbers (10 digits, Indian format)

&nbsp;    - Aadhaar numbers (12 digits)

&nbsp;    - Passport numbers (alphanumeric, e.g. P1234567)

&nbsp;    - UPI IDs (username@upi)

&nbsp;  - \*\*Combinatorial PII\*\* → Sensitive only if 2 or more appear together

&nbsp;    - Full name

&nbsp;    - Email address

&nbsp;    - Physical address

&nbsp;    - Device ID / IP address



&nbsp;  Non-PII such as order IDs, product details, or a standalone email are ignored.



3\. \*\*Redaction\*\*:

&nbsp;  - Phone → `98XXXXXX10`

&nbsp;  - Aadhaar → `1234 XXXX XXXX 9012`

&nbsp;  - Passport → `PXXXXXXX`

&nbsp;  - UPI → `teXXXXpi`

&nbsp;  - Email → `joXXX@gmail.com`

&nbsp;  - Name → `JXXX SXXXX`

&nbsp;  - Address → `\[REDACTED\_ADDRESS]`

&nbsp;  - IP → `192.168.XXX.XXX



