# IR-2026-042 notes (Acme / customer Globex)

- 03:14 jdoe opened a macro document on WKS-FIN-042; PowerShell pulled a stager
  from update-check.evil-cdn.xyz (185.220.101.47).
- Lateral movement via \\fs01\finance$ using svc_backup (password=Winter2026!).
- Exfil attempted to https://c2.badstuff.top/upload with header
  "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lIn0.c2lnbmF0dXJlLXNhbXBsZQ".
- Contacted Globex's SOC (soc@globex.com); Project Falcon data may be affected.
- AWS key AKIAIOSFODNN7EXAMPLE found in C:\Users\jdoe\.aws\credentials.
