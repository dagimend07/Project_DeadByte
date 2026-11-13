# DeadByte Phase 1 testing

1. Select **New case**, create an account or continue with Google. Email accounts require the confirmation link before sign-in.
2. Create `Harmless training case`, add your name, a description and a note. Capture the Case Manager screen with its generated case ID.
3. Refresh the page. Reopen the case, edit its notes, close it and reopen it by changing the status to Active. Confirm the changes survive refresh.
4. Create a plain text file containing `DeadByte harmless test evidence`. In Evidence Locker, choose the case, choose the file, add your name and confirm authorization. Upload.
5. Capture the evidence record with original filename, SHA-256 baseline and UNPROCESSED status. Refresh to confirm it remains available.
6. Download the original and compare its bytes with the source file. Use an independent hashing tool to compare SHA-256; Phase 1 does not save independent verification or mark files VERIFIED.
7. Try uploading the same file to the same case. Expect a duplicate warning. Empty files and files larger than 50 MB must be rejected.
8. Sign out. Case and evidence records must disappear. Sign in with a separate account: the first account's cases and private originals must remain inaccessible.
9. Capture dashboard counts and recent activity after the case and upload. Totals must reflect actual records, not samples.

## Implemented scope
Dark cyber workspace, account screens, investigator-owned cases, editable notes and status, private original evidence uploads and downloads, SHA-256 upload baselines, duplicate checks, automatically recorded case/upload activity.

## Not implemented
Forensic analyzers, human verification, AI, extracted timelines, report generation and PDF export. These screens explicitly show their upcoming phase. Arbitrary file types may be preserved but are not parsed or analyzed. Case sharing and team membership are not part of this phase; naming an investigator does not grant that person access.

## Verification limits
Provider sign-in and confirmation settings are configured. Full external email and Google sign-in require testing with a real investigator account. Private upload and cross-account tests should be repeated before any live demonstration. Files are limited to 50 MB. If a stored file's metadata save fails, the application reports the incomplete record instead of claiming a successful evidence submission.
