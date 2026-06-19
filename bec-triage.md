# BEC Triage - Meridian Group wire-transfer email

## Verdict
Spoofed (impersonation). Confidence: High.
Email was sent entirely from outside Meridian's infrastructure via a Gmail account
Attacker does not have access to sender's actual mailbox

## Red Flags found
- Reply-to is a Gmail address, not a company domain
- SPF softfail, DKIM fail, DMARC fail - sender not authorized
- Originating IP (41.223.x.x) is an African ISP, not Singapore
- Urgency (5 PM deadline), Secrecy ("dont tell the team"), authority (the CEO)

## Verification Checklist (before wiring money)
1. Call the CEO back on a known, trusted number (not from the email)
2. Require a second approver for any new payee or wire
3. Treat urgency as a red flag
4. Verify the sender domain character by character
5. Confirm any new or changed banking details through a separate channel
6. Apply a dollar threshold
7. Log the verification steps you took before submitting
