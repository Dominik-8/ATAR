# Standardization package - review and submission guide

Status 2026-09-09: **review-ready, NOT submitted anywhere.** Nothing below
happens without Dominik's explicit go, and the two account/legal steps can
only be done by Dominik himself.

## What is in this package

| File | What it is |
|---|---|
| `w3c-community-group-intro.md` | Post for the W3C Agent Identity Registry Protocol Community Group. The post body is the part between the `---` markers; the notes at the bottom are for review only. |
| `draft-dbrueck-atar-lifecycle-00.md` | IETF Internet-Draft source (kramdown-rfc2629). Canonical, human-editable source. |
| `draft-dbrueck-atar-lifecycle-00.xml` | RFCXML v3, generated from the .md. **This is the file the IETF Datatracker accepts.** |
| `draft-dbrueck-atar-lifecycle-00.txt` | Rendered text rendering (what reviewers read). |
| `draft-dbrueck-atar-lifecycle-00.html` | Rendered HTML rendering (easiest to review in a browser). |

Generated 2026-09-09 with kramdown-rfc2629 1.7.43 and xml2rfc 3.34.0;
xml2rfc validates with zero errors and zero warnings. The draft is a
complete 19-page document: attestation model, revocation, freshness/TTL,
key rotation, disputes, gossip transport, score semantics, informative
trust computation, security considerations, IANA considerations, and an
open-issues appendix.

To regenerate after editing the .md:
`kramdown-rfc draft-dbrueck-atar-lifecycle-00.md > draft-dbrueck-atar-lifecycle-00.xml`
then `xml2rfc --text --html draft-dbrueck-atar-lifecycle-00.xml`.

## Decisions only Dominik can make (before any submission)

1. **Author email for the IETF draft.** The draft currently lists only
   "Dominik Brück, Independent" with no email address. The Datatracker
   requires an email per author, and whatever is used becomes public
   (and receives spam) more or less forever. Options: his Gmail, a
   dedicated address, or a forwarded alias. His GitHub noreply address
   is technically possible but unusual for IETF documents. This is
   deliberately left blank - his call.
2. **W3C account.** Joining the community group needs his own W3C
   account under his own name.
3. **Two legal acknowledgments he makes personally:**
   - W3C: joining the group means accepting the W3C Community
     Contributor License Agreement (covers contributions he makes to the
     group).
   - IETF: submitting the draft means accepting the IETF Note Well /
     BCP 78 (grants the IETF Trust publication rights in the draft).
4. **Final read of both texts.** Both are written in his name
   ("I'm Dominik, ..." / author "Dominik Brück"). He should read the
   rendered `.html` of the draft and the post body once before they go
   out.

## Part A: W3C Community Group (post the intro)

Verified 2026-09-09: the group is real and active - "Agent Identity
Registry Protocol Community Group", launched 2026-04-24, public mailing
list public-agent-identity@w3.org. Its published scope explicitly
includes "Revocation and credential lifecycle management", which is
exactly ATAR's contribution.

1. Create a W3C account: https://www.w3.org/account/ (Request an
   account), with his name and his email; confirm the verification mail.
   W3C Membership is NOT required - a free account is enough.
2. Log in, then open: https://www.w3.org/community/agent-identity/join
3. Read and accept the Community Contributor License Agreement, then
   confirm joining. He is now publicly listed as a participant.
4. Post the intro: send it to **public-agent-identity@w3.org** from the
   email address he registered (or use the group's page once logged in).
   - Subject: `ATAR - an open-source agent trust graph with a full lifecycle, built on did:key + W3C VCs`
   - Body: the part of `w3c-community-group-intro.md` between the `---`
     markers (from "Hi all" to the signature line), as plain text.
5. Replies arrive by mail to his address. Answer them as himself; ask
   Instinct for draft replies anytime.

## Part B: IETF Internet-Draft (submit the draft)

The draft targets the **Independent Submission stream, Experimental**
(already set in the document header: `submissiontype: independent`,
`category: exp`). After submission it goes to the Independent
Submissions Editor (ISE) for review, not to a working group.

1. Create a Datatracker account: https://datatracker.ietf.org/accounts/create/
   with his name and the author email chosen above; confirm the
   verification mail.
2. Optional but recommended nit check: open
   https://author-tools.ietf.org/ and run idnits on
   `draft-dbrueck-atar-lifecycle-00.txt` (or the .xml). Fix anything it
   flags, or ask Instinct to.
3. Open https://datatracker.ietf.org/submit/ and upload
   **`draft-dbrueck-atar-lifecycle-00.xml`** (standalone xml2rfc v3 is
   the preferred format - exactly what this file is). The .txt is
   optional; the Datatracker regenerates it from the XML.
4. Check the pre-filled metadata: title, abstract, filename
   `draft-dbrueck-atar-lifecycle-00`, author "Dominik Brück" with the
   chosen email. The document date refreshes automatically on
   submission.
5. Accept the Note Well / BCP 78 confirmation and submit.
6. A confirmation email with a verification link goes to the author
   email. Click it - the submission is not complete without this step.
7. After confirmation the draft appears on the Datatracker and is
   announced to the I-D announce list; the ISE reviews independent
   submissions and may come back with comments before publishing it as
   an ISE-stream document.

## Order and timing

Recommended: W3C post first (starts the conversation, low ceremony),
IETF submission a few days later or right after - both are independent.
Neither step obligates him to anything beyond the two license
acknowledgments above.

## What stays undone until Dominik says go

No group has been joined, nothing has been posted or submitted, and no
third party has been contacted. The GitHub Support ticket #4741893
(old-commit cleanup) runs separately and does not affect this package.
