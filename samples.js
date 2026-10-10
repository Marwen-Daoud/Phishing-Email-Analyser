/* ===== DEMO EMAILS: entirely fictional. Domains are reserved for examples (example.com, .net, .invalid) and cannot be real. ===== */
const SAMPLES=[
{t:'Obvious phishing',b:`From: Account Security <alert@secure-paypa1-support.example.com>
Subject: URGENT!!! Your account is suspended

Dear customer,

Your account has been suspended. You must verify immediately or your account will be closed within 24 hours.
Confirm your password and the verification code we sent to your phone here:
http://192.0.2.45/login

Also pay the $50 processing fee using gift cards and reply with the numbers.
Open the attached file: Account_Form.pdf.exe`},
{t:'Sophisticated phishing',b:`From: Priya Nair <priya.nair@contoso-partners.example.com>
Reply-To: priya.nair@contoso-partners-mail.example.net
Subject: Q3 vendor onboarding documents

Hi Sam,

Thanks for the call this morning. As discussed, I've shared the onboarding pack for your review. You'll need to sign in with your work account to view it.

<a href="https://shared-docs-review.example.net/q3">example.com/shared/Q3-onboarding</a>

Let me know if you have any trouble.

Kind regards,
Priya`},
{t:'Fake Microsoft 365 warning',b:`Authentication-Results: mx.example.net; spf=fail; dkim=fail; dmarc=fail
From: Microsoft 365 Support <no-reply@microsoft-office365-verify.example.com>
Subject: Action required: password expires today

Your Microsoft 365 password expires today. Your mailbox will be deactivated unless you sign in and confirm your password now.

<a href="https://microsoft-office365-verify.example.com/login">Keep my password</a>

Microsoft Account Team`},
{t:'Fake parcel delivery',b:`From: Parcel Service <delivery@dhl-redelivery.example.com>
Subject: Your parcel could not be delivered

Your parcel could not be delivered today. Please act now and pay a £1.99 redelivery fee to rearrange delivery:
https://shrt.example/parcel-demo

If you do not pay within 24 hours your parcel will be returned.`},
{t:'Invoice / BEC-style',b:`From: Dana Whitfield (CEO) <dana.whitfield@acme-corp.example.com>
Reply-To: dana.whitfield@acme-corp-mail.example.net
Subject: Urgent - invoice and updated bank details

Hi,

I'm in meetings all day and can't take calls. Please process the attached overdue invoice today. Our supplier has changed their bank account details, so use the new account number below for this wire transfer. Keep this confidential and confirm once done.

Thanks,
Dana`},
{t:'Legitimate email',b:`Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass
From: Jordan Lee <jordan.lee@example.org>
Reply-To: jordan.lee@example.org
Subject: Notes from Tuesday's planning meeting

Hi Alex,

Here are the notes from Tuesday. The next meeting is Thursday at 2pm in the usual room. Agenda is at https://example.org/team/agenda

Thanks,
Jordan`}
];


if(typeof module!=='undefined')module.exports={SAMPLES};
