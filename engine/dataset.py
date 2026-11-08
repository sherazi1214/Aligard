"""SYNTHETIC training data generator (templates se). Ye asli phishing corpus ka badal NAHI hai:
bunyadi pipeline chalane aur English + Roman Urdu + Urdu + Pakistani brands ka dhancha dikhane ke
liye hai. Production ke liye train.py --csv se asli dataset (Nazario, SpamAssassin, Enron,
apne reported samples) do."""
from __future__ import annotations

import random
from dataclasses import dataclass

BRANDS = ["PayPal", "Microsoft", "Apple", "Amazon", "Netflix", "Google", "Facebook"]
BANKS = ["HBL", "UBL", "MCB", "Meezan Bank", "Allied Bank", "Bank Alfalah"]
WALLETS = ["Easypaisa", "JazzCash", "SadaPay"]
NAMES = ["Ali", "Ahmed", "Sara", "Hina", "Usman", "Ayesha", "Bilal", "Zain"]
MONTHS = ["January", "March", "May", "July", "September", "November"]

# family -> (label, [(subject, body), ...]). Aakhri template (agar 3+ hon) test ke liye alag.
P, L = 1, 0
FAMILIES: dict[str, tuple[int, list[tuple[str, str]]]] = {
    "bank_verify": (P, [
        ("Urgent: Verify your {bank} account", "Dear customer, we detected unusual activity on your {bank} account. Your account will be suspended within {hrs} hours unless you verify your identity. Click here to confirm your login details: {url}"),
        ("{bank} Security Alert", "Your online banking access has been locked. To restore access please log in and update your password and card number now: {url}"),
        ("Action required on your account", "Hello {name}, due to new regulations you must re-confirm your account number and PIN code today. Failure to do so will result in your {bank} account being blocked. {url}"),
    ]),
    "account_suspended": (P, [
        ("Your {brand} account has been suspended", "We noticed a sign in from a new device. For your safety your {brand} account is limited. Verify your account immediately to avoid permanent closure: {url}"),
        ("{brand}: confirm your identity", "Final notice. Your {brand} account will be deactivated. Please sign in to confirm your identity and billing information: {url}"),
    ]),
    "password_expire": (P, [
        ("Password expires today", "Hi {name}, your email password expires in {hrs} hours. Click below to keep the same password and avoid losing access: {url}"),
        ("IT Helpdesk: mailbox quota exceeded", "Your mailbox is almost full and incoming mail will be rejected. Log in to increase your storage: {url}"),
    ]),
    "delivery_fee": (P, [
        ("Parcel on hold", "Your parcel {ref} could not be delivered. Pay a small customs fee of Rs {amt} to release the package: {url}"),
        ("Delivery failed - reschedule", "We attempted to deliver your package but nobody was home. Confirm your address and pay the redelivery fee within {hrs} hours: {url}"),
    ]),
    "prize_winner": (P, [
        ("Congratulations! You have won", "Congratulations {name}, you have won a cash reward of Rs {amt}! Claim your prize now before it expires: {url}"),
        ("You are our lucky winner", "Your email was selected in our lottery. Send your full name, CNIC and bank account number to claim the gift card worth {amt}."),
    ]),
    "invoice_attached": (P, [
        ("Invoice {ref} attached", "Please find attached the overdue invoice. Open the document and enable content to view payment details: {url}"),
        ("Payment confirmation required", "Your payment of ${amt} is pending. Review the attached remittance advice and confirm your login: {url}"),
    ]),
    "tax_refund": (P, [
        ("Tax refund notification", "You are eligible for a tax refund of Rs {amt}. Submit your CNIC and card details to receive the refund within {hrs} hours: {url}"),
        ("FBR refund approved", "FBR has approved your refund. Verify your identity here to receive the payment: {url}"),
    ]),
    "wallet_block_ru": (P, [
        ("Aapka {wallet} account block ho gaya", "Aapka {wallet} account block ho gaya hai. Turant verify karein warna {hrs} ghante mein band ho jayega. Apna PIN aur CNIC yahan dein: {url}"),
        ("{wallet} alert: foran action", "Mohtaram customer, aap ke {wallet} account mein ghair mamooli activity hui hai. Foran apna password dein aur OTP bhejein: {url}"),
        ("{wallet} suspend", "Aapka account suspend kar diya gaya hai. Dobara active karne ke liye CNIC number aur PIN code is link par likhein: {url}"),
    ]),
    "bisp_8171": (P, [
        ("BISP Ehsaas inam", "Mubarak ho! Aap ka BISP Ehsaas program mein Rs {amt} ka inam nikla hai. Raqam wasool karne ke liye apna CNIC aur PIN dein: {url}"),
        ("8171 registration", "Ehsaas 8171 se Rs {amt} lene ke liye {hrs} ghante mein verify karein, warna aap ka naam list se nikal diya jayega: {url}"),
    ]),
    "jazzcash_prize_ru": (P, [
        ("JazzCash inaam", "Mubarak ho {name}! JazzCash lucky draw mein aap ne Rs {amt} jeeta hai. Claim karne ke liye link kholain aur apna PIN likhein: {url}"),
        ("Lucky draw winner", "Mubarak ho, aap ka number lucky draw mein nikla hai. Inaam lene ke liye foran apna CNIC bhejein: {url}"),
    ]),
    "urdu_script": (P, [
        ("اکاؤنٹ بلاک", "آپ کا {bank} اکاؤنٹ بلاک ہو گیا ہے۔ فوری تصدیق کریں اور اپنا پاس ورڈ اور شناختی کارڈ نمبر درج کریں: {url}"),
        ("مبارک ہو انعام", "مبارک ہو! آپ نے {amt} روپے کا انعام جیتا ہے۔ انعام حاصل کرنے کے لیے فوری لنک پر کلک کریں: {url}"),
    ]),
    "otp_phish": (P, [
        ("Verify transaction", "A payment of Rs {amt} is pending on your {bank} account. To cancel it reply with the OTP we just sent you or click: {url}"),
        ("{wallet} support", "Hum {wallet} se bol rahe hain. Aap ke account mein masla hai, apna OTP code hume bhej dein warna account band ho jayega."),
    ]),
    # --- legit ---
    "newsletter": (L, [
        ("Your weekly digest", "Hi {name}, here are this week's top stories and tips picked for you. Read more on our website: {url} You can unsubscribe at any time from your settings."),
        ("New articles this week", "Thanks for subscribing. This week: five productivity tips, a guide to Python testing and a profile of a local startup. {url}"),
        ("Weekend reading list", "Hello {name}, we picked a few long reads for your weekend: an interview with a designer, a short story and a recipe. Enjoy! {url}"),
    ]),
    "order_confirm": (L, [
        ("Order {ref} confirmed", "Thank you for your order, {name}. Your items will ship in 2 business days. Track your order or view details here: {url}"),
        ("Your {brand} receipt", "Thanks for your payment of ${amt}. This is a receipt for your records. No action is needed."),
    ]),
    "meeting": (L, [
        ("Meeting tomorrow at 3pm", "Hi team, reminder that the project meeting is tomorrow at 3pm in the conference room. Please bring your updates. Thanks, {name}"),
        ("Agenda for Friday", "Attached is the agenda for Friday's review. Let me know if you want to add anything. Best, {name}"),
        ("Rescheduled: team sync", "Hi all, the team sync has moved to Thursday morning. Same room, same agenda. Please confirm if you cannot attend. {name}"),
    ]),
    "otp_legit": (L, [
        ("Your {bank} one-time password", "Your OTP is {n} for your transaction of Rs {amt}. It is valid for 5 minutes. Do not share it with anyone. {bank} will never ask for your OTP."),
        ("Verification code", "{n} is your verification code. Never share this code. If you did not request it, ignore this message."),
    ]),
    "reset_legit": (L, [
        ("Reset your password", "We received a request to reset your password. Use the button to choose a new one: {url} If you did not request this, you can safely ignore this email."),
        ("Password changed", "Your password was changed successfully on {month}. If this was you, no action is needed. If not, contact support."),
        ("New sign-in to your account", "We noticed a new sign-in from a Windows device. If this was you, you do not need to do anything. If not, you can review recent activity in your account settings."),
    ]),
    "statement": (L, [
        ("Your e-statement is ready", "Dear {name}, your {bank} e-statement for {month} is now available. Log in to your mobile app to view it. {url}"),
        ("Monthly account summary", "Your monthly account summary is attached for your records. For questions please call our helpline during office hours."),
        ("Statement notification", "Your {month} statement has been generated. You can download it from the app or visit any branch. Thank you for banking with {bank}."),
    ]),
    "utility_bill": (L, [
        ("Electricity bill for {month}", "Your bill of Rs {amt} is due on {month} 25. You can pay online, through your bank app or at any branch. {url}"),
        ("Gas bill reminder", "This is a reminder that your bill of Rs {amt} is due soon. Ignore if already paid."),
    ]),
    "family_ru": (L, [
        ("Kal ka plan", "Yaar kal ka plan kya hai? Shaam ko cricket khelne chalte hain, sab ko bata do. {name} bhi aa raha hai."),
        ("Dawat", "Assalam o alaikum, is Sunday ghar par dawat hai, zaroor aana. Khana sab ke liye hoga."),
    ]),
    "promo_hard": (L, [
        ("Limited time offer", "Limited time offer from {brand}! Enjoy 20% off your next purchase. Claim your discount code on our website: {url} Terms apply."),
        ("Winner of our photo contest", "Congratulations to {name}, the winner of this month's photo contest! See all the entries here: {url}"),
        ("Flash sale this weekend", "Big savings this weekend only from {brand}. Free shipping on orders above Rs {amt}. Shop now: {url}"),
    ]),
    "university": (L, [
        ("Semester schedule", "Dear students, the exam schedule for this semester has been uploaded to the portal. Please check your timetable and contact the office with any clashes."),
        ("Fee challan notice", "The fee challan for the next semester is available on the student portal. The last date for payment is {month} 30."),
    ]),
    "shipping_legit": (L, [
        ("Your package has shipped", "Good news {name}, your package {ref} is on its way. Estimated delivery in 3 days. Track it here: {url}"),
        ("Out for delivery", "Your order is out for delivery today. Please keep your phone nearby for the courier."),
    ]),
}
# Poori family test ke liye alag (train ne kabhi nahi dekhi)
HOLDOUT: dict[str, tuple[int, list[tuple[str, str]]]] = {
    "crypto_support": (P, [
        ("Wallet security notice", "Your crypto wallet requires immediate validation. Connect your wallet and enter your recovery phrase to prevent loss of funds: {url}"),
        ("Exchange withdrawal paused", "Withdrawals on your account are paused. Verify your login and seed phrase within {hrs} hours: {url}"),
    ]),
    "job_fee": (P, [
        ("Job offer - registration fee", "Congratulations {name}, you are selected for the position. Pay a refundable registration fee of Rs {amt} to confirm your joining: {url}"),
    ]),
    "sim_block": (P, [
        ("PTA: SIM block notice", "PTA ke mutabiq aap ki SIM {hrs} ghante mein block ho jayegi. Biometric verify karne ke liye CNIC number bhejein: {url}"),
    ]),
    "school_pta": (L, [
        ("PTA meeting", "Dear parents, the PTA meeting will be held in {month} at 10am in the school hall. Your attendance is requested."),
    ]),
    "accounting": (L, [
        ("Invoice {ref} from our accounting team", "Hi, attached is invoice {ref} for the services last month, due in 30 days. Thanks for your business."),
    ]),
    "code_review": (L, [
        ("Pull request merged", "Your pull request was merged into main. View it on the repository page: {url}"),
    ]),
}


@dataclass
class Sample:
    text: str
    label: int
    group: str  # family/template, calibration ke GroupKFold ke liye


@dataclass
class Dataset:
    train: list[Sample]
    test_unseen_phrasing: list[Sample]
    test_unseen_families: list[Sample]


def _fill(rng: random.Random, template: tuple[str, str], label: int) -> str:
    brand = rng.choice(BRANDS)
    url = (f"http://{brand.lower()}-secure-{rng.randint(1, 99)}.{rng.choice(['xyz', 'top', 'click'])}/login"
           if label == P else f"https://www.{brand.lower()}.com/account/{rng.randint(100, 999)}")
    vals = {
        "brand": brand, "bank": rng.choice(BANKS), "wallet": rng.choice(WALLETS),
        "name": rng.choice(NAMES), "n": rng.randint(100000, 999999),
        "amt": f"{rng.randint(1, 500) * 100:,}", "hrs": rng.choice([12, 24, 48]),
        "ref": f"{rng.choice('ABCXYZ')}{rng.randint(10000, 99999)}", "month": rng.choice(MONTHS),
        "url": url,
    }
    subject, body = template
    return f"{subject.format(**vals)}\n{body.format(**vals)}"


def generate(seed: int = 42, per_template: int = 120, per_test_template: int = 40) -> Dataset:
    rng = random.Random(seed)  # noqa: S311 - crypto ki zaroorat nahi, sirf data generation
    train: list[Sample] = []
    unseen_phr: list[Sample] = []
    unseen_fam: list[Sample] = []
    for family, (label, templates) in FAMILIES.items():
        held = templates[-1:] if len(templates) >= 3 else []
        for i, tpl in enumerate(templates):
            is_held = tpl in held
            n = per_test_template if is_held else per_template
            for _ in range(n):
                s = Sample(_fill(rng, tpl, label), label, f"{family}:{i}")
                (unseen_phr if is_held else train).append(s)
    for family, (label, templates) in HOLDOUT.items():
        for i, tpl in enumerate(templates):
            for _ in range(per_test_template):
                unseen_fam.append(Sample(_fill(rng, tpl, label), label, f"{family}:{i}"))
    rng.shuffle(train)
    return Dataset(train, unseen_phr, unseen_fam)
