
PRICING = {
    3:  {'rate': 0.035, 'origination': 0.15,  'insurance': 0.008,  'collection': 0.0025,  'crb': 3000},
    6:  {'rate': 0.035, 'origination': 0.15,  'insurance': 0.014,  'collection': 0.0025,  'crb': 3000},
    9:  {'rate': 0.035, 'origination': 0.15,  'insurance': 0.02,   'collection': 0.015,   'crb': 3000},
    12: {'rate': 0.035, 'origination': 0.12,  'insurance': 0.026,  'collection': 0.01139, 'crb': 3000},
    15: {'rate': 0.035, 'origination': 0.2,   'insurance': 0.0297, 'collection': 0.01493, 'crb': 3000},
    18: {'rate': 0.035, 'origination': 0.2,   'insurance': 0.0358, 'collection': 0.014,   'crb': 3000},
    24: {'rate': 0.035, 'origination': 0.2,   'insurance': 0.037,  'collection': 0.0125,  'crb': 3000},
    36: {'rate': 0.035, 'origination': 0.3,   'insurance': 0.041,  'collection': 0.0112,  'crb': 3000},
    48: {'rate': 0.035, 'origination': 0.3,   'insurance': 0.045,  'collection': 0.0095,  'crb': 3000},
}

def calculate_capitalized_amount(loan_amount: float, config: dict) -> float:
    origination = loan_amount * config.get('origination', 0)
    insurance = loan_amount * config.get('insurance', 0)
    crb = config.get('crb', 0)
    return round(loan_amount + origination + insurance + crb, 2)

def calculate_top_up_balance(loan):
    config = PRICING.get(loan.term_months or 0, {})
    loan_amount = loan.loan_amount or 0
    capitalized_amount = calculate_capitalized_amount(loan_amount, config)

    payments = sorted(loan.payments, key=lambda p: p.created_at)
    running_balance = capitalized_amount
    payments_made = 0

    for p in payments:
        if p.allocation and p.allocation.principal:
            running_balance -= p.allocation.principal
            payments_made += 1

    current_balance = max(round(running_balance, 2), 0.00)
    monthly_rate = config.get('rate', 0)
    term = loan.term_months or 0
    remaining_term = term - payments_made

    if monthly_rate > 0 and term > 0:
        annuity_factor = (monthly_rate * (1 + monthly_rate) ** term) / ((1 + monthly_rate) ** term - 1)
        annuity_payment = capitalized_amount * annuity_factor
    else:
        annuity_payment = 0

    total_interest = 0.0
    temp_balance = current_balance
    for _ in range(min(3, remaining_term)):
        if temp_balance <= 0:
            break
        interest = temp_balance * monthly_rate
        principal = annuity_payment - interest
        principal = min(principal, temp_balance)
        total_interest += interest
        temp_balance -= principal

    return round(current_balance + total_interest, 2)