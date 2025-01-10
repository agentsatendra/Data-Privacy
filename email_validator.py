import re
import dns.resolver

def validate_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(regex, email):
        return False, "Invalid email format"
    
    domain = email.split('@')[1]
    try:
        dns.resolver.resolve(domain, 'MX')
        return True, "Valid email"
    except dns.resolver.NoAnswer:
        return False, "Domain does not exist" 