import os
import json
import time
import random
import urllib.parse
from playwright.sync_api import sync_playwright

ACCOUNTS_FILE = "accounts.json"
EMAIL_ICON_BASE64_SRC = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAYAAACOEfKtAAAACXBIWXMAACxLAAAsSwGlPZapAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJwSURBVHgB7dvhcZtAEAXgl1TgEraDuASV4A7kDpIOoIOkA7sDpwOSCuQOcAd2B5gdibFHY2Dv9oAD3jezfyyk454ArXUCICIiIiIiIiKivN21VbX12lazkdK5PLV1jwndtlUDaDZedVuCxI7Y1hFnqSMSEQDNDksPmFskUANodloVnO4BNDuvAxyeIgYskC/dt9D5PMDhFDFgd+gL8nGD8z7FzKWGQ9+LPhoHFizP2n79GXgs2tAL/jLsVHPZbik/EbaPswaoBLZ39zfOp9Fcbi5jWs6Sz63K7AEqge36UmOeU1pgu3brPl+/qYsE2ClhC/EO09HXtvzHVPY8f9EAuwnUGJ9AgfQKw7ivGH4DFw9QCWwhVkhzSltblJNhvCwCVDqpobYg1XUxpEWxfIhlE2BnylYntEWxyC5AJUjb6sS2KBZZBqgEaVodfSy2RbHINsBOCVuIX31SelsUi+wDVDGtTmHYfqxFsVhFgEpgb3Uqw3aWFsViNQEqa6szVtYWxWJVAXasrc5XlfqbnlUGqARhay+6bZIFnyurDVAJbNc73Waqr8ZWHWCnHBi3xLQ2EaC6bnVStCgWwfP9hvEXjHleCoKPJcW/bb1hesHzzTnAJQTP9zvIhQE6MUAnBujEAJ0YoBMDdGKATgzQiQE6MUAnBugUG+Ccv/WbS9ScxgJ86fn7kr86ncqx5+/PcHhE/5eMBfL6IXkswfC68wMcDohfMdtKHeBUAWh2WickINjfjYZaNRJeovZyq2tXyW40/EwQd+vX2qpCwJEXszh0wPkmxB+XgdbeE+pq30tb/3Fe/fsHIiIiIiIiIiKibXoHG20wZVqj454AAAAASUVORK5CYII="

def load_accounts():
    """Reads the accounts data from the JSON file."""
    if not os.path.exists(ACCOUNTS_FILE):
        return {"primary": None, "secondary": []}
    with open(ACCOUNTS_FILE, 'r') as f:
        return json.load(f)

def save_accounts(accounts_data):
    """Saves the accounts data to the JSON file."""
    with open(ACCOUNTS_FILE, 'w') as f:
        json.dump(accounts_data, f, indent=4)
    print(f"💾 Accounts data updated in '{ACCOUNTS_FILE}'.")

def human_like_typing(page, selector, text):
    """Types text into an element character by character with random delays."""
    for char in text:
        page.locator(selector).press(char)
        time.sleep(random.uniform(0.05, 0.2))

def login_and_add_account(role, email, password):
    """
    Automates login, intercepts the /api/user/getinfo call to get fresh tokens,
    and saves all session data.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36')
        page = context.new_page()

        try:
            print("1. Navigating to Terabox...")
            page.goto("https://www.terabox.com/")
            time.sleep(random.uniform(1, 2.5))
            page.get_by_role("button", name="Get Started").first.click()
            time.sleep(random.uniform(1, 2))
            page.locator(f"div.logo:has(img[src='{EMAIL_ICON_BASE64_SRC}'])").click()

            print("2. Entering credentials...")
            human_like_typing(page, 'input[placeholder="Enter your email"]', email)
            human_like_typing(page, 'input[placeholder="Enter your password"]', password)
            
            print("3. Submitting login and waiting for the key API call...")

            # --- THE DEFINITIVE FIX ---
            # We wait for the specific API call that we know contains the fresh tokens.
            # This is far more reliable than waiting for UI elements or fixed timers.
            with page.expect_request("**/api/user/getinfo**", timeout=60000) as request_info:
                page.locator("div.email-able-input").click()
            
            # The request has been intercepted
            request = request_info.value
            print("4. Key API call intercepted! Extracting dynamic tokens...")
            
            parsed_url = urllib.parse.urlparse(request.url)
            query_params = urllib.parse.parse_qs(parsed_url.query)

            js_token = query_params.get('jsToken', [None])[0]
            bdstoken_from_url = query_params.get('bdstoken', [None])[0] # This is also the csrfToken

            if not js_token or not bdstoken_from_url:
                print("❌ CRITICAL: Could not parse jsToken or bdstoken from the /api/user/getinfo call.")
                browser.close()
                return False

            print("5. Capturing session cookies...")
            cookies = context.cookies()
            browser.close()
            
            formatted_cookies = {cookie['name']: cookie['value'] for cookie in cookies}
            
            # Verify the token from the URL matches the one in the cookies for sanity
            if formatted_cookies.get('csrfToken') != bdstoken_from_url:
                print("⚠️ Warning: csrfToken in cookie does not match bdstoken in URL. Using URL token.")
                # Ensure the correct token is in the cookie dict we save
                formatted_cookies['csrfToken'] = bdstoken_from_url

            accounts = load_accounts()
            account_data = {
                'email': email,
                'password': password,
                'cookies': formatted_cookies,
                'js_token': js_token
            }

            if role == 'primary':
                accounts['primary'] = account_data
                print(f"✅ Primary account set/updated for user '{email}'.")
            elif role == 'secondary':
                accounts.setdefault('secondary', []).append(account_data)
                index = len(accounts['secondary'])
                print(f"✅ Secondary account added for user '{email}'. Use it with flag '-s {index}'.")
            
            save_accounts(accounts)
            return True

        except Exception as e:
            print(f"\n❌ An error occurred during the login process: {e}")
            browser.close()
            return False

def get_account_data(role, index=0):
    """Loads the entire data block (cookies, jstoken) for a specific account."""
    accounts = load_accounts()
    if role == 'primary':
        return accounts.get('primary')
    elif role == 'secondary':
        secondary_accounts = accounts.get('secondary', [])
        if 0 <= index < len(secondary_accounts):
            return secondary_accounts[index]
    return None