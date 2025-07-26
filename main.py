import argparse
import requests
from bs4 import BeautifulSoup
import logging
import re
import urllib.parse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyze HTML forms for anti-CSRF token implementation.")
    parser.add_argument("url", help="The URL of the page to analyze.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output (debug logging).")
    return parser

def validate_url(url):
    """
    Validates the input URL.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_forms(url):
    """
    Retrieves all forms from the specified URL.

    Args:
        url (str): The URL to retrieve forms from.

    Returns:
        list: A list of BeautifulSoup form elements.  Returns an empty list if no forms found or an error occurs.
    """
    try:
        response = requests.get(url, timeout=10) # Added timeout for safety
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        return forms
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
        return [] # Return empty list if request fails
    except Exception as e:
        logging.error(f"Error parsing HTML: {e}")
        return [] # Return empty list if parsing fails

def analyze_form(form, url):
    """
    Analyzes a single HTML form for CSRF protection.

    Args:
        form (bs4.element.Tag): The BeautifulSoup form element to analyze.
        url (str): The URL of the page containing the form.

    Returns:
        dict: A dictionary containing the analysis results.
              {'has_csrf_token': bool, 'token_name': str, 'method': str, 'action': str}
              Returns None if an error occurs.
    """
    try:
        method = form.get('method', 'GET').upper()
        action = form.get('action', url)

        # Normalize action URL
        action = urllib.parse.urljoin(url, action)

        csrf_token_field = None
        for input_field in form.find_all('input'):
            if input_field.get('type') == 'hidden':
                # Check if the input field name looks like a CSRF token
                name = input_field.get('name')
                if name and re.search(r"(csrf|token|xsrf|authenticity)", name, re.IGNORECASE):
                    csrf_token_field = name
                    break

        has_csrf_token = csrf_token_field is not None

        return {
            'has_csrf_token': has_csrf_token,
            'token_name': csrf_token_field,
            'method': method,
            'action': action
        }
    except Exception as e:
        logging.error(f"Error analyzing form: {e}")
        return None

def main():
    """
    Main function to orchestrate the CSRF token check.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url

    if not validate_url(url):
        logging.error("Invalid URL provided.")
        sys.exit(1)

    logging.info(f"Analyzing URL: {url}")

    forms = get_forms(url)

    if not forms:
        logging.info("No forms found on the page.")
        sys.exit(0)

    for i, form in enumerate(forms):
        logging.info(f"Analyzing Form {i+1}:")
        analysis_result = analyze_form(form, url)

        if analysis_result:
            logging.info(f"  Method: {analysis_result['method']}")
            logging.info(f"  Action: {analysis_result['action']}")
            if analysis_result['has_csrf_token']:
                logging.info(f"  CSRF Token Present: Yes (Name: {analysis_result['token_name']})")
            else:
                logging.warning("  CSRF Token Present: No")
                logging.warning("  Potential CSRF vulnerability found!")
        else:
            logging.error(f"  Failed to analyze form {i+1}")

if __name__ == "__main__":
    main()

# Example Usage:
# python vscan-anti-csrf-token-checker.py http://example.com
# python vscan-anti-csrf-token-checker.py https://example.com/login --verbose