import re
import os
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
from collections import Counter, defaultdict
import nltk
from nltk.corpus import stopwords

# Initialize NLTK stop words
nltk.download('stopwords')
STOP_WORDS = set(stopwords.words('english'))

# Global variables to track word frequencies and the longest page
word_frequencies = Counter()
longest_page = {
    'url': None,
    'word_count': 0
}
# Global variables to track the number of processed URLs and whether results have been reported
processed_urls = 0
results_reported = False

# Global variables to track unique URLs and subdomains
unique_urls = set()
subdomains = defaultdict(int)

def tokenize(text):
    # Use regular expression to find all sequences of alphanumeric characters
    tokens = re.findall(r'\b\w+\b', text.lower())
    return tokens

def contains_garbage_content(text):
    """
    Checks for patterns or indicators of garbage content in the extracted text.
    
    Args:
        text (str): Extracted text from the page.
    
    Returns:
        bool: True if garbage content is detected, False otherwise.
    """
    # Define patterns that are indicative of garbage content
    garbage_patterns = [
        r'\x00',  # Null byte
        r'�',      # Replacement character
        r'\ufffd', # Unicode replacement character
        r'\bPDF-\d+\.\d+\b',  # PDF headers
        r'\bMicrosoft Word\b',
        r'\bOffice.Document\b'
        # Add more patterns as needed
    ]
    
    for pattern in garbage_patterns:
        if re.search(pattern, text):
            return True
    return False

def is_html_content(content_type):
    """
    Determines if the Content-Type indicates standard HTML content.
    """
    # Allow content types that start with 'text/html' and exclude others
    if not content_type.startswith('text/html'):
        return False
    
    # Optionally, check for known problematic subtypes or parameters
    # For example, exclude 'text/html; charset=utf-16' if it's problematic
    # Modify as per your requirements
    return True



def scraper(url, resp):
    global processed_urls
    global results_reported
    global word_frequencies
    global longest_page
    global unique_urls
    global subdomains

    # Increment the counter each time a URL is processed
    processed_urls += 1

    # Check if 100 URLs have been processed and results have not been reported yet
    if processed_urls == 100 and not results_reported:
        report_results()        # Output the scraping results
        write_unique_urls_and_subdomains()  # Output the unique URLs and subdomains
        results_reported = True  # Set the flag to prevent multiple reports
        return []                # Optionally stop further crawling by returning an empty list

    # Check if the response status is 200 OK
    if resp.status != 200:
        return []

    # Inside the scraper function after checking resp.status == 200
    content_type = resp.raw_response.headers.get('Content-Type', '').lower()
    if not is_html_content(content_type):
        return []


    # Extract and validate links from the current page
    links = extract_next_links(url, resp)

    # Process the page content to update word frequencies and longest page
    # Get the text content from the page
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    text = soup.get_text(separator=' ', strip=True)

    # Check for garbage content
    if contains_garbage_content(text):
        return []
    

    # Output the URL and its text content to a file
    with open("Logs/url_content.txt", "a", encoding="utf-8") as f:
        f.write(f"URL: {resp.url}\n")
        f.write(f"Text content:\n{text}\n{'-'*80}\n")

    # Tokenize the text
    tokens = tokenize(text)

    # Remove stop words
    filtered_tokens = [token for token in tokens if token not in STOP_WORDS]

    # Update word frequencies
    word_frequencies.update(filtered_tokens)

    # Update the longest page if this page has more words
    word_count = len(filtered_tokens)
    if word_count > longest_page['word_count']:
        longest_page['word_count'] = word_count
        longest_page['url'] = resp.url

    # Process the current URL for uniqueness and subdomain tracking
    parsed_url = urlparse(resp.url)._replace(fragment="")
    normalized_url = urlunparse(parsed_url)
    
    if normalized_url not in unique_urls:
        unique_urls.add(normalized_url)
        
        # Extract subdomain
        domain_parts = parsed_url.netloc.split('.')
        if len(domain_parts) > 2:
            subdomain = '.'.join(domain_parts[:-2]) + '.' + '.'.join(domain_parts[-2:])
        else:
            subdomain = parsed_url.netloc  # No subdomain
        
        subdomains[subdomain] += 1

    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    # Implementation required.
    # Return a list with the hyperlinks (as strings) scraped from resp.raw_response.content

    error_phrases = [
        "page not found", "404 error", "not available", "no longer exists", 
        "we couldn't find", "this page may have been removed"
    ]

    # Don't parse pages with no content
    if not resp.raw_response:
        return []

    # Don't parse pages that don't return correct status code or that have errors
    if resp.status != 200 or any(resp.error == error_phrase for error_phrase in error_phrases):
        return []

    # Use BeautifulSoup to parse the web page
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

    # Detect if the page is a login page
    forms = soup.find_all("form")
    for form in forms:
        if any(
            input_tag.get("type") == "password" or
            input_tag.get("name") in ["username", "email", "password", "login"]
            for input_tag in form.find_all("input")):
            return []

    # Get all the hyperlinks from the page
    hyperlinks = [a['href'] for a in soup.find_all('a', href=True)]

    # Remove those that don't belong to allowed domains
    result = []
    allowed_domains = [".ics.uci.edu",".cs.uci.edu",".informatics.uci.edu",".stat.uci.edu"]

    for link in hyperlinks:
        # Join partial directory
        if link.startswith("/") and link.endswith("/"):
            parsed = urlparse(urljoin(url, link))._replace(fragment="")
        elif not link.startswith('http'):
            continue
        else:
            parsed = urlparse(link)._replace(fragment="")

        domain = parsed.netloc
        path = parsed.path
        # Check domain
        if any(domain.endswith(allowed) for allowed in allowed_domains) or (domain == "today.uci.edu" and path.startswith("/department/information_computer_sciences")):
            good_link = urlunparse(parsed)
            result.append(good_link)

    return result


def is_valid(url):
    # Decide whether to crawl this url or not.
    try:
        parsed = urlparse(url)

        # Check for disallowed query parameters
        if parsed.query and re.search(r"(date|ical|action|filter)", parsed.query.lower()):
            return False

        # Check for disallowed URL patterns
        if re.search(r"(/pdf/|login|facebook|twitter|wp-content/uploads)", url.lower()):
            return False

        # Check for possible calendar URLs
        date_pattern = re.compile(
            r"\b\d{4}[-/]\d{2}[-/]\d{2}\b|"
            r"\b\d{2}[-/]\d{2}[-/]\d{4}\b|"
            r"\b\d{4}[-/]\d{2}\b|"
            r"\b\d{2}[-/]\d{4}\b"
        )
        if bool(date_pattern.search(url)):
            return False

        if parsed.scheme not in set(["http", "https"]):
            return False

        # Check if URL points to a known non-HTML resource even without extension
        if 'wp-content/uploads' in parsed.path.lower():
            return False

        # Existing file extension check
        return not re.search(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ppsx|bib|sql"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)(?:[\?#]|$)", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise

def report_results():
    # Report the longest page
    if longest_page['url']:
        print(f"Longest page: {longest_page['url']} with {longest_page['word_count']} words.")
    else:
        print("No pages crawled to determine the longest page.")

    # Report the 50 most common words
    most_common_words = word_frequencies.most_common(50)
    for rank, (word, freq) in enumerate(most_common_words, 1):
        print(f"{rank}. {word}: {freq}")

    # Optionally, save the results to files
    with open("Logs/common_words.txt", "w") as f:
        f.write("Top 50 Most Common Words:\n")
        for rank, (word, freq) in enumerate(most_common_words, 1):
            f.write(f"{rank}. {word}: {freq}\n")

    with open("Logs/longest_page.txt", "w") as f:
        if longest_page['url']:
            f.write(f"Longest page: {longest_page['url']} with {longest_page['word_count']} words.\n")
        else:
            f.write("No pages crawled to determine the longest page.\n")

def write_unique_urls_and_subdomains():
    # Write the length of unique URLs set
    with open("Logs/unique_urls.txt", "w") as f:
        f.write(f"Total unique URLs: {len(unique_urls)}\n")

    # Write the subdomains dictionary sorted alphabetically by subdomain
    sorted_subdomains = dict(sorted(subdomains.items()))
    with open("Logs/subdomains.txt", "w") as f:
        f.write("Subdomains and their unique page counts:\n")
        for subdomain, count in sorted_subdomains.items():
            f.write(f"{subdomain}: {count}\n")
