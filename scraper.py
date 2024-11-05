import re
import os
from urllib.parse import urlparse, urljoin, urlunparse, unquote
from bs4 import BeautifulSoup
from collections import Counter, defaultdict
from threading import Lock
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from boilerpy3 import extractors
from langdetect import detect, DetectorFactory
import hashlib
import logging

# Set up logging
logging.basicConfig(filename='crawler.log', level=logging.INFO)

# Ensure consistent language detection results
DetectorFactory.seed = 0

# Initialize NLTK resources
try:
    STOP_WORDS = set(stopwords.words('english'))
except LookupError:
    nltk.download('stopwords')
    STOP_WORDS = set(stopwords.words('english'))

try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

# Global variables to track word frequencies and the longest page
word_frequencies = Counter()
longest_page = {
    'url': None,
    'word_count': 0
}

# Global variables to track unique URLs and subdomains
unique_urls = set()
subdomains = defaultdict(int)

# Locks for thread safety
word_frequencies_lock = Lock()
longest_page_lock = Lock()
unique_urls_lock = Lock()
subdomains_lock = Lock()
file_lock = Lock()
content_hash_lock = Lock()

# Processed content hashes to detect duplicates
processed_hashes = set()

def tokenize(text):
    tokens = word_tokenize(text.lower())
    return [token for token in tokens if token.isalnum()]

def is_html_content(content_type):
    # Determines if the Content-Type indicates standard HTML content.
    return content_type.startswith('text/html')

def get_content_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def get_text_to_html_ratio(soup):
    text = soup.get_text(separator=' ', strip=True)
    total_text_length = len(text)
    total_html_length = len(str(soup))
    if total_html_length == 0:
        return 0
    return total_text_length / total_html_length

def link_text_ratio(soup):
    link_text = ' '.join(a.get_text() for a in soup.find_all('a'))
    total_text = soup.get_text(separator=' ', strip=True)
    if len(total_text) == 0:
        return 0
    return len(link_text) / len(total_text)

def scraper(url, resp):
    global word_frequencies
    global longest_page
    global unique_urls
    global subdomains

    # Check if the response status is 200 OK
    if resp.status != 200:
        logging.warning(f"Non-200 response for URL {url}: {resp.status}")
        return []

    # Check if the Content-Type is HTML
    content_type = resp.raw_response.headers.get('Content-Type', '').lower()
    if not is_html_content(content_type):
        logging.info(f"Non-HTML content at URL {url}: {content_type}")
        return []

    # Decode the content
    try:
        html_content = resp.raw_response.content.decode('utf-8', 'ignore')
    except Exception as e:
        logging.error(f"Error decoding content from URL {url}: {e}")
        return []

    soup = BeautifulSoup(html_content, 'html.parser')

    # Extract main content using boilerplate removal
    extractor = extractors.ArticleExtractor()
    try:
        main_content = extractor.get_content(html_content)
    except Exception as e:
        logging.error(f"Error extracting main content from URL {url}: {e}")
        return []

    if not main_content or len(main_content) < 200:
        logging.info(f"Low-content page at URL {url}")
        return []

    # Check text-to-HTML ratio
    text_to_html_ratio = get_text_to_html_ratio(soup)
    if text_to_html_ratio < 0.05:
        logging.info(f"Low text-to-HTML ratio at URL {url}")
        return []

    # Check link-to-text ratio
    ratio = link_text_ratio(soup)
    if ratio > 0.5:
        logging.info(f"High link-to-text ratio at URL {url}")
        return []

    # Compute content hash to avoid duplicates
    content_hash = get_content_hash(main_content)
    with content_hash_lock:
        if content_hash in processed_hashes:
            logging.info(f"Duplicate content at URL {url}")
            return []
        else:
            processed_hashes.add(content_hash)

    # Tokenize and process the main content
    tokens = tokenize(main_content)

    # Remove stop words
    filtered_tokens = [token for token in tokens if token not in STOP_WORDS]

    # Update word frequencies
    with word_frequencies_lock:
        word_frequencies.update(filtered_tokens)

    # Update the longest page if this page has more words
    word_count = len(filtered_tokens)
    with longest_page_lock:
        if word_count > longest_page['word_count']:
            longest_page['word_count'] = word_count
            longest_page['url'] = resp.url

    # Process the current URL for uniqueness and subdomain tracking
    parsed_url = urlparse(resp.url)._replace(fragment="")
    normalized_url = urlunparse(parsed_url)

    with unique_urls_lock:
        if normalized_url not in unique_urls:
            unique_urls.add(normalized_url)

            # Extract subdomain
            domain_parts = parsed_url.netloc.split('.')
            if len(domain_parts) > 2:
                subdomain = '.'.join(domain_parts)
            else:
                subdomain = parsed_url.netloc  # No subdomain

            with subdomains_lock:
                subdomains[subdomain] += 1

    # Output the URL and its text content to a file
    with file_lock:
        with open("Logs/url_content.txt", "a", encoding="utf-8") as f:
            f.write(f"URL: {resp.url}\n")
            f.write(f"Text content:\n{main_content}\n{'-'*80}\n")

    # Extract and validate links from the current page
    links = extract_next_links(resp.url, resp)
    valid_links = [link for link in links if is_valid(link)]

    return valid_links

def extract_next_links(url, resp):
    # Return a list with the hyperlinks (as strings) scraped from resp.raw_response.content
    error_phrases = [
        "page not found", "404 error", "not available", "no longer exists",
        "we couldn't find", "this page may have been removed", "error 404"
    ]

    # Don't parse pages with no content
    if not resp.raw_response:
        logging.warning(f"No content at URL {url}")
        return []

    # Check for error messages in content
    content = resp.raw_response.content.decode('utf-8', 'ignore')
    if any(phrase in content.lower() for phrase in error_phrases):
        logging.info(f"Error page detected at URL {url}")
        return []

    # Use BeautifulSoup to parse the web page
    soup = BeautifulSoup(content, 'html.parser')

    # Check if it has "high information value"
    if len(soup.get_text(separator=" ", strip=True)) < 50:
        logging.info(f"Low-information page at URL {url}")
        return []

    # Detect if the page is a login page
    forms = soup.find_all("form")
    for form in forms:
        if any(
            input_tag.get("type") == "password" or
            input_tag.get("name") in ["username", "email", "password", "login"]
            for input_tag in form.find_all("input")
        ):
            logging.info(f"Login page detected at URL {url}")
            return []

    # Get all the hyperlinks from the page
    hyperlinks = [a['href'] for a in soup.find_all('a', href=True)]

    # Normalize and collect all extracted URLs
    result = []
    for link in hyperlinks:
        # Normalize the URL
        full_link = urljoin(url, link)
        parsed = urlparse(full_link)._replace(fragment="")
        normalized_link = urlunparse(parsed)
        result.append(normalized_link)

    return result

def is_valid(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in set(["http", "https"]):
            return False

        # Normalize URL
        url = urlunparse(parsed._replace(fragment=""))
        parsed = urlparse(url)

        # Check for allowed domains
        allowed_domains = [".ics.uci.edu", ".cs.uci.edu", ".informatics.uci.edu", ".stat.uci.edu"]
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        if not any(domain.endswith(allowed) for allowed in allowed_domains) and not \
           (domain == "today.uci.edu" and path.startswith("/department/information_computer_sciences")):
            return False

        # Exclude disallowed query parameters
        disallowed_query = re.compile(r"(sessionid=|sid=|phpsessid=|jsessionid=|utm_|fbclid=|gclid=|date|ical|action|filter)")
        if parsed.query and disallowed_query.search(parsed.query.lower()):
            return False

        # Exclude disallowed URL patterns
        disallowed_patterns = re.compile(
            r"(/pdf/|/rss/|/feed/|/wp-json/|/tag/|/category/|login|logout|signup|register|"
            r"facebook|twitter|linkedin|instagram|wp-content/uploads|print=|format=)"
        )
        if disallowed_patterns.search(url.lower()):
            return False

        # Exclude calendar and date URLs
        date_pattern = re.compile(
            r"/\d{4}/\d{1,2}/\d{1,2}/"
            r"|/\d{1,2}/\d{1,2}/\d{4}/"
            r"|/\d{4}-\d{1,2}-\d{1,2}/"
            r"|/\d{1,2}-\d{1,2}-\d{4}/"
        )
        if date_pattern.search(url):
            return False

        # Avoid Pagination Traps
        pagination_patterns = [
            r"(?:(?:\?|&)(?:page|p|pg|start)=)(\d+)",
            r"/page/(\d+)",
        ]
        for pattern in pagination_patterns:
            match = re.search(pattern, url)
            if match:
                page_num = int(match.group(1))
                if page_num > 5:
                    return False

        # Avoid Repeating Directories
        if re.search(r"(\/\w+\/)\1{2,}", parsed.path):
            return False

        # Avoid Very Long URLs
        if len(url) > 200:
            return False

        # Avoid URLs with excessive encoding
        decoded_path = unquote(parsed.path)
        if '%' in decoded_path:
            return False

        # Avoid URLs with too many parameters
        if len(parsed.query.split('&')) > 5:
            return False

        # Existing file extension check
        if re.search(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            r"|png|tiff?|mid|mp2|mp3|mp4"
            r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ppsx|bib|sql"
            r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            r"|epub|dll|cnf|tgz|sha1"
            r"|thmx|mso|arff|rtf|jar|csv"
            r"|rm|smil|wmv|swf|wma|zip|rar|gz)(?:[\?#]|$)", parsed.path.lower()):
            return False

        return True

    except TypeError:
        logging.error(f"TypeError for URL {url}")
        return False
    except Exception as e:
        logging.error(f"Error validating URL {url}: {e}")
        return False

def report_results():
    # Report the longest page
    if longest_page['url']:
        print(f"Longest page: {longest_page['url']} with {longest_page['word_count']} words.")
    else:
        print("No pages crawled to determine the longest page.")

    # Report the 100 most common words
    most_common_words = word_frequencies.most_common(100)
    for rank, (word, freq) in enumerate(most_common_words, 1):
        print(f"{rank}. {word}: {freq}")

    # Save the results to files
    with open("Logs/common_words.txt", "w") as f:
        f.write("Top 100 Most Common Words:\n")
        for rank, (word, freq) in enumerate(most_common_words, 1):
            f.write(f"{rank}. {word}: {freq}\n")

    with open("Logs/longest_page.txt", "w") as f:
        if longest_page['url']:
            f.write(f"Longest page: {longest_page['url']} with {longest_page['word_count']} words.\n")
        else:
            f.write("No pages crawled to determine the longest page.\n")

def write_unique_urls_and_subdomains():
    # Write the total number of unique URLs
    with open("Logs/unique_urls.txt", "w") as f:
        f.write(f"Total unique URLs: {len(unique_urls)}\n")

    # Write the subdomains dictionary sorted alphabetically by subdomain
    with open("Logs/subdomains.txt", "w") as f:
        f.write("Subdomains and their unique page counts:\n")
        for subdomain, count in sorted(subdomains.items()):
            f.write(f"{subdomain}: {count}\n")
