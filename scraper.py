import re
import os
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
from collections import Counter, defaultdict
import nltk
from threading import Lock
from nltk.corpus import stopwords

try:
    STOP_WORDS = set(stopwords.words('english'))
except LookupError:
    nltk.download('stopwords')
    STOP_WORDS = set(stopwords.words('english'))

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

# Similarity detection variables and lock
similarity_lock = Lock()
seen_hashes = set()
similar_pages = {}
similar_comparison = []

def tokenize(text):
    current_token = ''
    for char in text:
        char = char.lower()
        if 'a' <= char <= 'z' or '0' <= char <= '9':
            current_token += char
        else:
            if current_token:
                yield current_token
                current_token = ''
    if current_token:
        yield current_token
            
def compute_word_hash(word, hash_bits=64):
   # Generates a hash for the given word
    hash_value = 0
    for i, char in enumerate(word):
        hash_value += ord(char) * (101 ** i)
        hash_value = hash_value & ((1 << hash_bits) - 1)  # Ensure it stays within the limit
    return bin(hash_value)[2:].zfill(hash_bits)

def compute_simhash(text, hash_bits=64):
    # Computes the Simhash of the given text using the provided tokenize function.
    tokens = list(tokenize(text))
    token_counts = Counter(tokens)
    vector = [0] * hash_bits

    for token, weight in token_counts.items():  # Use frequency as weight
        hash_bits_str = compute_word_hash(token, hash_bits)

        for i in range(hash_bits):
            if hash_bits_str[i] == '1':
                vector[i] += weight
            else:
                vector[i] -= weight

    # Create the fingerprint
    fingerprint = 0
    for i in range(hash_bits):
        if vector[i] > 0:
            fingerprint |= (1 << i)

    return fingerprint

def distance(hash1, hash2):
    # Calculates the distance between two hash values.
    x = hash1 ^ hash2
    distance = 0
    while x:
        distance += x & 1
        x >>= 1
    return distance

def detect_similarity(url, text, threshold=3, hash_bits=64):
    # Detects similarity between the current page and previously processed pages.
    global seen_hashes
    global similar_pages
    global similar_comparison

    result = False

    # Compute Simhash for the current page
    page_hash = compute_simhash(text, hash_bits)

    # Use the lock to synchronize access to the shared variables
    with similarity_lock:
        # Check for similarity by comparing with seen hashes
        for other_url, other_hash in similar_pages.items():
            if distance(page_hash, other_hash) <= threshold:
                similar_comparison.append((url, other_url))
                result = True

        # Add the current page to the records
        seen_hashes.add(page_hash)
        similar_pages[url] = page_hash

    return result
            
def contains_garbage_content(text):
    garbage_patterns = [
        r'\x00',          # Null byte
        r'�',             # Replacement character
        r'\ufffd',        # Unicode replacement character
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
    # Determines if the Content-Type indicates standard HTML content.
    return content_type.startswith('text/html')

def scraper(url, resp):
    global word_frequencies
    global longest_page
    global unique_urls
    global subdomains

    # Check if the response status is 200 OK
    if resp.status != 200:
        return []

    # Check if the Content-Type is HTML
    content_type = resp.raw_response.headers.get('Content-Type', '').lower()
    if not is_html_content(content_type):
        return []

    # Process the page content to update word frequencies and longest page
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    
    # Extract text from specific HTML tags
    text_elements = soup.find_all(['p', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
    text = ' '.join(element.get_text(separator=' ', strip=True) for element in text_elements)

    # Detecting the similarity
    detect_similarity(resp.url, text)

    # Check for garbage content
    if contains_garbage_content(text):
        return []

    tokens = list(tokenize(text))

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
                subdomain = '.'.join(domain_parts[:-2]) + '.' + '.'.join(domain_parts[-2:])
            else:
                subdomain = parsed_url.netloc  # No subdomain

            with subdomains_lock:
                subdomains[subdomain] += 1

    # Output the URL and its text content to a file
    with file_lock:
        with open("Logs/url_content.txt", "a", encoding="utf-8") as f:
            f.write(f"URL: {resp.url}\n")
            f.write(f"Text content:\n{text}\n{'-'*80}\n")

    # Extract and validate links from the current page
    links = extract_next_links(url, resp)
    valid_links = [link for link in links if is_valid(link)]

    return valid_links

def extract_next_links(url, resp):
    # Return a list with the hyperlinks (as strings) scraped from resp.raw_response.content
    error_phrases = [
        "page not found", "404 error", "not available", "no longer exists",
        "we couldn't find", "this page may have been removed"
    ]

    # Don't parse pages with no content
    if not resp.raw_response:
        return []

    # Don't parse pages that have errors
    if any(error_phrase in resp.raw_response.content.decode('utf-8', 'ignore').lower() for error_phrase in error_phrases):
        return []

    # Use BeautifulSoup to parse the web page
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

    # Check if it has "high information value", we may not use it. Just some hardcode heuristics. 
    if len(soup.get_text(separator=" ", strip=True)) < 50:
        return list()

    # Detect if the page is a login page
    forms = soup.find_all("form")
    for form in forms:
        if any(
            input_tag.get("type") == "password" or
            input_tag.get("name") in ["username", "email", "password", "login"]
            for input_tag in form.find_all("input")
        ):
            return []

    # Get all the hyperlinks from the page
    hyperlinks = [a['href'] for a in soup.find_all('a', href=True)]

    # Normalize and collect all extracted URLs
    result = []
    for link in hyperlinks:
        # Normalize the URL
        if link.startswith("http"):
            parsed = urlparse(link)._replace(fragment="")
            normalized_link = urlunparse(parsed)
            result.append(normalized_link)

    return result

def is_valid(url):
    # Decide whether to crawl this url or not.
    try:
        parsed = urlparse(url)

        # Check for allowed domains
        allowed_domains = [".ics.uci.edu", ".cs.uci.edu", ".informatics.uci.edu", ".stat.uci.edu"]
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        if not any(domain.endswith(allowed) for allowed in allowed_domains) and not \
           (domain == "today.uci.edu" and path.startswith("/department/information_computer_sciences")):
            return False

        # Check for disallowed query parameters
        if parsed.query and re.search(r"(date|ical|action|filter)", parsed.query.lower()):
            return False

        # Check for disallowed URL patterns
        if re.search(r"(/pdf/|login|facebook|twitter|wp-content/uploads)", url.lower()):
            return False

        # Check for possible calendar URLs
        date_pattern = re.compile(
            r"\b\d{4}[-/]\d{2}[-/]\d{2}\b|"  # YYYY-MM-DD or YYYY/MM/DD
            r"\b\d{2}[-/]\d{2}[-/]\d{4}\b|"  # MM-DD-YYYY or MM/DD/YYYY
            r"\b\d{4}[-/]\d{2}\b|"           # YYYY-MM
            r"\b\d{2}[-/]\d{4}\b"            # MM-YYYY
        )
        if bool(date_pattern.search(url)):
            return False

        # Avoid Pagination Traps
        page_match = re.search(r"(?:(?:\?|&)page=|/page/)(\d+)", url)
        if page_match:
            page_num = int(page_match.group(1))
            if page_num > 5:
                return False

        if parsed.scheme not in set(["http", "https"]):
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
        print("TypeError for ", parsed)
        raise

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
            
    with open("Logs/detect_similarity.txt", "w") as f:
        if similar_comparison:
            f.write("Similar page found between the following page pairs:\n")
            for url1, url2 in similar_comparison:
                f.write(f"{url1} and {url2}\n")
        else:
            f.write("No similar pages found.\n")

def write_unique_urls_and_subdomains():
    # Ensure the Logs directory exists
    if not os.path.exists("Logs"):
        os.makedirs("Logs")

    # Write the total number of unique URLs
    with open("Logs/unique_urls.txt", "w") as f:
        f.write(f"Total unique URLs: {len(unique_urls)}\n")

    # Write the subdomains dictionary sorted alphabetically by subdomain
    sorted_subdomains = dict(sorted(subdomains.items()))
    with open("Logs/subdomains.txt", "w") as f:
        f.write("Subdomains and their unique page counts:\n")
        for subdomain, count in sorted_subdomains.items():
            f.write(f"{subdomain}: {count}\n")