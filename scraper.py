import re
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

    # Extract and validate links from the current page
    links = extract_next_links(url, resp)

    # Process the page content to update word frequencies and longest page
    # Get the text content from the page
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    text = soup.get_text(separator=' ', strip=True)

    # **Print the URL and its text content**
    print(f"URL: {resp.url}")
    print(f"Text content:\n{text}\n{'-'*80}\n")

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

        # print(f"Unique URL: {normalized_url}")
        # print(f"unique_set: {unique_urls}")
        # print(f"Subdomain: {subdomain}")
        # print(f"subdomains: {subdomains}\n{'-'*80}\n")
        
        subdomains[subdomain] += 1

    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    error_phrases = [
        "page not found", "404 error", "not available", "no longer exists", 
        "we couldn't find", "this page may have been removed"
    ]

    
    #Don't parse all pages with none content
    if not resp.raw_response:
        return list()

    #Don't parse all pages that doesn't return correct status code or that return correct status code but has errors
    if resp.status != 200 or any(resp.error == error_phrase for error_phrase in error_phrases):
        return list()

    #Use BeautifulSoup to parse the web page
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

    #check if it has "high information value", we may not use it. Just some hardcode heuristics. 
    # if len(soup.get_text(separator=" ", strip=True)) < 200:
    #     return list()

    #Detect if the page is a login page
    forms = soup.find_all("form")
    for form in forms:
        if any(
            input_tag.get("type") == "password" or
            input_tag.get("name") in ["username", "email", "password", "login"]
            for input_tag in form.find_all("input")):
            return list()
    

    #Get all the hyperlinks from the page
    hyperlinks = [a['href'] for a in soup.find_all('a', href=True)]

    # Remove those that doesn't belong to this domain
    result = []
    allowed_domains = [".ics.uci.edu",".cs.uci.edu",".informatics.uci.edu",".stat.uci.edu"]

    for link in hyperlinks:
        # join partial directory
        if link.startswith("/") and link.endswith("/"):
            parsed = urlparse(urljoin(url, link))._replace(fragment="")
        elif not link.startswith('http'):
            continue
        else:
            parsed = urlparse(link)._replace(fragment="")

        domain = parsed.netloc
        path = parsed.path
        #Check domain
        if any(domain.endswith(allowed) for allowed in allowed_domains) or (domain == "today.uci.edu" and path.startswith("/department/information_computer_sciences")):
            good_link = urlunparse(parsed)
            result.append(good_link)
            # print(good_link)

    return result


def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        

        parsed = urlparse(url)

        # if parsed.query and re.search(r"(date|ical|action|session|track|ref|utm|fbclid|gclid|mc_eid|mc_cid)", parsed.query.lower()):
        #     return False
        
        #Rule out those queries
        if parsed.query and re.search(r"(date|ical|action|filter)", parsed.query.lower()):
            return False
        #Rule out these conditions
        if re.search(r"(/pdf/|login|facebook|twitter)", url.lower()):
            return False
        #Rule out possible calendar
        date = re.compile(
            r"\b\d{4}[-/]\d{2}[-/]\d{2}\b|"
            r"\b\d{2}[-/]\d{2}[-/]\d{4}\b|"
            r"\b\d{4}[-/]\d{2}\b|"
            r"\b\d{2}[-/]\d{4}\b"
        )
        if bool(date.search(url)):
            return False
        
        #Avoid Pagination Traps
        # page_match = re.search(r"(?:(?:\?|&)page=|/page/)(\d+)", url)
        # if page_match:
        #     page_num = int(page_match.group(1))
        #     if page_num > 10:
        #         return False
            

        if parsed.scheme not in set(["http", "https"]):
            return False
        #Rule out these files
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
