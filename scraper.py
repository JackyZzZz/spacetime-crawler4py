import re
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
from collections import Counter
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



def scraper(url, resp):
    global processed_urls
    global results_reported

    # Increment the counter each time a URL is processed
    processed_urls += 1

    # Check if 100 URLs have been processed and results have not been reported yet
    if processed_urls == 100 and not results_reported:
        report_results()        # Output the scraping results
        results_reported = True  # Set the flag to prevent multiple reports
        return []                # Optionally stop further crawling by returning an empty list

    # Extract and validate links from the current page
    links = extract_next_links(url, resp)
    valid_links = [link for link in links if is_valid(link)]
    
    return valid_links

def tokenize_text(text):
    """
    Tokenizes the input text into words, removes stop words, and non-alphanumeric characters.
    """
    # Convert text to lowercase
    text = text.lower()

    # Remove non-alphanumeric characters using regex
    # This pattern retains lowercase letters, numbers, and whitespace
    text = re.sub(r'[^a-z0-9\s]', '', text)

    # Split text into words
    words = text.split()

    # Remove stop words
    filtered_words = [word for word in words if word not in STOP_WORDS]

    return filtered_words


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

    if resp.status != 200 or any(resp.error == error_phrase for error_phrase in error_phrases):
        return list()
    
    # print(resp.status)
    # print(resp.error)


    result = []
    allowed_domains = ["ics.uci.edu","cs.uci.edu","informatics.uci.edu","stat.uci.edu","today.uci.edu/department/information_computer_sciences"]

    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

    #check if it has "high information value", we may not use it. Just some hardcode heuristics. 
    if len(soup.get_text(separator=" ", strip=True)) < 200:
        return list()

     # Extract text and process word counts
    page_text = soup.get_text(separator=" ", strip=True)
    words = tokenize_text(page_text)
    word_count = len(words)

    # Update the longest page information
    global longest_page
    if word_count > longest_page['word_count']:
        longest_page['url'] = resp.url
        longest_page['word_count'] = word_count

    # Update global word frequencies
    global word_frequencies
    word_frequencies.update(words)
    
    hyperlinks = [a['href'] for a in soup.find_all('a', href=True)]
    
    
    for link in hyperlinks:
        if not link.startswith('http'):
            continue
        parsed = urlparse(urljoin(resp.url, link))


        domain = parsed.netloc
        path = parsed.path

        if any(domain.endswith(allowed) and path.startswith('/') for allowed in allowed_domains):
            good_link = urlunparse(parsed)
            result.append(good_link)
            # print(good_link)



        

    return result


def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        # keywords = ['calendar', 'month', 'year', 'week', 'map']
        


        parsed = urlparse(url)

        if parsed.query and re.search(r"(date|ical|action|session|track|ref|utm|fbclid|gclid|mc_eid|mc_cid)", parsed.query.lower()):
            return False

        date = re.compile(
            r"\b\d{4}[-/]\d{2}[-/]\d{2}\b|"
            r"\b\d{2}[-/]\d{2}[-/]\d{4}\b|"
            r"\b\d{4}[-/]\d{2}\b|"
            r"\b\d{2}[-/]\d{4}\b"
        )
        if bool(date.search(url)):
            return False
        
        page_match = re.search(r"(?:(?:\?|&)page=|/page/)(\d+)", url)
        if page_match:
            page_num = int(page_match.group(1))
            if page_num > 10:
                return False
            

        if parsed.scheme not in set(["http", "https"]):
            return False

        return not re.search(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
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
