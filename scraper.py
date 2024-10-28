import re
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup

'''
def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]
'''
unique_urls = set()

def scraper(url, resp):
    links = extract_next_links(url, resp)

    '''
    if len(unique_urls) >100:
        print("Reached 100 unique URLs. Stopping the program.")
        sys.exit()
    '''

    for link in links:
        if is_valid(link):
            unique_link = find_unique(link)
            #print("Valid and Unique Link Found:", unique_link)
            unique_urls.add(unique_link)
    print("count", len(unique_urls))
    return list(unique_urls)

def find_unique(link):
    return link.split("#", 1)[0]
    
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
    allowed_domains = [".ics.uci.edu",".cs.uci.edu",".informatics.uci.edu",".stat.uci.edu"]

    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

    #check if it has "high information value", we may not use it. Just some hardcode heuristics. 
    if len(soup.get_text(separator=" ", strip=True)) < 200:
        return list()

    forms = soup.find_all("form")

    for form in forms:
        if any(
            input_tag.get("type") == "password" or
            input_tag.get("name") in ["username", "email", "password", "login"]
            for input_tag in form.find_all("input")):
            return list()
    
    hyperlinks = [a['href'] for a in soup.find_all('a', href=True)]

    for link in hyperlinks:
        if not link.startswith('http'):
            continue
        # parsed = urlparse(urljoin(url, link))._replace(fragment="")
        parsed = urlparse(link)._replace(fragment="")

        domain = parsed.netloc
        path = parsed.path

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
        # keywords = ['calendar', 'month', 'year', 'week', 'map']
        


        parsed = urlparse(url)

        # if parsed.query and re.search(r"(date|ical|action|session|track|ref|utm|fbclid|gclid|mc_eid|mc_cid)", parsed.query.lower()):
        #     return False
        
        if parsed.query and re.search(r"(date|ical|action|filter)", parsed.query.lower()):
            return False

        if re.search(r"(/pdf/|login|/month|/uploads/|facebook|twitter)", url.lower()):
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
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ppsx|bib"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)(?:[\?#]|$)", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
