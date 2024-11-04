from threading import Thread, Lock
from inspect import getsource
from utils.download import download
from utils import get_logger
import scraper
import time
from urllib.parse import urlparse

# Shared data structure and lock for politeness policy
last_access_times = {}
last_access_lock = Lock()

class Worker(Thread):
    def __init__(self, worker_id, config, frontier):
        self.logger = get_logger(f"Worker-{worker_id}", "Worker")
        self.config = config
        self.frontier = frontier
        #self.barrier = barrier
        # Basic check for requests in scraper
        assert {getsource(scraper).find(req) for req in {"from requests import", "import requests"}} == {-1}, "Do not use requests in scraper.py"
        assert {getsource(scraper).find(req) for req in {"from urllib.request import", "import urllib.request"}} == {-1}, "Do not use urllib.request in scraper.py"
        super().__init__(daemon=True)
        
    def run(self):
        while True:
            try:
                tbd_url = self.frontier.get_tbd_url()
                if not tbd_url:
                    self.logger.info("Frontier is empty. Stopping Crawler.")
                    break
                    #index = self.barrier.wait()
                    #if index == 0:
                        # Only one thread will execute this block
                        #scraper.report_results()
                        #scraper.write_unique_urls_and_subdomains()
                    #break
    
                # Enforce politeness policy
                domain = urlparse(tbd_url).netloc
                with last_access_lock:
                    last_access = last_access_times.get(domain)
                    current_time = time.time()
                    if last_access:
                        elapsed_time = current_time - last_access
                        if elapsed_time < 0.5:
                            sleep_time = 0.5 - elapsed_time
                            self.logger.info(f"Sleeping for {sleep_time:.2f} seconds to respect politeness policy for domain {domain}")
                            time.sleep(sleep_time)
                    # Update the last access time
                    last_access_times[domain] = time.time()
    
                resp = download(tbd_url, self.config, self.logger)
                self.logger.info(
                    f"Downloaded {tbd_url}, status <{resp.status}>, "
                    f"using cache {self.config.cache_server}.")
                scraped_urls = scraper.scraper(tbd_url, resp)
                for scraped_url in scraped_urls:
                    self.frontier.add_url(scraped_url)
                self.frontier.mark_url_complete(tbd_url)
                time.sleep(self.config.time_delay)
            
            except Exception as e:
                self.logger.error(f"Error processing URL {tbd_url}: {e}", exc_info=True)
                if tbd_url:
                    self.frontier.mark_url_complete(tbd_url)
                    time.sleep(self.config.time_delay)
