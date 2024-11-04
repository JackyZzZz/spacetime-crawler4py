import os
import shelve

from threading import Lock
from queue import Queue, Empty

from utils import get_logger, get_urlhash, normalize
from scraper import is_valid

class Frontier(object):
    def __init__(self, config, restart):
        self.logger = get_logger("FRONTIER")
        self.config = config
        self.to_be_downloaded = Queue()
        self.lock = Lock()

        if not os.path.exists(self.config.save_file) and not restart:
            self.logger.info(f"Did not find save file {self.config.save_file}, starting from seed.")
        elif os.path.exists(self.config.save_file) and restart:
            self.logger.info(f"Found save file {self.config.save_file}, deleting it.")
            os.remove(self.config.save_file)

        self.save = shelve.open(self.config.save_file)

        if restart:
            for url in self.config.seed_urls:
                self.add_url(url)
        else:
            self._parse_save_file()
            if not self.save:
                for url in self.config.seed_urls:
                    self.add_url(url)

    def _parse_save_file(self):
        total_count = len(self.save)
        tbd_count = 0

        with self.lock:
            for url, completed in self.save.values():
                if not completed and is_valid(url):
                    self.to_be_downloaded.put(url)
                    tbd_count += 1

        self.logger.info(f"Found {tbd_count} urls to be downloaded from {total_count} total urls discovered.")

    def get_tbd_url(self):
        try:
            while True:
                url_never_seen = self.to_be_downloaded.get(block=False)
                url_never_seen = normalize(url_never_seen)
                urlhash = get_urlhash(url_never_seen)

                with self.lock:
                    if urlhash in self.save and not self.save[urlhash][1]:
                        return url_never_seen
                # If URL is already completed, continue to the next one
        except Empty:
            return None

    def add_url(self, url):
        url = normalize(url)
        urlhash = get_urlhash(url)

        with self.lock:
            if urlhash not in self.save:
                self.save[urlhash] = (url, False)
                self.save.sync()
                self.to_be_downloaded.put(url)

    def mark_url_complete(self, url):
        url = normalize(url)
        urlhash = get_urlhash(url)

        with self.lock:
            if urlhash not in self.save:
                self.logger.error(f"Completed url {url}, but have not seen it before.")
                return

            self.save[urlhash] = (url, True)
            self.save.sync()

    def close(self):
        with self.lock:
            self.save.close()
            self.logger.info(f"Closed save file {self.config.save_file}.")