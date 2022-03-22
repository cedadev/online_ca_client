"""Online CA service client - OAuth 2.0 client for obtaining a delegated 
certificate

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "18/02/22"
__copyright__ = "Copyright 2022 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import contextlib
import threading
import time
from queue import Queue
import webbrowser

import uvicorn 
from uvicorn.protocols.http.h11_impl import H11Protocol


class StoppableWebServer(uvicorn.Server):
    """Threaded Uvicorn server which receives content from an external queue
    to signal to shutdown the service
    """
    def __init__(self, config: uvicorn.Config, queue: Queue) -> None:
        super().__init__(config)

        # Queue used to store flag to indicate server should be shutdown
        self.queue = queue

    @contextlib.contextmanager
    def run_in_thread(self) -> None:
        thread = threading.Thread(target=self.run)
        thread.start()
        launched_browser = False
        try:
            # Flow complete Queue object is used to flag that the OAuth
            # process has been completed
            while self.queue.qsize() < 1:
                time.sleep(1e-3)
                self.thread_callback()
            yield
        finally:
            self.should_exit = True
            thread.join()

    def thread_callback(self):
        """Callback function for loop to allow application of custom behaviours
        """
        pass
