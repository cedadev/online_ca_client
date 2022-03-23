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

import uvicorn 


class StoppableWebServer(uvicorn.Server):
    """Threaded Uvicorn server which receives content from an external queue
    to signal to shutdown the service

    config passed to constructor needs an additional attribute 
    h11_shutdown_queue which is a queue.Queue object
    """
    @contextlib.contextmanager
    def run_in_thread(self) -> None:
        thread = threading.Thread(target=self.run)
        thread.start()
        launched_browser = False
        try:
            # Flow complete Queue object is used to flag that the OAuth
            # process has been completed
            while self.config.h11_shutdown_queue.qsize() < 1:
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
