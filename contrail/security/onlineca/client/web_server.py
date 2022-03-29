"""Online CA service client - web server which can be stopped programmatically
by populating a Queue object with at least one element

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

import uvicorn 
import signal, socket
from types import FrameType
from typing import Optional, List


class StoppableWebServer(uvicorn.Server):
    """Threaded Uvicorn server which receives content from an external queue
    to signal to shutdown the service

    config passed to constructor needs an additional attribute 
    shutdown_queue which is a queue.Queue object
    """
    def __init__(self, config: uvicorn.Config) -> None:
        super().__init__(config)
        self.config.shutdown_queue = Queue()

    async def serve(self, sockets: Optional[List[socket.socket]] = None) -> None:
        """Override base implementation in order to catch exceptions and make
        the program exit"""
        try:
            await super().serve(sockets)
        except (Exception, BaseException) as e:
            # Use queue to signal to top-level loop to break
            self.config.shutdown_queue.put(True)

    @contextlib.contextmanager
    def run_in_thread(self) -> None:
        thread = threading.Thread(target=self.run)
        thread.start()

        try:
            # Flow complete Queue object is used to flag that the OAuth
            # process has been completed
            while self.config.shutdown_queue.qsize() < 1:
                time.sleep(1e-3)
                self.thread_callback()
            yield
        finally:
            self.should_exit = True
            thread.join()

    def thread_callback(self):
        """Callback function for loop - make an alternative method in a subclass 
        allow application of custom behaviours
        """
        pass
