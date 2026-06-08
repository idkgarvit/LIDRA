import logging
import queue
import threading
import time
from typing import Callable, Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class WorkerPool:
    def __init__(self, num_workers: int = 4, queue_size: int = 1000):
        self._num_workers = max(1, num_workers)
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._workers: List[threading.Thread] = []
        self._running = False
        self._results: queue.Queue = queue.Queue()
        self._processed = 0
        self._dropped = 0
        self._start_time = time.time()

    def start(self, worker_fn: Callable):
        self._running = True
        for i in range(self._num_workers):
            t = threading.Thread(target=self._worker_loop, args=(worker_fn,), daemon=True, name=f"worker-{i}")
            t.start()
            self._workers.append(t)
        logger.info(f"[WorkerPool] Started {self._num_workers} workers")

    def stop(self):
        self._running = False
        for _ in self._workers:
            try:
                self._queue.put(None, timeout=1)
            except queue.Full:
                logger.debug("[WorkerPool] Queue full during stop")
        for t in self._workers:
            t.join(timeout=2)
        logger.info(f"[WorkerPool] Stopped — processed={self._processed} dropped={self._dropped}")

    def submit(self, item: Any) -> bool:
        if not self._running:
            return False
        try:
            self._queue.put(item, timeout=0.1)
            return True
        except queue.Full:
            self._dropped += 1
            return False

    def drain_results(self) -> List[Any]:
        results = []
        while not self._results.empty():
            try:
                results.append(self._results.get_nowait())
            except queue.Empty:
                break
        return results

    def stats(self) -> Dict:
        elapsed = time.time() - self._start_time
        return {
            "workers": self._num_workers,
            "processed": self._processed,
            "dropped": self._dropped,
            "pps": round(self._processed / elapsed, 1) if elapsed > 0 else 0,
            "queue_size": self._queue.qsize(),
        }

    def _worker_loop(self, worker_fn: Callable):
        while self._running:
            try:
                item = self._queue.get(timeout=0.5)
                if item is None:
                    break
                try:
                    result = worker_fn(item)
                    if result is not None:
                        self._results.put(result)
                except Exception as e:
                    logger.warning(f"[WorkerPool] Worker error: {e}")
                self._processed += 1
                self._queue.task_done()
            except queue.Empty:
                continue
