"""The masternode sync stages of nodes over time, for the scripts that compare
`mnsync status` with divid's.

divid's sync takes a step at most every five seconds once its chain is synced
(masternode-sync.cpp:297-333), so two nodes move through the stages at their
own moments. A `StagePoller` polls the nodes side by side in a thread and keeps,
per node, the stages it saw in order, each once (0, 1 for INITIAL then SPORKS;
998 is FAILED, 999 FINISHED). Scripts compare those sequences, not when each
node moved.

    poller = StagePoller([C, I]).start()
    ...                        # mine, connect, reset
    seqs = poller.stop()       # {node.name: [0, 1]}

Each node needs `.name` and `.call(method, *params)` -> ('ok', result) or
('err', code, message), as the scripts' Node classes have.
"""

import threading
import time


def stage(node):
    """The node's currentMasternodeSyncStatus, or the error of its reply"""
    try:
        out = node.call("mnsync", "status")
    except Exception as e:  # a node that stopped: shown as such in the sequence
        return f"no reply ({type(e).__name__})"
    if out[0] == "ok" and isinstance(out[1], dict):
        return out[1].get("currentMasternodeSyncStatus")
    return f"error {out[1]}"


class StagePoller:
    def __init__(self, nodes, interval=0.5):
        self.nodes = list(nodes)
        self.interval = interval
        self.seen = {n.name: [] for n in self.nodes}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _sample(self):
        for n in self.nodes:
            s = stage(n)
            seq = self.seen[n.name]
            if not seq or seq[-1] != s:
                seq.append(s)

    def _run(self):
        while not self._stop.is_set():
            self._sample()
            self._stop.wait(self.interval)

    def start(self):
        self._thread.start()
        return self

    def stop(self, settle=0.0):
        """Stop polling (after `settle` more seconds) and return the sequences"""
        if settle:
            time.sleep(settle)
        self._stop.set()
        self._thread.join(timeout=30)
        self._sample()
        return self.seen


def text(seq):
    return ",".join(str(s) for s in seq)
