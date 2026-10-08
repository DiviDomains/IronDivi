# chaos lane status

- done: divi-swapd `[swap]` config overrides (maker/taker timeout, confirmations) so refund runs need not wait hours; validated by SwapConfig::validate
- running: building tools/swap-poc/chaos/ (fault proxy, kill/restart driver) against --backend mock
- broken: nothing
- left: proxy + driver, mock smoke, then live runs (kill at each state, rpc_outage, esplora_429)
- decisions: maker_refundable runs use maker_timeout 1800 s / taker 18000 s (gap 16200 = required 4.5 h); mock daemon loses its in-memory chains on kill -9, so mock only proves driver mechanics, completion is live-only
- last_sha: pending
