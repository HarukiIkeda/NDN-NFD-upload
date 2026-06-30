import asyncio
import json
import time
from ndn.app import NDNApp
from ndn.types import InterestCanceled, InterestTimeout, InterestNack, ValidationFailure
from ndn.encoding import Component, Name

app = NDNApp()
CONSUMER_NAME = "/local/consumer1"

# 【評価用】パケットカウンタ
metrics = {"rx_i": 0, "tx_i": 0, "tx_d": 0, "rx_d": 0}

@app.route(f"{CONSUMER_NAME}/upload")
def on_interest_i4(name, param, app_param):
    metrics["rx_i"] += 1  # 受信Interest(I_4)
    try:
        # 「upload」を基準に session_id と chunk_id を取得
        uri_parts = Name.to_str(name).strip('/').split('/')
        idx = uri_parts.index("upload")
        session_id = uri_parts[idx + 1]
        chunk_id = int(uri_parts[idx + 2])
        
        print(f"[Consumer] Received I_4! Requesting chunk {chunk_id}")

        payload_dict = {
            "session_id": session_id,
            "chunk_id": chunk_id,
            "data": f"This is chunk {chunk_id} for session {session_id}"
        }
        
        data_payload = json.dumps(payload_dict).encode('utf-8')
        
        app.put_data(name, content=data_payload, freshness_period=1000)
        metrics["tx_d"] += 1  # 送信Data(D_4)
        print(f"[Consumer] Sent Data D_4 for chunk {chunk_id}")
    except Exception as e:
        print(f"[Consumer] Error in on_interest_i4: {e}")

async def start_upload(gateway_prefix, producer_prefix, session_id, chunk_size):
    print("[Consumer] Waiting 5 seconds for network convergence...")
    await asyncio.sleep(5)

    name = f"{gateway_prefix}/upload-request/{session_id}"

    # 【評価用】全体の処理時間を測るために start_time を埋め込む
    start_time = time.time()

    app_param = json.dumps({
        "consumer": CONSUMER_NAME,
        "producer": producer_prefix,
        "chunk_size": chunk_size,
        "start_time": start_time  # 追加
    }).encode()

    try:
        print(f"[Consumer] Sending I_1 for session {session_id}")
        metrics["tx_i"] += 1  # 送信Interest(I_1)
        data_name, meta, content = await app.express_interest(
            name, app_param=app_param, must_be_fresh=True, can_be_prefix=False, lifetime=1000)
        metrics["rx_d"] += 1  # 受信Data(D_1)
        print("[Consumer] Received Ack (D_1). Waiting for chunk requests...")
    except (InterestTimeout, InterestNack) as e:
        print(f"[Consumer] Failed to start upload: {e}")

    # しばらく待ってから最終メトリクスを表示
    await asyncio.sleep(15)
    print(f"\n=== [EVALUATION] Consumer Metrics ===")
    print(f"Total Packets Exchanged: {sum(metrics.values())} {metrics}")

if __name__ == '__main__':
    app.run_forever(after_start=start_upload("/gateway", "/producer", "session-12345", 5))
