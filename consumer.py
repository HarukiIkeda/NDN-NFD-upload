import asyncio
import json
from ndn.app import NDNApp
from ndn.types import InterestCanceled, InterestTimeout, InterestNack, ValidationFailure
from ndn.encoding import Component  # <--- 追加

app = NDNApp()
CONSUMER_NAME = "/local/consumer1"

@app.route(f"{CONSUMER_NAME}/upload")
def on_interest_i4(name, param, app_param):
    try:
        # 【変更】Component.to_str を使って純粋な文字列を取得
        session_id = Component.to_str(name[3])
        chunk_id = int(Component.to_str(name[4]))
        print(f"[Consumer] Received I_4! Requesting chunk {chunk_id}")
        
        data_payload = f"This is chunk {chunk_id} for session {session_id}".encode()
        
        app.put_data(name, content=data_payload, freshness_period=1000)
        print(f"[Consumer] Sent Data D_4 for chunk {chunk_id}")
    except Exception as e:
        print(f"[Consumer] Error in on_interest_i4: {e}")

async def start_upload(gateway_prefix, session_id, chunk_size):
    print("[Consumer] Waiting 5 seconds for network convergence...")
    await asyncio.sleep(5)

    name = f"{gateway_prefix}/upload-request/{session_id}"
    app_param = json.dumps({
        "consumer": CONSUMER_NAME,
        "chunk_size": chunk_size
    }).encode()

    try:
        print(f"[Consumer] Sending I_1 for session {session_id}")
        data_name, meta, content = await app.express_interest(
            name, app_param=app_param, must_be_fresh=True, can_be_prefix=False, lifetime=4000)
        print("[Consumer] Received Ack (D_1). Waiting for chunk requests...")
    except (InterestTimeout, InterestNack) as e:
        print(f"[Consumer] Failed to start upload: {e}")

if __name__ == '__main__':
    app.run_forever(after_start=start_upload("/gateway", "session-12345", 5))