import asyncio
import json
import base64
from ndn.app import NDNApp
from ndn.types import InterestTimeout, InterestNack, InterestCanceled
from ndn.encoding import Component  # <--- 追加

app = NDNApp()
PRODUCER_NAME = "/producer"

def generate_keypair(): return "priv_p", "pub_p"
def derive_shared_key(priv, pub): return "shared_key"
def encrypt_name(plain_str, key): return base64.urlsafe_b64encode(plain_str.encode()).decode().rstrip('=')

@app.route(f"{PRODUCER_NAME}/setup")
def on_interest_i2(name, param, app_param):
    # 【変更】Component.to_str を使用
    session_id = Component.to_str(name[2])
    payload = json.loads(bytes(app_param).decode())
    p_g = payload["pub_key"]
    gateway_name = payload["gateway"]
    chunk_size = payload["chunk_size"]

    s_p, p_p = generate_keypair()
    session_key = derive_shared_key(s_p, p_g)
    
    d2_payload = json.dumps({"pub_key": p_p}).encode()
    app.put_data(name, content=d2_payload, freshness_period=1000)
    print(f"[Producer] Setup complete for session {session_id}")

    asyncio.create_task(fetch_chunks_pipeline(gateway_name, session_id, chunk_size, session_key))

async def fetch_chunks_pipeline(gateway_name, session_id, chunk_size, session_key):
    WINDOW_SIZE = 4
    semaphore = asyncio.Semaphore(WINDOW_SIZE)

    async def fetch_single_chunk(chunk_id):
        async with semaphore:
            plain_name = f"{session_id}/{chunk_id}"
            encrypted_name = encrypt_name(plain_name, session_key)
            i3_name = f"{gateway_name}/fetch/{encrypted_name}"
            
            try:
                print(f"[Producer] Expressing Interest for chunk {chunk_id}: {i3_name}")
                d3_name, meta, d3_content = await app.express_interest(
                    i3_name, must_be_fresh=True, lifetime=4000)
                
                print(f"[Producer] Received Data for chunk {chunk_id}: {bytes(d3_content).decode()}")
                return True
            except InterestTimeout:
                print(f"[Producer] Failed to fetch chunk {chunk_id}: Timeout")
                return False
            except InterestNack as nack:
                print(f"[Producer] Failed to fetch chunk {chunk_id}: Nack ({nack.reason})")
                return False
            except Exception as e:
                print(f"[Producer] Failed to fetch chunk {chunk_id}: {type(e).__name__}")
                return False

    print(f"[Producer] Starting pipeline fetch for {chunk_size} chunks (Window: {WINDOW_SIZE})")
    tasks = [fetch_single_chunk(i) for i in range(1, chunk_size + 1)]
    results = await asyncio.gather(*tasks)
    success_count = sum(1 for r in results if r)
    print(f"[Producer] Pipeline fetch complete. Successfully received {success_count}/{chunk_size} chunks.")

if __name__ == '__main__':
    app.run_forever()