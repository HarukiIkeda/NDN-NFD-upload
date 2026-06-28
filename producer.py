import asyncio
import json
import base64
import time
from ndn.app import NDNApp
from ndn.types import InterestTimeout, InterestNack, InterestCanceled
from ndn.encoding import Component, Name

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

app = NDNApp()
PRODUCER_NAME = "/producer"

# 【評価用】パケットカウンタ
metrics = {"rx_i": 0, "tx_i": 0, "tx_d": 0, "rx_d": 0}

def generate_keypair():
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_key, base64.b64encode(pub_bytes).decode('utf-8')

def derive_shared_key(priv_key, peer_pub_str):
    peer_pub_bytes = base64.b64decode(peer_pub_str)
    peer_pub_key = serialization.load_pem_public_key(peer_pub_bytes)
    shared_secret = priv_key.exchange(ec.ECDH(), peer_pub_key)
    return base64.urlsafe_b64encode(HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ndn-upload-protocol').derive(shared_secret))

def encrypt_name(plain_str, session_key):
    return Fernet(session_key).encrypt(plain_str.encode('utf-8')).decode('utf-8').rstrip('=')

@app.route(f"{PRODUCER_NAME}/setup")
def on_interest_i2(name, param, app_param):
    metrics["rx_i"] += 1
    print(f"[Producer] Received Interest I_2: {Name.to_str(name)}")
    uri_parts = Name.to_str(name).strip('/').split('/')
    session_id = uri_parts[uri_parts.index("setup") + 1]
    
    payload = json.loads(bytes(app_param).decode())
    p_g, gateway_name, chunk_size = payload["pub_key"], payload["gateway"], payload["chunk_size"]
    start_time = payload["start_time"]  # コンシューマーから渡された計測開始時刻

    s_p, p_p = generate_keypair()
    session_key = derive_shared_key(s_p, p_g)
    print(f"[Producer] Generated the session key for session {session_id}")
    
    app.put_data(name, content=json.dumps({"pub_key": p_p}).encode(), freshness_period=1000)
    metrics["tx_d"] += 1
    print(f"[Producer] Sent Data D_2 with a producer public key for session {session_id}: {Name.to_str(name)}")
    
    print(f"[Producer] Pipeline starting...")
    asyncio.create_task(fetch_chunks_pipeline(gateway_name, session_id, chunk_size, session_key, start_time))

async def fetch_chunks_pipeline(gateway_name, session_id, chunk_size, session_key, start_time):
    WINDOW_SIZE = 4
    semaphore = asyncio.Semaphore(WINDOW_SIZE)

    async def fetch_single_chunk(chunk_id):
        max_retries = 3
        async with semaphore:
            plain_name = f"{session_id}/{chunk_id}"
            i3_name = f"{gateway_name}/fetch/{encrypt_name(plain_name, session_key)}"
            
            for attempt in range(1, max_retries + 1):
                try:
                    metrics["tx_i"] += 1
                    print(f"[Producer] Sent Interest I_3 (Attempt {attempt}): {i3_name}")
                    d3_name, meta, d3_content = await app.express_interest(i3_name, must_be_fresh=True, lifetime=2000)
                    metrics["rx_d"] += 1
                    print(f"[Producer] Received Data D_3: {Name.to_str(d3_name)}")
                    return True
                except Exception as e:
                    print(f"[Producer] Chunk {chunk_id} Timeout/Error on attempt {attempt}")
            return False

    tasks = [fetch_single_chunk(i) for i in range(1, chunk_size + 1)]
    results = await asyncio.gather(*tasks)
    success_count = sum(1 for r in results if r)
    
    # 【評価用】最終メトリクスの計算と表示
    completion_time = time.time() - start_time
    
    print(f"\n=== [EVALUATION] Pipeline Complete ===")
    print(f"Chunks Received: {success_count}/{chunk_size}")
    print(f"Total Completion Time: {completion_time:.4f} seconds")
    print(f"Producer Metrics: Total {sum(metrics.values())} {metrics}")

if __name__ == '__main__':
    app.run_forever()