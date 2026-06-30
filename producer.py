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

# --- ECDH 鍵共有ロジック ---
def generate_keypair():
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_key, base64.b64encode(pub_bytes).decode('utf-8')

def derive_shared_key(priv_key, peer_pub_str):
    peer_pub_bytes = base64.b64decode(peer_pub_str)
    peer_pub_key = serialization.load_pem_public_key(peer_pub_bytes)
    shared_secret = priv_key.exchange(ec.ECDH(), peer_pub_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ndn-upload-protocol'
    ).derive(shared_secret)
    return base64.urlsafe_b64encode(derived_key)

def encrypt_name(plain_str, session_key):
    # 導出したセッション鍵をセットしたFernet（暗号化マシン）を準備します。
    f = Fernet(session_key)
    # 平文の文字列(例: "session-12345/1")をバイト列にし、暗号化します。
    encrypted_bytes = f.encrypt(plain_str.encode('utf-8'))
    # 暗号化されたバイト列を文字列(Base64URL)に変換し、末尾のパディング( "=" )を削除。
    # NDNのURI仕様において "=" が入るとパースエラーになるため削除する
    return encrypted_bytes.decode('utf-8').rstrip('=')

@app.route(f"{PRODUCER_NAME}/setup")
def on_interest_i2(name, param, app_param):
    metrics["rx_i"] += 1
    # キーワード「setup」を基準に session_id を取得
    uri_parts = Name.to_str(name).strip('/').split('/')
    idx = uri_parts.index("setup")
    session_id = uri_parts[idx + 1]

    payload = json.loads(bytes(app_param).decode())
    p_g = payload["pub_key"]
    gateway_name = payload["gateway"]
    chunk_size = payload["chunk_size"]
    start_time = payload["start_time"]  # コンシューマーから渡された計測開始時刻

    s_p, p_p = generate_keypair()
    session_key = derive_shared_key(s_p, p_g)
    print(f"[Producer] Generated the session key for session {session_id}")
    
    d2_payload = json.dumps({"pub_key": p_p}).encode()
    app.put_data(name, content=d2_payload, freshness_period=1000)
    metrics["tx_d"] += 1
    print(f"[Producer] Transmitting producer public key for session {session_id}")

    asyncio.create_task(fetch_chunks_pipeline(gateway_name, session_id, chunk_size, session_key, start_time))

async def fetch_chunks_pipeline(gateway_name, session_id, chunk_size, session_key, start_time):
    WINDOW_SIZE = 4
    semaphore = asyncio.Semaphore(WINDOW_SIZE) #指定した数以上のタスクが同時に実行されるのを防ぐ

    async def fetch_single_chunk(chunk_id):
        max_retries = 3  # 最大3回まで再送を試みる

        async with semaphore:
            plain_name = f"{session_id}/{chunk_id}"
            # AESで暗号化する
            encrypted_name = encrypt_name(plain_name, session_key)
            i3_name = f"{gateway_name}/fetch/{encrypted_name}"
            
            # パケット送信全体をリトライループで囲む
            for attempt in range(1, max_retries + 1):
                try:
                    metrics["tx_i"] += 1
                    print(f"[Producer] Expressing Interest for chunk {chunk_id} (Attempt {attempt}/{max_retries})")
                    
                    d3_name, meta, d3_content = await app.express_interest(
                        i3_name, must_be_fresh=True, lifetime=1000)
                    metrics["rx_d"] += 1
                    
                    d3_payload = json.loads(bytes(d3_content).decode('utf-8'))
                    actual_data = d3_payload["data"]
                    
                    print(f"[Producer] Received Data for chunk {chunk_id}: {actual_data}")
                    return True
                
                except InterestTimeout:
                    print(f"[Producer] Failed to fetch chunk {chunk_id}: Timeout on attempt {attempt}")
                except InterestNack as nack:
                    print(f"[Producer] Failed to fetch chunk {chunk_id}: Nack ({nack.reason}) on attempt {attempt}")
                except Exception as e:
                    print(f"[Producer] Failed to fetch chunk {chunk_id}: {type(e).__name__} on attempt {attempt}")
            
            print(f"[Producer] Gave up on chunk {chunk_id} after {max_retries} attempts.")
            return False

    print(f"[Producer] Starting pipeline fetch for {chunk_size} chunks (Window: {WINDOW_SIZE})")
    tasks = [fetch_single_chunk(i) for i in range(1, chunk_size + 1)]
    results = await asyncio.gather(*tasks)
    success_count = sum(1 for r in results if r)

    # 【評価用】最終メトリクスの計算と表示
    completion_time = time.time() - start_time

    # print(f"[Producer] Pipeline fetch complete. Successfully received {success_count}/{chunk_size} chunks.")

    print(f"\n=== [EVALUATION] Pipeline Complete ===")
    print(f"Chunks Received: {success_count}/{chunk_size}")
    print(f"Total Completion Time: {completion_time:.4f} seconds")
    print(f"Producer Metrics: Total {sum(metrics.values())} {metrics}")

if __name__ == '__main__':
    app.run_forever()