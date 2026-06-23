import asyncio
import json
import base64
from ndn.app import NDNApp
from ndn.types import InterestTimeout, InterestNack, InterestCanceled
from ndn.encoding import Component  # <--- 追加
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

app = NDNApp()
PRODUCER_NAME = "/producer"

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
    session_id = Component.to_str(name[2])
    payload = json.loads(bytes(app_param).decode())
    p_g = payload["pub_key"]
    gateway_name = payload["gateway"]
    chunk_size = payload["chunk_size"]

    s_p, p_p = generate_keypair()
    session_key = derive_shared_key(s_p, p_g)
    
    d2_payload = json.dumps({"pub_key": p_p}).encode()
    app.put_data(name, content=d2_payload, freshness_period=1000)
    print(f"[Producer] ECDH Setup complete for session {session_id}")

    asyncio.create_task(fetch_chunks_pipeline(gateway_name, session_id, chunk_size, session_key))

async def fetch_chunks_pipeline(gateway_name, session_id, chunk_size, session_key):
    WINDOW_SIZE = 4
    semaphore = asyncio.Semaphore(WINDOW_SIZE) #指定した数以上のタスクが同時に実行されるのを防ぐ、交通整理のための仕組み

    async def fetch_single_chunk(chunk_id):
        async with semaphore:
            plain_name = f"{session_id}/{chunk_id}"
            # 【重要】本物のAESで暗号化する
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