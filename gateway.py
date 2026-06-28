import asyncio
import json
import base64
import random
from ndn.app import NDNApp
from ndn.types import InterestCanceled, InterestTimeout, InterestNack
from ndn.encoding import Component, Name

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

app = NDNApp()
session_table = {}  
GATEWAY_NAME = "/gateway"

# 【評価用】パケットロス率 (RICE論文の Packet Loss Ratio 0.0 ~ 0.1 のシミュレーション用)
DROP_RATE = 0.0

# 【評価用】メトリクストラッカー
metrics = {"rx_i": 0, "tx_i": 0, "tx_d": 0, "rx_d": 0}
state_metrics = {"current_pending_chunks": 0, "max_pending_chunks": 0}

def update_state_metrics():
    # テーブルに保持されている現在処理中(I_4送信中)のチャンク数を計算
    current_size = sum(len(data.get("i3_names", {})) for data in session_table.values())
    state_metrics["current_pending_chunks"] = current_size
    if current_size > state_metrics["max_pending_chunks"]:
        state_metrics["max_pending_chunks"] = current_size

def generate_keypair():
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_key, base64.b64encode(pub_bytes).decode('utf-8')

def derive_shared_key(priv_key, peer_pub_str):
    peer_pub_bytes = base64.b64decode(peer_pub_str)
    peer_pub_key = serialization.load_pem_public_key(peer_pub_bytes)
    shared_secret = priv_key.exchange(ec.ECDH(), peer_pub_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ndn-upload-protocol').derive(shared_secret)
    return base64.urlsafe_b64encode(derived_key)

def decrypt_name(encrypted_str, session_key):
    f = Fernet(session_key)
    pad_len = (4 - len(encrypted_str) % 4) % 4
    return f.decrypt((encrypted_str + ('=' * pad_len)).encode('utf-8')).decode('utf-8')

@app.route(f"{GATEWAY_NAME}/upload-request")
def on_interest_i1(name, param, app_param):
    if random.random() < DROP_RATE:
        print("[Gateway EVAL] Dropped I_1 to simulate packet loss")
        return
    metrics["rx_i"] += 1
    print(f"[Gateway] Received Interest I_1: {Name.to_str(name)}")

    uri_parts = Name.to_str(name).strip('/').split('/')
    session_id = uri_parts[uri_parts.index("upload-request") + 1]
    payload = json.loads(bytes(app_param).decode())
    
    session_table[session_id] = {
        "consumer": payload["consumer"], 
        "key": None, 
        "i1_name": name, 
        "i3_names": {},
        "completed_chunks": set()
    }
    s_g, p_g = generate_keypair()

    async def forward_to_producer():
        # 【評価用】start_time を I_2 へ引き継ぐ
        i2_param = json.dumps({
            "gateway": GATEWAY_NAME, 
            "chunk_size": payload["chunk_size"], 
            "pub_key": p_g,
            "start_time": payload["start_time"]
        }).encode()
        i2_name = f'{payload["producer"]}/setup/{session_id}'
        
        try:
            metrics["tx_i"] += 1
            print(f"[Gateway] Sent Interest I_2: {i2_name}")
            d2_name, meta, d2_content = await app.express_interest(i2_name, app_param=i2_param, must_be_fresh=True, lifetime=4000)
            metrics["rx_d"] += 1
            print(f"[Gateway] Received Data D_2: {Name.to_str(d2_name)}")
            
            d2_uri_parts = Name.to_str(d2_name).strip('/').split('/')
            recv_session_id = d2_uri_parts[d2_uri_parts.index("setup") + 1]
            
            p_p = json.loads(bytes(d2_content).decode())["pub_key"]
            session_table[recv_session_id]["key"] = derive_shared_key(s_g, p_p)
            print(f"[Gateway] Session established. Key secured.")

            app.put_data(session_table[recv_session_id]["i1_name"], content=b"Ack", freshness_period=1000)
            metrics["tx_d"] += 1
            print(f"[Gateway] Sent Data D_1: {Name.to_str(session_table[recv_session_id]['i1_name'])}")
        except Exception as e:
            print(f"[Gateway] Failed to setup with producer: {e}")

    asyncio.create_task(forward_to_producer())

@app.route(f"{GATEWAY_NAME}/fetch")
def on_interest_i3(name, param, app_param):
    if random.random() < DROP_RATE:
        print("[Gateway EVAL] Dropped I_3 to simulate packet loss")
        return
    metrics["rx_i"] += 1
    print(f"[Gateway] Received Interest I_3: {Name.to_str(name)}")

    try:
        uri_parts = Name.to_str(name).strip('/').split('/')
        encrypted_component = uri_parts[uri_parts.index("fetch") + 1]
        
        async def process_i3():
            decrypted = target_session_id = None
            for sid, data in session_table.items():
                sess_key = data.get("key")
                if not sess_key: continue
                try:
                    decrypted = decrypt_name(encrypted_component, sess_key)
                    target_session_id = sid
                    break
                except Exception: continue 

            if not decrypted: return
            session_id, chunk_id = decrypted.split("/")
            
            if chunk_id in session_table[target_session_id]["completed_chunks"]: return
            if chunk_id in session_table[target_session_id]["i3_names"]:
                session_table[target_session_id]["i3_names"][chunk_id] = name
                return
            
            session_table[target_session_id]["i3_names"][chunk_id] = name
            update_state_metrics() # ステート増加
            
            i4_name = f'{session_table[target_session_id]["consumer"]}/upload/{session_id}/{chunk_id}'
            try:
                metrics["tx_i"] += 1
                print(f"[Gateway] Sent Interest I_4: {i4_name}")
                d4_name, meta, d4_content = await app.express_interest(i4_name, must_be_fresh=True, lifetime=2000)
                metrics["rx_d"] += 1
                print(f"[Gateway] Received Data D_4: {Name.to_str(d4_name)}")
                
                d4_payload = json.loads(bytes(d4_content).decode('utf-8'))
                recv_session_id, recv_chunk_id = d4_payload["session_id"], str(d4_payload["chunk_id"])
                
                target_i3_name = session_table[recv_session_id]["i3_names"][recv_chunk_id]
                app.put_data(target_i3_name, content=d4_content, freshness_period=1000)
                metrics["tx_d"] += 1
                print(f"[Gateway] Sent Data D_3: {Name.to_str(target_i3_name)}")
                
                del session_table[recv_session_id]["i3_names"][recv_chunk_id]
                session_table[recv_session_id]["completed_chunks"].add(recv_chunk_id)
                update_state_metrics() # ステート減少
                
            except Exception as e:
                if chunk_id in session_table[target_session_id]["i3_names"]:
                    del session_table[target_session_id]["i3_names"][chunk_id]
                    update_state_metrics()

        asyncio.create_task(process_i3())
    except Exception as e: print(f"[Gateway] Error: {e}")

async def print_metrics_periodically():
    await asyncio.sleep(15)
    print(f"\n=== [EVALUATION] Gateway Metrics ===")
    print(f"Total Packets Exchanged: {sum(metrics.values())} {metrics}")
    print(f"Max State Size (Pending Chunks): {state_metrics['max_pending_chunks']}")

if __name__ == '__main__':
    # 警告を解消するため、NDNAppのafter_startを使ってタスクを登録
    app.run_forever(after_start=print_metrics_periodically())