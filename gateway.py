import asyncio
import json
import base64
from ndn.app import NDNApp
from ndn.types import InterestCanceled, InterestTimeout, InterestNack
from ndn.encoding import Component  # <--- 追加

app = NDNApp()
session_table = {}  # Session ID <-> Consumer Name
GATEWAY_NAME = "/gateway"
PRODUCER_PREFIX = "/producer"

def generate_keypair(): return "priv_g", "pub_g"
def derive_shared_key(priv, pub): return "shared_key"
def decrypt_name(encrypted_str, key):
    pad_len = (4 - len(encrypted_str) % 4) % 4
    pad = '=' * pad_len
    return base64.urlsafe_b64decode((encrypted_str + pad).encode()).decode()

@app.route(f"{GATEWAY_NAME}/upload-request")
def on_interest_i1(name, param, app_param):
    # 【変更】Component.to_str を使用
    session_id = Component.to_str(name[2])
    payload = json.loads(bytes(app_param).decode())
    consumer_name = payload["consumer"]
    chunk_size = payload["chunk_size"]

    session_table[session_id] = consumer_name
    s_g, p_g = generate_keypair()

    async def forward_to_producer():
        i2_name = f"{PRODUCER_PREFIX}/setup/{session_id}"
        i2_param = json.dumps({"gateway": GATEWAY_NAME, "chunk_size": chunk_size, "pub_key": p_g}).encode()
        
        try:
            d2_name, meta, d2_content = await app.express_interest(
                i2_name, app_param=i2_param, must_be_fresh=True, lifetime=4000)
            
            d2_payload = json.loads(bytes(d2_content).decode())
            p_p = d2_payload["pub_key"]
            session_key = derive_shared_key(s_g, p_p)
            print(f"[Gateway] Session established. Key: {session_key}")

            app.put_data(name, content=b"Ack", freshness_period=1000)
        except Exception as e:
            print(f"[Gateway] Failed to setup with producer: {e}")

    asyncio.create_task(forward_to_producer())

@app.route(f"{GATEWAY_NAME}/fetch")
def on_interest_i3(name, param, app_param):
    try:
        # 【変更】Component.to_str を使用
        encrypted_component = Component.to_str(name[2])
        print(f"[Gateway] Received I_3: {encrypted_component}")
        
        decrypted = decrypt_name(encrypted_component, "shared_key")
        session_id, chunk_id = decrypted.split("/")
        print(f"[Gateway] Decrypted I_3 -> session: {session_id}, chunk: {chunk_id}")
        
        consumer_name = session_table.get(session_id)
        if not consumer_name:
            print(f"[Gateway] Session {session_id} not found in table!")
            return

        async def fetch_from_consumer():
            i4_name = f"{consumer_name}/upload/{session_id}/{chunk_id}"
            print(f"[Gateway] Forwarding I_4 to Consumer: {i4_name}")
            try:
                d4_name, meta, d4_content = await app.express_interest(
                    i4_name, must_be_fresh=True, lifetime=2000)
                
                app.put_data(name, content=d4_content, freshness_period=1000)
                print(f"[Gateway] Proxied chunk {chunk_id} back to Producer")
            except Exception as e:
                print(f"[Gateway] Failed to fetch chunk from consumer: {e}")

        asyncio.create_task(fetch_from_consumer())
    except Exception as e:
        print(f"[Gateway] Error in on_interest_i3: {e}")

if __name__ == '__main__':
    app.run_forever()