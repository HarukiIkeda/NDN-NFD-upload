import asyncio
import json
import base64
import random
import time
from datetime import datetime
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

# 【評価用】パケットロス率 
DROP_RATE = 0.0

# 【評価用】メトリクストラッカー
metrics = {"rx_i": 0, "tx_i": 0, "tx_d": 0, "rx_d": 0}
state_metrics = {"current_pending_chunks": 0, "max_pending_chunks": 0}

def log_print(msg):
    t = datetime.now().strftime('%H:%M:%S.%f')[:-1]
    print(f"[{t}] {msg}", flush=True)

def update_state_metrics():
    # テーブルに保持されている現在処理中(I_4送信中)のチャンク数を計算
    current_size = sum(len(data.get("i3_names", {})) for data in session_table.values())
    state_metrics["current_pending_chunks"] = current_size
    if current_size > state_metrics["max_pending_chunks"]:
        state_metrics["max_pending_chunks"] = current_size

# --- ECDH 鍵共有ロジック ---
def generate_keypair():
    # 楕円曲線(SECP256R1)を用いて秘密鍵と公開鍵を生成
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key() # 秘密鍵から、相手に渡すための「公開鍵」を数学的に計算して生成。
    
    # 公開鍵をPEM形式の文字列に変換してJSONで送れるようにする
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # 秘密鍵のオブジェクトと、Base64文字列に変換した公開鍵のセットを返す。
    return priv_key, base64.b64encode(pub_bytes).decode('utf-8')

def derive_shared_key(priv_key, peer_pub_str):
    # 相手から受け取った公開鍵文字列(Base64)をバイト列に戻す
    peer_pub_bytes = base64.b64decode(peer_pub_str)
    # バイト列を、Pythonで計算可能な「公開鍵オブジェクト」に復元
    peer_pub_key = serialization.load_pem_public_key(peer_pub_bytes)
    
    # ECDHで共有シークレットを導出
    shared_secret = priv_key.exchange(ec.ECDH(), peer_pub_key)
    
    # HKDFを使用して、Fernet(AES)用の32バイトの安全な共通鍵を生成。共有シークレットはそのままではパスワードとして使いづらいため、HKDFに通す。
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ndn-upload-protocol'
    ).derive(shared_secret)
    
    return base64.urlsafe_b64encode(derived_key)

def decrypt_name(encrypted_str, session_key):
    # 同じセッション鍵をセットしたFernetを準備
    f = Fernet(session_key)
    # 暗号化時に削除した末尾の "=" を計算して付け直す。
    # Base64は必ず4文字区切りになる性質を利用し、足りない文字数分だけ "=" を補完。
    pad_len = (4 - len(encrypted_str) % 4) % 4
    padded_str = encrypted_str + ('=' * pad_len)
    # 補完した文字列をバイト列にして復号(decrypt)し、元の平文文字列に戻して返す。
    return f.decrypt(padded_str.encode('utf-8')).decode('utf-8')

@app.route(f"{GATEWAY_NAME}/upload-request")
def on_interest_i1(name, param, app_param):

    if random.random() < DROP_RATE:
        log_print("[Gateway EVAL] Dropped I_1 to simulate packet loss")
        return
    metrics["rx_i"] += 1

    uri_parts = Name.to_str(name).strip('/').split('/')
    session_id = uri_parts[uri_parts.index("upload-request") + 1]
    payload = json.loads(bytes(app_param).decode())

    log_print(f"[Gateway] Received I_1 for session {session_id} from Consumer {payload['consumer']}")

    session_table[session_id] = {
        "consumer": payload["consumer"], 
        "key": None, 
        "i1_name": name, 
        "i3_names": {},
        "completed_chunks": set()
    }
    s_g, p_g = generate_keypair()

    async def forward_to_producer():

        i2_param = json.dumps({
            "gateway": GATEWAY_NAME, 
            "chunk_size": payload["chunk_size"], 
            "pub_key": p_g,
            "start_time": payload["start_time"]
        }).encode()
        i2_name = f'{payload["producer"]}/setup/{session_id}'
        
        try:
            metrics["tx_i"] += 1
            # print(f"[Gateway] Sending I_2 setup request to {payload["producer"]}")
            d2_name, meta, d2_content = await app.express_interest(
                i2_name, app_param=i2_param, must_be_fresh=True, lifetime=1000)
            metrics["rx_d"] += 1
            # 「setup」を基準に D_2 の名前から session_id を取得
            d2_uri_parts = Name.to_str(d2_name).strip('/').split('/')
            # d2_idx = d2_uri_parts.index("setup")
            # recv_session_id = d2_uri_parts[d2_idx + 1]
            recv_session_id = d2_uri_parts[d2_uri_parts.index("setup") + 1]

            log_print(f"[Gateway] D_2 received from {payload['producer']}")

            p_p = json.loads(bytes(d2_content).decode())["pub_key"]

            # ECDHセッション鍵を導出し、テーブルに保存する。D_2から得たsession_idを使ってテーブルを参照し、keyにセッション鍵を保存
            session_key = derive_shared_key(s_g, p_p)
            session_table[recv_session_id]["key"] = session_key 
            log_print(f"[Gateway] Session established. Key secured.")

            # テーブルを参照し、D_1を返す対象となるI_1の名前を取り出す
            target_i1_name = session_table[recv_session_id]["i1_name"]

            log_print(f"[Gateway] Sending Ack (D_1) back to Consumer")
            app.put_data(target_i1_name, content=b"Ack", freshness_period=1000)
            metrics["tx_d"] += 1
        except Exception as e:
            log_print(f"[Gateway] Failed to setup with producer: {e}")

    asyncio.create_task(forward_to_producer()) # I_1の受信処理をブロックしないよう、プロデューサーとの通信をバックグラウンドタスクとして実行

@app.route(f"{GATEWAY_NAME}/fetch")
def on_interest_i3(name, param, app_param):

    if random.random() < DROP_RATE:
        log_print("[Gateway EVAL] Dropped I_3 to simulate packet loss")
        return
    metrics["rx_i"] += 1

    try:
        # 「fetch」を基準に encrypted_component を取得
        uri_parts = Name.to_str(name).strip('/').split('/')
        idx = uri_parts.index("fetch")
        encrypted_component = uri_parts[idx + 1]

        log_print(f"[Gateway] Received I_3: {encrypted_component[:15]}...") # 長いのでログは省略表示
        
        # I_3の復号と処理を非同期タスク化し、鍵の確立を待てるようにする
        async def process_i3():
            decrypted = target_session_id = None
            
            for sid, data in session_table.items(): #sid: session_id, data: {"consumer": consumer_name, "key": session_key, "i1_name": name, "i3_names": {}}
                sess_key = data.get("key") # セッション鍵取り出す
                if not sess_key: continue
                    
                try:
                    decrypted = decrypt_name(encrypted_component, sess_key)
                    target_session_id = sid
                    break
                except Exception:
                    continue 

            if not decrypted:
                log_print("[Gateway] Security Error: Decryption failed. Dropped I_3.")
                return

            session_id, chunk_id = decrypted.split("/")
            
            if session_id != target_session_id: # セッションIDが一致しない場合はセキュリティ上の問題として処理を中断
                log_print("[Gateway] Security Error: Decrypted Session ID mismatch!")
                return
                
            log_print(f"[Gateway] Decrypted I_3 -> session: {session_id}, chunk: {chunk_id}")
            
            # すでに完了済みのチャンクかチェック（無視する）
            if chunk_id in session_table[target_session_id]["completed_chunks"]:
                log_print(f"[Gateway] Chunk {chunk_id} is already completed. Ignoring retransmitted I_3.")
                return

            # すでに処理中（I_4送信済み）のチャンクかチェック
            if chunk_id in session_table[target_session_id]["i3_names"]:
                log_print(f"[Gateway] I_3 for chunk {chunk_id} is already in progress. Updating pending name and skipping I_4.")
                # 重複してI_4は送らないが、宛先名は「最新の再送パケット(I_3)」に更新しておく
                session_table[target_session_id]["i3_names"][chunk_id] = name
                return
            
            # 初回のみ名前を登録し、I_4の送信へ進む
            session_table[target_session_id]["i3_names"][chunk_id] = name

            update_state_metrics() # ステート増加
            
            consumer_name = session_table[target_session_id]["consumer"]

            i4_name = f"{consumer_name}/upload/{session_id}/{chunk_id}"
            log_print(f"[Gateway] Forwarding I_4 to Consumer: {i4_name}")

            try:
                metrics["tx_i"] += 1
                d4_name, meta, d4_content = await app.express_interest(
                    i4_name, must_be_fresh=True, lifetime=1000)
                metrics["rx_d"] += 1
                
                d4_payload = json.loads(bytes(d4_content).decode('utf-8'))
                recv_session_id = d4_payload["session_id"]
                recv_chunk_id = str(d4_payload["chunk_id"])

                target_i3_name = session_table[recv_session_id]["i3_names"][recv_chunk_id]

                log_print(f"[Gateway] Proxied chunk {recv_chunk_id} back to Producer")
                app.put_data(target_i3_name, content=d4_content, freshness_period=1000)
                metrics["tx_d"] += 1

                # 送信完了した名前はテーブルから削除（メモリのクリーンアップ）
                del session_table[recv_session_id]["i3_names"][recv_chunk_id]
                session_table[recv_session_id]["completed_chunks"].add(recv_chunk_id)
                update_state_metrics() # ステート減少

            except Exception as e:
                log_print(f"[Gateway] Failed to fetch chunk from consumer: {e}")
                # I_4の取得に失敗（タイムアウト等）した場合は、次回のI_3再送時にI_4を送れるよう履歴を消す
                if chunk_id in session_table[target_session_id]["i3_names"]:
                    del session_table[target_session_id]["i3_names"][chunk_id]
                    update_state_metrics()

        # I_3の処理（鍵待ち＋転送）をバックグラウンドで開始
        asyncio.create_task(process_i3())
    except Exception as e:
        log_print(f"[Gateway] Error in on_interest_i3: {e}")

async def print_metrics_periodically():
    await asyncio.sleep(15)
    print(f"\n=== [EVALUATION] Gateway Metrics ===")
    print(f"Total Packets Exchanged: {sum(metrics.values())} {metrics}")
    print(f"Max State Size (Pending Chunks): {state_metrics['max_pending_chunks']}")

if __name__ == '__main__':
    # asyncio.get_event_loop().create_task(print_metrics_periodically())
    # app.run_forever()
    # 警告を解消するため、NDNAppのafter_startを使ってタスクを登録
    app.run_forever(after_start=print_metrics_periodically())