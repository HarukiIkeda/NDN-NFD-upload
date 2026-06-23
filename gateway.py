import asyncio
import json
import base64
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
    # 同じセッション鍵をセットしたFernetを準備します
    f = Fernet(session_key)
    # 暗号化時に削除した末尾の "=" を計算して付け直します。
    # Base64は必ず4文字区切りになる性質を利用し、足りない文字数分だけ "=" を補完します。
    pad_len = (4 - len(encrypted_str) % 4) % 4
    padded_str = encrypted_str + ('=' * pad_len)
    # 補完した文字列をバイト列にして復号(decrypt)し、元の平文文字列に戻して返します。
    return f.decrypt(padded_str.encode('utf-8')).decode('utf-8')

@app.route(f"{GATEWAY_NAME}/upload-request")
def on_interest_i1(name, param, app_param):
    # キーワード「upload-request」を基準に session_id を取得
    uri_parts = Name.to_str(name).strip('/').split('/')
    idx = uri_parts.index("upload-request")
    session_id = uri_parts[idx + 1]

    payload = json.loads(bytes(app_param).decode())
    consumer_name = payload["consumer"]
    chunk_size = payload["chunk_size"]

    producer_name = payload["producer"]

    session_table[session_id] = {"consumer": consumer_name, "key": None, "i1_name": name, "i3_names": {}}
    s_g, p_g = generate_keypair()

    async def forward_to_producer():
        i2_name = f"{producer_name}/setup/{session_id}"
        i2_param = json.dumps({"gateway": GATEWAY_NAME, "chunk_size": chunk_size, "pub_key": p_g}).encode()
        
        try:
            print(f"[Gateway] Sending I_2 setup request to {producer_name}")
            d2_name, meta, d2_content = await app.express_interest(
                i2_name, app_param=i2_param, must_be_fresh=True, lifetime=4000)
            
            # 【変更】キーワード「setup」を基準に D_2 の名前から session_id を取得
            d2_uri_parts = Name.to_str(d2_name).strip('/').split('/')
            d2_idx = d2_uri_parts.index("setup")
            recv_session_id = d2_uri_parts[d2_idx + 1]

            d2_payload = json.loads(bytes(d2_content).decode())
            p_p = d2_payload["pub_key"]

            # 【重要】本物のECDHセッション鍵を導出し、テーブルに保存する。D_2から得たsession_idを使ってテーブルを参照し、鍵を保存
            session_key = derive_shared_key(s_g, p_p)
            session_table[recv_session_id]["key"] = session_key
            print(f"[Gateway] ECDH Session established. Key secured.")

            # 【追加】テーブルを参照し、D_1を返す対象となるI_1の名前を取り出す
            target_i1_name = session_table[recv_session_id]["i1_name"]

            app.put_data(target_i1_name, content=b"Ack", freshness_period=1000)
        except Exception as e:
            print(f"[Gateway] Failed to setup with producer: {e}")

    asyncio.create_task(forward_to_producer())

@app.route(f"{GATEWAY_NAME}/fetch")
def on_interest_i3(name, param, app_param):
    try:
        # キーワード「fetch」を基準に encrypted_component を取得
        uri_parts = Name.to_str(name).strip('/').split('/')
        idx = uri_parts.index("fetch")
        encrypted_component = uri_parts[idx + 1]

        print(f"[Gateway] Received I_3: {encrypted_component[:15]}...") # 長いのでログは省略表示
        
        # 【追加】I_3の復号と処理を非同期タスク化し、鍵の確立を待てるようにする
        async def process_i3():
            decrypted = None
            target_session_id = None
            
            # 競合(Race Condition)対策：最大2秒間（0.1秒×20回）鍵がテーブルに入るのを待つ
            for _ in range(20):
                for sid, data in session_table.items():
                    sess_key = data.get("key")
                    if not sess_key: continue
                    
                    try:
                        decrypted = decrypt_name(encrypted_component, sess_key)
                        target_session_id = sid
                        break
                    except Exception:
                        continue 
                
                if decrypted:
                    break
                
                # 鍵がまだテーブルにない、または復号できない場合は0.1秒待機してリトライ
                await asyncio.sleep(0.1)

            if not decrypted:
                print("[Gateway] Security Error: Decryption failed. No matching session key found!")
                return

            session_id, chunk_id = decrypted.split("/")
            
            if session_id != target_session_id:
                print("[Gateway] Security Error: Decrypted Session ID mismatch!")
                return
                
            print(f"[Gateway] Decrypted I_3 -> session: {session_id}, chunk: {chunk_id}")
            
            # D_3を正しく返すため、受信した I_3 の名前をチャンクIDごとにテーブルに記憶
            session_table[target_session_id]["i3_names"][chunk_id] = name
            
            consumer_name = session_table[target_session_id]["consumer"]

            i4_name = f"{consumer_name}/upload/{session_id}/{chunk_id}"
            print(f"[Gateway] Forwarding I_4 to Consumer: {i4_name}")
            try:
                d4_name, meta, d4_content = await app.express_interest(
                    i4_name, must_be_fresh=True, lifetime=2000)
                
                # 【変更】テーブルを参照し、対応する I_3 の名前を取り出して D_3 を送信
                target_i3_name = session_table[target_session_id]["i3_names"][chunk_id]
                app.put_data(target_i3_name, content=d4_content, freshness_period=1000)
                
                # 送信完了した名前はテーブルから削除（メモリのクリーンアップ）
                del session_table[target_session_id]["i3_names"][chunk_id]
                
                print(f"[Gateway] Proxied chunk {chunk_id} back to Producer")
            except Exception as e:
                print(f"[Gateway] Failed to fetch chunk from consumer: {e}")

        # I_3の処理（鍵待ち＋転送）をバックグラウンドで開始
        asyncio.create_task(process_i3())
    except Exception as e:
        print(f"[Gateway] Error in on_interest_i3: {e}")

if __name__ == '__main__':
    app.run_forever()