from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import os
from datetime import datetime
from passlib.apache import HtpasswdFile
import requests
import base64

app = FastAPI()
security = HTTPBasic()
# Registry 통신을 위한 인증 헤더 생성
def get_registry_auth_header():
    return {
        'Authorization': f'Basic {base64.b64encode(b"admin:adminpass").decode()}'
    }
# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

REGISTRY_URL = os.getenv('REGISTRY_URL', 'http://registry:5000')
HTPASSWD_PATH = os.getenv('AUTH_FILE', '/auth/htpasswd')

def init_db():
    conn = sqlite3.connect('/data/audit.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log
        (timestamp TEXT, user TEXT, action TEXT, repository TEXT, tag TEXT)
    ''')
    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()
    if not os.path.exists(HTPASSWD_PATH):
        ht = HtpasswdFile(HTPASSWD_PATH, new=True)
        ht.save()

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)
        if not ht.check_password(credentials.username, credentials.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credentials.username
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Basic"},
        )
@app.get("/api/images")
async def list_images(username: str = Depends(verify_credentials)):
    try:
        # Registry API 호출 시 인증 헤더 추가
        headers = get_registry_auth_header()
        
        # 카탈로그 조회
        response = requests.get(f"{REGISTRY_URL}/v2/_catalog", headers=headers)
        if response.status_code != 200:
            print(f"Catalog response: {response.status_code}, {response.text}")
            raise HTTPException(status_code=500, detail="Failed to fetch catalog from registry")
            
        repositories = response.json().get("repositories", [])
        images = []
        
        for repo in repositories:
            # 각 저장소의 태그 목록 조회
            tags_response = requests.get(
                f"{REGISTRY_URL}/v2/{repo}/tags/list",
                headers=headers
            )
            
            if tags_response.status_code == 200:
                tags_data = tags_response.json()
                tags = tags_data.get("tags", [])
                
                # 각 태그의 상세 정보 조회
                for tag in tags:
                    manifest_response = requests.get(
                        f"{REGISTRY_URL}/v2/{repo}/manifests/{tag}",
                        headers={
                            **headers,
                            'Accept': 'application/vnd.docker.distribution.manifest.v2+json'
                        }
                    )
                    
                    if manifest_response.status_code == 200:
                        manifest = manifest_response.json()
                        created_at = datetime.utcnow().isoformat()
                        
                        # config blob에서 생성 시간 조회 시도
                        try:
                            config_response = requests.get(
                                f"{REGISTRY_URL}/v2/{repo}/blobs/{manifest['config']['digest']}",
                                headers=headers
                            )
                            if config_response.status_code == 200:
                                config = config_response.json()
                                if 'created' in config:
                                    created_at = config['created']
                        except:
                            pass
                        
                        images.append({
                            "name": repo,
                            "tags": tags,
                            "lastUpdated": created_at,
                            "size": sum(layer['size'] for layer in manifest.get('layers', [])),
                            "digest": manifest_response.headers.get('Docker-Content-Digest', '')
                        })
                        break  # 하나의 태그 정보만 가져옴
        
        return {"images": images}
    except Exception as e:
        print(f"Error in list_images: {str(e)}")
@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/users")
async def list_users(username: str = Depends(verify_credentials)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)
        return {"users": list(ht.users())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/users")
async def create_user(
    username: str,
    password: str,
    current_user: str = Depends(verify_credentials)
):
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)
        ht.set_password(username, password)
        ht.save()
        return {"message": f"User {username} created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/users/{username}")
async def delete_user(
    username: str,
    current_user: str = Depends(verify_credentials)
):
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)
        if username == "admin":
            raise HTTPException(status_code=400, detail="Cannot delete admin user")
        if username in ht.users():
            ht.delete(username)
            ht.save()
            return {"message": f"User {username} deleted successfully"}
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit")
async def get_audit_logs(
    user: str = None,
    image: str = None,
    username: str = Depends(verify_credentials)
):
    try:
        conn = sqlite3.connect('/data/audit.db')
        c = conn.cursor()
        
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        
        if user:
            query += " AND user = ?"
            params.append(user)
        if image:
            query += " AND repository = ?"
            params.append(image)
            
        c.execute(query, params)
        logs = c.fetchall()
        conn.close()
        
        return {
            "logs": [
                {
                    "timestamp": log[0],
                    "user": log[1],
                    "action": log[2],
                    "repository": log[3],
                    "tag": log[4]
                }
                for log in logs
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
