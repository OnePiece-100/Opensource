from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import sqlite3
import os
import json
import hashlib
import uuid
from datetime import datetime
from typing import Optional, List
from passlib.apache import HtpasswdFile
import requests
import base64

# FastAPI 애플리케이션 생성
app = FastAPI(title="Docker Registry Management API", version="1.0.0")

# HTTP Basic 인증을 위한 보안 객체 생성
security = HTTPBasic()

# Pydantic 모델 정의
class UserCreate(BaseModel):
    username: str
    password: str

class ImageFilter(BaseModel):
    name: Optional[str] = None
    tag: Optional[str] = None

# Registry 통신을 위한 인증 헤더 생성 함수
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

# 환경변수 설정
REGISTRY_URL = os.getenv('REGISTRY_URL', 'http://registry:5000')
HTPASSWD_PATH = os.getenv('AUTH_FILE', '/auth/htpasswd')

# SQLite 데이터베이스 초기화 함수
def init_db():
    conn = sqlite3.connect('/data/audit.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         timestamp TEXT NOT NULL,
         user TEXT NOT NULL,
         action TEXT NOT NULL,
         repository TEXT,
         tag TEXT,
         details TEXT)
    ''')
    conn.commit()
    conn.close()

# Audit 로그 기록 함수
def log_audit(user: str, action: str, repository: str = None, tag: str = None, details: str = None):
    try:
        conn = sqlite3.connect('/data/audit.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO audit_log (timestamp, user, action, repository, tag, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (datetime.utcnow().isoformat(), user, action, repository, tag, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log audit: {e}")

# FastAPI 시작 이벤트
@app.on_event("startup")
async def startup_event():
    init_db()
    # 인증 파일 및 디렉토리 생성
    auth_dir = os.path.dirname(HTPASSWD_PATH)
    if not os.path.exists(auth_dir):
        os.makedirs(auth_dir, exist_ok=True)
    
    if not os.path.exists(HTPASSWD_PATH):
        ht = HtpasswdFile(HTPASSWD_PATH, new=True)
        ht.set_password("admin", "adminpass")  # 기본 관리자 계정
        ht.save()

# 사용자 인증 검증 함수
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

# ============== Docker Registry v2 API 구현 ==============

# 1. API v2 지원 여부 확인
@app.get("/v2/")
async def check_api_v2():
    """Docker Registry API v2 지원 확인"""
    return Response(
        content="",
        status_code=200,
        headers={
            "Docker-Distribution-API-Version": "registry/2.0",
            "Content-Length": "0"
        }
    )

# 2. Manifest 조회
@app.get("/v2/{name:path}/manifests/{reference}")
async def get_manifest(name: str, reference: str, request: Request):
    """이미지 Manifest 조회"""
    try:
        headers = get_registry_auth_header()
        accept_header = request.headers.get("accept", "application/vnd.docker.distribution.manifest.v2+json")
        headers["Accept"] = accept_header
        
        response = requests.get(
            f"{REGISTRY_URL}/v2/{name}/manifests/{reference}",
            headers=headers
        )
        
        if response.status_code == 200:
            # Audit 로그 기록
            log_audit("system", "MANIFEST_GET", name, reference)
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        else:
            raise HTTPException(status_code=response.status_code, detail=response.text)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 3. Manifest 업로드
@app.put("/v2/{name:path}/manifests/{reference}")
async def put_manifest(name: str, reference: str, request: Request, username: str = Depends(verify_credentials)):
    """이미지 Manifest 업로드"""
    try:
        headers = get_registry_auth_header()
        content_type = request.headers.get("content-type", "application/vnd.docker.distribution.manifest.v2+json")
        headers["Content-Type"] = content_type
        
        body = await request.body()
        
        response = requests.put(
            f"{REGISTRY_URL}/v2/{name}/manifests/{reference}",
            headers=headers,
            data=body
        )
        
        if response.status_code in [201, 202]:
            # Audit 로그 기록
            log_audit(username, "MANIFEST_PUT", name, reference, f"Size: {len(body)} bytes")
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        else:
            raise HTTPException(status_code=response.status_code, detail=response.text)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 4. Blob 존재 확인 (HEAD)
@app.head("/v2/{name:path}/blobs/{digest}")
async def head_blob(name: str, digest: str):
    """Blob 존재 확인"""
    try:
        headers = get_registry_auth_header()
        response = requests.head(f"{REGISTRY_URL}/v2/{name}/blobs/{digest}", headers=headers)
        
        return Response(
            content="",
            status_code=response.status_code,
            headers=dict(response.headers)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 5. Blob 다운로드
@app.get("/v2/{name:path}/blobs/{digest}")
async def get_blob(name: str, digest: str):
    """Blob 다운로드"""
    try:
        headers = get_registry_auth_header()
        response = requests.get(f"{REGISTRY_URL}/v2/{name}/blobs/{digest}", headers=headers, stream=True)
        
        if response.status_code == 200:
            # Audit 로그 기록
            log_audit("system", "BLOB_GET", name, None, f"Digest: {digest}")
            
            def generate():
                for chunk in response.iter_content(chunk_size=8192):
                    yield chunk
            
            return StreamingResponse(
                generate(),
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        else:
            raise HTTPException(status_code=response.status_code, detail=response.text)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 6. Blob 업로드 세션 시작
@app.post("/v2/{name:path}/blobs/uploads/")
async def start_blob_upload(name: str, username: str = Depends(verify_credentials)):
    """Blob 업로드 세션 시작"""
    try:
        headers = get_registry_auth_header()
        response = requests.post(f"{REGISTRY_URL}/v2/{name}/blobs/uploads/", headers=headers)
        
        if response.status_code == 202:
            # Audit 로그 기록
            upload_uuid = response.headers.get("Docker-Upload-UUID", "unknown")
            log_audit(username, "BLOB_UPLOAD_START", name, None, f"UUID: {upload_uuid}")
            
            return Response(
                content="",
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        else:
            raise HTTPException(status_code=response.status_code, detail=response.text)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 7. Blob 데이터 업로드 (PATCH)
@app.patch("/v2/{name:path}/blobs/uploads/{uuid}")
async def patch_blob_upload(name: str, uuid: str, request: Request, username: str = Depends(verify_credentials)):
    """Blob 데이터 업로드"""
    try:
        headers = get_registry_auth_header()
        content_type = request.headers.get("content-type", "application/octet-stream")
        headers["Content-Type"] = content_type
        
        if "content-range" in request.headers:
            headers["Content-Range"] = request.headers["content-range"]
        
        body = await request.body()
        
        response = requests.patch(
            f"{REGISTRY_URL}/v2/{name}/blobs/uploads/{uuid}",
            headers=headers,
            data=body
        )
        
        if response.status_code == 202:
            # Audit 로그 기록
            log_audit(username, "BLOB_UPLOAD_PATCH", name, None, f"UUID: {uuid}, Size: {len(body)} bytes")
            
            return Response(
                content="",
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        else:
            raise HTTPException(status_code=response.status_code, detail=response.text)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 8. Blob 업로드 완료 (PUT)
@app.put("/v2/{name:path}/blobs/uploads/{uuid}")
async def put_blob_upload(name: str, uuid: str, request: Request, digest: str = Query(...), username: str = Depends(verify_credentials)):
    """Blob 업로드 완료"""
    try:
        headers = get_registry_auth_header()
        content_type = request.headers.get("content-type", "application/octet-stream")
        headers["Content-Type"] = content_type
        
        body = await request.body()
        
        response = requests.put(
            f"{REGISTRY_URL}/v2/{name}/blobs/uploads/{uuid}?digest={digest}",
            headers=headers,
            data=body
        )
        
        if response.status_code == 201:
            # Audit 로그 기록
            log_audit(username, "BLOB_UPLOAD_COMPLETE", name, None, f"UUID: {uuid}, Digest: {digest}")
            
            return Response(
                content="",
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        else:
            raise HTTPException(status_code=response.status_code, detail=response.text)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============== 추가 관리 API ==============

# 전체 이미지 목록 조회 (필터 지원)
@app.get("/api/images")
async def list_images(
    name: Optional[str] = Query(None, description="이미지 이름 필터"),
    tag: Optional[str] = Query(None, description="태그 필터"),
    username: str = Depends(verify_credentials)
):
    """전체 이미지 목록 검색 (필터 지원)"""
    try:
        headers = get_registry_auth_header()
        
        # Registry 카탈로그 조회
        response = requests.get(f"{REGISTRY_URL}/v2/_catalog", headers=headers)
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch catalog from registry")
            
        repositories = response.json().get("repositories", [])
        images = []
        
        for repo in repositories:
            # 이름 필터 적용
            if name and name not in repo:
                continue
                
            # 태그 목록 조회
            tags_response = requests.get(f"{REGISTRY_URL}/v2/{repo}/tags/list", headers=headers)
            
            if tags_response.status_code == 200:
                tags_data = tags_response.json()
                tags = tags_data.get("tags", [])
                
                # 태그 필터 적용
                if tag:
                    tags = [t for t in tags if tag in t]
                
                if not tags:
                    continue
                
                # 각 태그의 상세 정보 조회
                for current_tag in tags:
                    try:
                        # Manifest 조회
                        manifest_response = requests.get(
                            f"{REGISTRY_URL}/v2/{repo}/manifests/{current_tag}",
                            headers={
                                **headers,
                                'Accept': 'application/vnd.docker.distribution.manifest.v2+json'
                            }
                        )
                        
                        if manifest_response.status_code == 200:
                            manifest = manifest_response.json()
                            created_at = datetime.utcnow().isoformat()
                            size = 0
                            
                            # Config blob에서 생성 시간 조회
                            try:
                                if 'config' in manifest:
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
                            
                            # 레이어 크기 계산
                            if 'layers' in manifest:
                                size = sum(layer.get('size', 0) for layer in manifest['layers'])
                            
                            images.append({
                                "name": repo,
                                "tag": current_tag,
                                "digest": manifest_response.headers.get('Docker-Content-Digest', ''),
                                "size": size,
                                "created_at": created_at,
                                "manifest": manifest
                            })
                            
                    except Exception as e:
                        print(f"Error processing {repo}:{current_tag}: {e}")
                        continue
        
        # Audit 로그 기록
        log_audit(username, "IMAGES_LIST", None, None, f"Filter - name: {name}, tag: {tag}")
        
        return {"images": images}
        
    except Exception as e:
        print(f"Error in list_images: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching images")

# 특정 이미지 삭제
@app.delete("/api/images/{name:path}")
async def delete_image(name: str, username: str = Depends(verify_credentials)):
    """특정 이미지 삭제"""
    try:
        headers = get_registry_auth_header()
        
        # 이미지의 모든 태그 조회
        tags_response = requests.get(f"{REGISTRY_URL}/v2/{name}/tags/list", headers=headers)
        if tags_response.status_code != 200:
            raise HTTPException(status_code=404, detail="Image not found")
        
        tags = tags_response.json().get("tags", [])
        deleted_tags = []
        
        # 각 태그별로 삭제
        for tag in tags:
            try:
                # Manifest 조회하여 digest 얻기
                manifest_response = requests.get(
                    f"{REGISTRY_URL}/v2/{name}/manifests/{tag}",
                    headers={**headers, 'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
                )
                
                if manifest_response.status_code == 200:
                    digest = manifest_response.headers.get('Docker-Content-Digest')
                    if digest:
                        # Manifest 삭제
                        delete_response = requests.delete(
                            f"{REGISTRY_URL}/v2/{name}/manifests/{digest}",
                            headers=headers
                        )
                        if delete_response.status_code in [200, 202, 404]:
                            deleted_tags.append(tag)
                            
            except Exception as e:
                print(f"Error deleting tag {tag}: {e}")
                continue
        
        # Audit 로그 기록
        log_audit(username, "IMAGE_DELETE", name, None, f"Deleted tags: {deleted_tags}")
        
        return {"message": f"Deleted {len(deleted_tags)} tags from image {name}", "deleted_tags": deleted_tags}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 특정 이미지의 태그 조회
@app.get("/api/images/{name:path}/tags")
async def get_image_tags(name: str, username: str = Depends(verify_credentials)):
    """특정 이미지의 태그 조회"""
    try:
        headers = get_registry_auth_header()
        response = requests.get(f"{REGISTRY_URL}/v2/{name}/tags/list", headers=headers)
        
        if response.status_code == 200:
            # Audit 로그 기록
            log_audit(username, "TAGS_LIST", name, None, None)
            return response.json()
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to fetch tags")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 특정 태그 삭제
@app.delete("/api/images/{name:path}/tags/{tag}")
async def delete_image_tag(name: str, tag: str, username: str = Depends(verify_credentials)):
    """특정 이미지의 태그 삭제"""
    try:
        headers = get_registry_auth_header()
        
        # Manifest 조회하여 digest 얻기
        manifest_response = requests.get(
            f"{REGISTRY_URL}/v2/{name}/manifests/{tag}",
            headers={**headers, 'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
        )
        
        if manifest_response.status_code != 200:
            raise HTTPException(status_code=404, detail="Tag not found")
        
        digest = manifest_response.headers.get('Docker-Content-Digest')
        if not digest:
            raise HTTPException(status_code=500, detail="Could not get manifest digest")
        
        # Manifest 삭제
        delete_response = requests.delete(f"{REGISTRY_URL}/v2/{name}/manifests/{digest}", headers=headers)
        
        if delete_response.status_code in [200, 202, 404]:
            # Audit 로그 기록
            log_audit(username, "TAG_DELETE", name, tag, f"Digest: {digest}")
            return {"message": f"Tag {tag} deleted from image {name}"}
        else:
            raise HTTPException(status_code=delete_response.status_code, detail="Failed to delete tag")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============== 사용자 관리 API ==============

# 사용자 목록 조회
@app.get("/api/users")
async def list_users(username: str = Depends(verify_credentials)):
    """사용자 목록 조회 (관리자 전용)"""
    if username != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)
        users = list(ht.users())
        log_audit(username, "USERS_LIST", None, None, None)
        return {"users": users}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 사용자 생성
@app.post("/api/users")
async def create_user(user_data: UserCreate, current_user: str = Depends(verify_credentials)):
    """사용자 생성 (관리자 전용)"""
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)
        ht.set_password(user_data.username, user_data.password)
        ht.save()
        
        log_audit(current_user, "USER_CREATE", None, None, f"Created user: {user_data.username}")
        return {"message": f"User {user_data.username} created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 사용자 삭제
@app.delete("/api/users/{username}")
async def delete_user(username: str, current_user: str = Depends(verify_credentials)):
    """사용자 삭제 (관리자 전용)"""
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if username == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete admin user")
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)
        if username in ht.users():
            ht.delete(username)
            ht.save()
            log_audit(current_user, "USER_DELETE", None, None, f"Deleted user: {username}")
            return {"message": f"User {username} deleted successfully"}
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============== Audit 로그 API ==============

# Audit 로그 조회
@app.get("/api/audit")
async def get_audit_logs(
    user: Optional[str] = Query(None, description="사용자 필터"),
    image: Optional[str] = Query(None, description="이미지 필터"),
    action: Optional[str] = Query(None, description="액션 필터"),
    limit: int = Query(100, description="최대 결과 수"),
    username: str = Depends(verify_credentials)
):
    """사용자별/이미지별 활동 기록 조회"""
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
        if action:
            query += " AND action = ?"
            params.append(action)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        c.execute(query, params)
        logs = c.fetchall()
        conn.close()
        
        return {
            "logs": [
                {
                    "id": log[0],
                    "timestamp": log[1],
                    "user": log[2],
                    "action": log[3],
                    "repository": log[4],
                    "tag": log[5],
                    "details": log[6]
                }
                for log in logs
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============== 시스템 상태 API ==============

# 시스템 상태 확인
@app.get("/api/health")
async def health_check():
    """시스템 상태 확인"""
    try:
        # Registry 연결 확인
        headers = get_registry_auth_header()
        registry_response = requests.get(f"{REGISTRY_URL}/v2/", headers=headers, timeout=5)
        registry_healthy = registry_response.status_code == 200
        
        # 데이터베이스 연결 확인
        conn = sqlite3.connect('/data/audit.db')
        c = conn.cursor()
        c.execute("SELECT 1")
        conn.close()
        db_healthy = True
        
        # 인증 파일 확인
        auth_healthy = os.path.exists(HTPASSWD_PATH)
        
        return {
            "status": "healthy" if all([registry_healthy, db_healthy, auth_healthy]) else "unhealthy",
            "components": {
                "registry": "healthy" if registry_healthy else "unhealthy",
                "database": "healthy" if db_healthy else "unhealthy",
                "authentication": "healthy" if auth_healthy else "unhealthy"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
