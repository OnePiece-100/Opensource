from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import os
from datetime import datetime
from passlib.apache import HtpasswdFile
import requests
import base64

# - FastAPI를 사용하여 애플리케이션 만들기

# FastAPI 애플리케이션 생성
app = FastAPI()

# - 사용자 이름과 비밀번호를 인증하는 기능을 추가

# HTTP Basic 인증을 위한 보안 객체 생성
security = HTTPBasic()

# - Docker Registry와 통신할 때 사용할 인증 정보 만들기

# Registry 통신을 위한 인증 헤더 생성 함수
def get_registry_auth_header():
    # 기본 인증 정보를 Base64로 인코딩하여 Authorization 헤더 반환
    return {
        'Authorization': f'Basic {base64.b64encode(b"admin:adminpass").decode()}'
    }

# - 웹 브라우저에서 다른 도메인에서 API를 호출할 수 있도록 허용

# CORS 설정 -
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# - Docker Registry와 인증 파일의 위치를 환경변수에서 가져옵니다. 기본 값도 설정

# Registry URL 및 인증 파일 경로 환경 변수에서 가져오기
REGISTRY_URL = os.getenv('REGISTRY_URL', 'http://registry:5000')
HTPASSWD_PATH = os.getenv('AUTH_FILE', '/auth/htpasswd')

# - 데이터베이스를 초기화하고, 로그를 저장할 공간 만들

# SQLite 데이터베이스 초기화 함수
def init_db():
    conn = sqlite3.connect('/data/audit.db')  # 데이터베이스 연결
    c = conn.cursor()
    # Audit 로그 테이블 생성
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log
        (timestamp TEXT, user TEXT, action TEXT, repository TEXT, tag TEXT)
    ''')
    conn.commit()
    conn.close()

# -  서버가 시작될 때 데이터베이스를 설정하고, 인증 파일이 없으면 새로만들기

# FastAPI 시작 이벤트 - 데이터베이스 초기화 및 인증 파일 생성
@app.on_event("startup")
async def startup_event():
    init_db()  # DB 초기화
    if not os.path.exists(HTPASSWD_PATH):  # 인증 파일이 없으면 새로 생성
        ht = HtpasswdFile(HTPASSWD_PATH, new=True)
        ht.save()

# -  사용자 이름과 비밀번호가 맞는지 확인하고, 맞으면 사용자 이름을 반환

# 사용자 인증 검증 함수
def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)  # 인증 파일 읽기
        # 사용자 이름과 비밀번호 검증
        if not ht.check_password(credentials.username, credentials.password):
            # 인증 실패 시 HTTP 예외 발생
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credentials.username  # 인증 성공 시 사용자 이름 반환
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        # 인증 오류 발생 시 HTTP 예외 발생
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Basic"},
        )

# -  Registry에서 저장소와 이미지 정보를 가져옵니다. 사용자가 인증되어야 합니다

# 이미지 목록 조회 API
@app.get("/api/images")
async def list_images(username: str = Depends(verify_credentials)):
    try:
        # Registry API 호출을 위한 인증 헤더 생성
        headers = get_registry_auth_header()
        
        # Registry 카탈로그 조회

        # ** API v2 지원 여부 확인 **
        response = requests.get(f"{REGISTRY_URL}/v2/_catalog", headers=headers)
        if response.status_code != 200:  # 오류 발생 시 예외 처리
            print(f"Catalog response: {response.status_code}, {response.text}")
            raise HTTPException(status_code=500, detail="Failed to fetch catalog from registry")
            
        repositories = response.json().get("repositories", [])  # 저장소 목록 가져오기
        images = []  # 이미지 정보를 저장할 리스트
        
        for repo in repositories:
            # 각 저장소의 태그 목록 조회
            tags_response = requests.get(
                f"{REGISTRY_URL}/v2/{repo}/tags/list",
                headers=headers
            )
            
            if tags_response.status_code == 200:  # 태그 조회 성공 시 처리
                tags_data = tags_response.json()
                tags = tags_data.get("tags", [])
                
                # 각 태그의 상세 정보 조회
                for tag in tags:
                    # ** Manifest 조회 ** 
                    manifest_response = requests.get(
                        f"{REGISTRY_URL}/v2/{repo}/manifests/{tag}",
                        headers={
                            **headers,
                            'Accept': 'application/vnd.docker.distribution.manifest.v2+json'
                        }
                    )
                    
                    if manifest_response.status_code == 200:  # Manifest 조회 성공 시 처리
                        manifest = manifest_response.json()
                        created_at = datetime.utcnow().isoformat()  # 현재 시간으로 초기화
                        
                        # config blob에서 생성 시간 조회 시도
                        try:
                            # ** Config Blob 다운로드 **
                            config_response = requests.get(
                                f"{REGISTRY_URL}/v2/{repo}/blobs/{manifest['config']['digest']}",
                                headers=headers
                            )
                            if config_response.status_code == 200:  # Config blob 조회 성공
                                config = config_response.json()
                                if 'created' in config:  # 생성 시간이 포함된 경우 업데이트
                                    created_at = config['created']
                        except:
                            pass
                        
                        # 이미지 정보 추가
                        images.append({
                            "name": repo,
                            "tags": tags,
                            "lastUpdated": created_at,
                            # ** Layer Blob 다운로드 ** 
                            "size": sum(layer['size'] for layer in manifest.get('layers', [])),
                            "digest": manifest_response.headers.get('Docker-Content-Digest', '')
                        })
                        break  # 하나의 태그 정보만 가져옴
        
        return {"images": images}  # 이미지 목록 반환
    except Exception as e:
        print(f"Error in list_images: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching images")

# 이미지 업로드 API


# 시스템 상태 확인 API
@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}  # 시스템 상태 반환

# 사용자 목록 조회 API
@app.get("/api/users")
async def list_users(username: str = Depends(verify_credentials)):
    if username != "admin":  # 관리자만 접근 가능
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)  # 인증 파일 읽기
        return {"users": list(ht.users())}  # 사용자 목록 반환
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 사용자 생성 API
@app.post("/api/users")
async def create_user(
    username: str,
    password: str,
    current_user: str = Depends(verify_credentials)
):
    if current_user != "admin":  # 관리자만 접근 가능
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)  # 인증 파일 읽기
        ht.set_password(username, password)  # 사용자 생성
        ht.save()  # 변경 사항 저장
        return {"message": f"User {username} created successfully"}  # 성공 메시지 반환
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 사용자 삭제 API
@app.delete("/api/users/{username}")
async def delete_user(
    username: str,
    current_user: str = Depends(verify_credentials)
):
    if current_user != "admin":  # 관리자만 접근 가능
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        ht = HtpasswdFile(HTPASSWD_PATH)  # 인증 파일 읽기
        if username == "admin":  # 관리자 계정 삭제 금지
            raise HTTPException(status_code=400, detail="Cannot delete admin user")
        if username in ht.users():  # 사용자 존재 확인
            ht.delete(username)  # 사용자 삭제
            ht.save()  # 변경 사항 저장
            return {"message": f"User {username} deleted successfully"}  # 성공 메시지 반환
        raise HTTPException(status_code=404, detail="User not found")  # 사용자 없음
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Audit 로그 조회 API
@app.get("/api/audit")
async def get_audit_logs(
    user: str = None,
    image: str = None,
    username: str = Depends(verify_credentials)
):
    try:
        conn = sqlite3.connect('/data/audit.db')  # 데이터베이스 연결
        c = conn.cursor()
        
        query = "SELECT * FROM audit_log WHERE 1=1"  # 기본 쿼리
        params = []
        
        if user:  # 사용자 필터링 조건 추가
            query += " AND user = ?"
            params.append(user)
        if image:  # 이미지 필터링 조건 추가
            query += " AND repository = ?"
            params.append(image)
            
        c.execute(query, params)  # 쿼리 실행
        logs = c.fetchall()  # 결과 가져오기
        conn.close()  # 데이터베이스 연결 닫기
        
        # 로그 형식 변환 및 반환
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
