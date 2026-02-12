# ====== IGLOO AI Model Hub v2.0 ======␊
import streamlit as st␊
import pandas as pd␊
import json␊
from datetime import datetime␊
import math␊
import uuid␊
import base64␊
import os␊
␊
st.set_page_config(page_title="IGLOO AI Model Hub", page_icon=r"D:\Work\16. 모델 팩토리\2.code\photo\page_icon.png", layout="wide")␊
␊
# ===== 사용자 설정 =====␊
PROFILE_ICON_PATH = ""␊
␊
# ===== 영구 저장소 (서버 실행 중 유지) =====␊
@st.cache_resource␊
def get_store():␊
    return {"models": [], "model_files": {}, "feedback": [], "docs": [], "init": False}␊
␊
store = get_store()␊
␊
if not store["init"]:␊
    store["models"] = [␊
        {␊
            'id': 1, 'name': 'WAF SQL Injection Detector', 'algorithm': 'Random Forest', 'type': '지도학습',␊
            'log_type': 'WAF', 'version': 'v1.2.1', 'size': '15.2 MB', 'model_id': 'waf_sql_001',␊
            'summary': 'WAF 로그 기반 SQL Injection 공격 탐지 모델', 'status': 'active',␊
            'description': '웹 애플리케이션 방화벽 로그를 분석하여 SQL Injection 공격을 실시간으로 탐지합니다.',␊
            'detection_target': 'SQL Injection 공격 패턴', 'threat_tags': ['SQL Injection', 'Web Attack'],␊
            'features': ['request_uri', 'user_agent', 'payload_length', 'special_chars'],␊
            'parameters': '{"max_depth": 10, "n_estimators": 100, "min_samples_split": 5}',␊
            'required_fields': ['timestamp', 'src_ip', 'request_uri', 'user_agent'],␊
            'created_at': '2024-01-15', 'updated_at': '2024-02-05', 'downloads': 243, 'views': 1205, 'has_file': True,␊
            'mitre_tactics': ['TA0001'], 'mitre_techniques': ['T1190'],␊
            'dataset_settings': {'logType': ['waf'], 'features': ['sent_bytes_sum']},␊
            'trigger_settings': {'fadingFactor': 0.9, 'boundType': 'UPPER', 'sensitivity': 0.85}␊
        },␊
        {␊
            'id': 2, 'name': 'Network DDoS Pattern Analyzer', 'algorithm': 'RRCF', 'type': '비지도학습',␊
            'log_type': 'Network', 'version': 'v2.0.0', 'size': '8.7 MB', 'model_id': 'net_ddos_001',␊
            'summary': '네트워크 트래픽 기반 DDoS 공격 패턴 분석', 'status': 'active',␊
            'description': '네트워크 로그를 실시간 분석하여 DDoS 공격 패턴을 탐지하고 알려줍니다.',␊
            'detection_target': 'DDoS 공격 트래픽', 'threat_tags': ['DDoS', 'Network Attack'],␊
            'features': ['packet_rate', 'bytes_per_sec', 'connection_count'],␊
            'parameters': '{"num_trees": 100, "shingle_size": 4, "sample_size": 512}',␊
            'required_fields': ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_size'],␊
            'created_at': '2024-01-20', 'updated_at': '2024-02-08', 'downloads': 156, 'views': 834, 'has_file': True,␊
            'mitre_tactics': ['TA0040'], 'mitre_techniques': ['T1498'],␊
            'dataset_settings': {'logType': ['network'], 'features': ['packet_count']},␊
            'trigger_settings': {'fadingFactor': 0.8, 'boundType': 'UPPER', 'sensitivity': 0.9}␊
        },␊
        {␊
            'id': 3, 'name': 'IDS Brute Force Detection', 'algorithm': 'Isolation Forest', 'type': '비지도학습',␊
            'log_type': 'IDS', 'version': 'v1.1.0', 'size': '12.3 MB', 'model_id': 'ids_brute_001',␊
            'summary': 'IDS 로그 기반 Brute Force 공격 탐지', 'status': 'active',␊
            'description': 'IDS 이벤트 로그를 분석하여 무차별 대입 공격을 탐지합니다.',␊
            'detection_target': 'Brute Force 공격', 'threat_tags': ['Brute Force', 'Authentication'],␊
            'features': ['login_attempts', 'source_diversity', 'time_pattern'],␊
            'parameters': '{"contamination": 0.1, "n_estimators": 200}',␊
            'required_fields': ['timestamp', 'src_ip', 'username', 'auth_result'],␊
            'created_at': '2024-02-01', 'updated_at': '2024-02-09', 'downloads': 89, 'views': 456, 'has_file': True,␊
            'mitre_tactics': ['TA0006'], 'mitre_techniques': ['T1110'],␊
            'dataset_settings': {'logType': ['ids'], 'features': ['login_count']},␊
            'trigger_settings': {'fadingFactor': 0.95, 'boundType': 'UPPER', 'sensitivity': 0.7}␊
        }␊
    ]␊
    store["docs"] = [␊
        {'id': 1, 'title': 'IGLOO AI Model Hub 시작하기', 'category': '사용자 가이드', 'author': '관리자', 'date': '2024-02-11', 'views': 45,␊
         'content': 'IGLOO AI Model Hub는 보안 위협 탐지를 위한 AI 모델들을 중앙에서 관리하고 배포하는 플랫폼입니다.', 'file_attached': False},␊
        {'id': 2, 'title': 'JSON 설정 파일 구조 가이드', 'category': '기술 문서', 'author': '개발팀', 'date': '2024-02-10', 'views': 32,␊
         'content': 'JSON 설정 파일은 algorithm, algorithmSettings, logType, datasetSettings, triggerSettings 등의 섹션으로 구성됩니다.', 'file_attached': True},␊
        {'id': 3, 'title': '환경별 로그 필드 매핑 가이드', 'category': '운영 가이드', 'author': '운영팀', 'date': '2024-02-09', 'views': 28,␊
         'content': '환경마다 로그 필드명이 다를 수 있습니다. 예: sent_bytes vs bytes_sent vs send_byte', 'file_attached': False},␊
        {'id': 4, 'title': 'ExD 모델 업로드 방법 안내', 'category': '운영 가이드', 'author': '관리자', 'date': '2024-02-08', 'views': 19,␊
         'content': 'Management 메뉴에서 모델을 등록하고, JSON 설정 파일과 모델 바이너리 파일을 업로드합니다.', 'file_attached': True}␊
    ]␊
    store["init"] = True␊
␊
# ===== 개발모드 바 =====␊
st.markdown("""␊
<style>␊
    header{display:none!important}#MainMenu{visibility:hidden}footer{visibility:hidden}␊
    .block-container{padding-top:0rem!important;border-top:none!important}␊
</style>␊
<div style="background-color:#1a1a2e;color:#fff;text-align:center;padding:14px 10px 10px;font-size:0.9em;letter-spacing:0.5px;margin:-1rem -25rem 0 -25rem;">␊
    📐 IGLOO AI Model Hub v2.0 — <span style="color:#00D4B8;font-weight:600;">개발 모드</span>␊
</div>␊
""", unsafe_allow_html=True)␊
␊
# ===== 세션 초기화 =====␊
for k, v in {'is_logged_in': False, 'login_time': None, 'user_name': '', 'show_advanced_filters': False, 'temp_json_editor': {}, 'json_search_term': ''}.items():␊
    if k not in st.session_state:␊
        st.session_state[k] = v␊
␊
VALID_USERNAME = "hub"␊
VALID_PASSWORD = "hub1234#$"␊
␊
if not st.session_state.is_logged_in and st.query_params.get("auth") == "1":␊
    st.session_state.is_logged_in = True␊
    st.session_state.user_name = "hub"␊
    st.session_state.login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")␊
␊
# ==================== 로그인 ====================␊
if not st.session_state.is_logged_in:␊
    st.markdown("""␊
<style>␊
    [data-testid="stAppViewContainer"]{background-color:#f0f7f9;min-height:100vh}␊
    .block-container{padding-top:15vh!important;max-width:100%!important}␊
    div[data-testid="stForm"]{background:#fff;border-radius:20px;box-shadow:0 16px 100px rgba(0,0,0,.2);padding:24px 22px;max-width:460px;margin:0 auto}␊
    .wh{background:linear-gradient(135deg,#00A98E,#00D4B8);padding:24px 22px 22px;text-align:center;border-radius:0 0 50% 50%/0 0 20% 20%;margin:-24px -22px 0}␊
    .wt{color:#fff!important;font-size:2em;font-weight:700;margin:0;text-shadow:0 2px 8px rgba(0,0,0,.18)}␊
    .ws{color:rgba(255,255,255,.9);font-size:.9em;margin-top:8px;line-height:1.6}␊
    .lt{text-align:center;color:#666;font-size:1.25em;font-weight:600;letter-spacing:5px;margin:14px 0 10px}␊
    .le{color:#ff4444!important;font-size:13px!important}␊
    .stAlert{display:none}␊
    button[kind="secondaryFormSubmit"]{background:white!important;color:#568fa6!important;border:2px solid #e0e0e0!important;font-size:14px!important;letter-spacing:1px!important;text-transform:uppercase!important;border-radius:3px!important;height:50px!important;width:100%!important}␊
    button[kind="secondaryFormSubmit"]:hover{border-color:#44d8a4!important;color:#44d8a4!important}␊
</style>""", unsafe_allow_html=True)␊
    _, c, _ = st.columns([1, 2, 1])␊
    with c:␊
        with st.form("login"):␊
            st.markdown('<div class="wh"><h1 class="wt">IGLOO<br/><span style="padding-left:30px">AI Model Hub</span></h1><p class="ws">IGLOO AI Model Hub v2.0에 오신 것을 환영합니다.<br/>로그인하여 다양한 AI 모델을 관리하세요.</p></div><div class="lt">LOGIN</div>', unsafe_allow_html=True)␊
            u = st.text_input("ID", placeholder="Enter your ID")␊
            p = st.text_input("Password", type="password", placeholder="Enter your password")␊
            if st.session_state.get('login_error'):␊
                st.markdown('<p class="le">아이디 또는 비밀번호가 올바르지 않습니다.</p>', unsafe_allow_html=True)␊
            if st.form_submit_button("LOGIN", use_container_width=True):␊
                if u == VALID_USERNAME and p == VALID_PASSWORD:␊
                    st.session_state.is_logged_in = True␊
                    st.session_state.login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")␊
                    st.session_state.user_name = u␊
                    st.session_state.login_error = False␊
                    st.query_params.update({"auth": "1"})␊
                    st.rerun()␊
                else:␊
                    st.session_state.login_error = True␊
                    st.rerun()␊
    st.stop()␊
␊
# ===== 프로필 아이콘 =====␊
picon = '<div class="pi-def">H</div>'␊
if PROFILE_ICON_PATH and os.path.exists(PROFILE_ICON_PATH):␊
    try:␊
        with open(PROFILE_ICON_PATH, "rb") as f:␊
            picon = f'<img src="data:image/png;base64,{base64.b64encode(f.read()).decode()}" class="pi-img">'␊
    except: pass␊
␊
# ==================== 메인 CSS ====================␊
st.markdown("""␊
<style>␊
    .main,[data-testid="stAppViewContainer"]{background:#F8FAFC!important}␊
    .block-container{max-width:1400px!important;padding-top:0!important;padding-left:2rem!important;padding-right:2rem!important;margin:0 auto!important}␊
␊
    /* 네비게이션 */␊
    .top-nav{background:linear-gradient(135deg,#fff,#f8fafc);border-bottom:1px solid #e2e8f0;box-shadow:0 4px 20px rgba(0,0,0,.08);width:100vw;position:relative;left:50%;right:50%;margin-left:-50vw;margin-right:-50vw;margin-top:-1rem;margin-bottom:2rem}␊
    .nav-inner{max-width:1400px;width:95%;margin:0 auto;height:85px;display:flex;align-items:center;justify-content:space-between}␊
    .nav-left{display:flex;align-items:center;gap:45px}␊
    .nav-logo-link{text-decoration:none!important;display:block}␊
    .nav-logo-link .logo-t{color:#00A98E;font-weight:800;font-size:1.8em;letter-spacing:-.5px;line-height:1.1}␊
    .nav-logo-link .logo-s{color:#64748b;font-size:.7em;font-weight:500;letter-spacing:1px}␊
    .nav-menu{display:flex;gap:36px;align-items:center}␊
    .nav-menu a{text-decoration:none;color:#475569;font-size:.95em;font-weight:600;transition:.3s;padding:8px 16px;border-radius:8px}␊
    .nav-menu a:hover{color:#00A98E;background:rgba(0,169,142,.1)}␊
    .nav-menu a.act{color:#00A98E;background:rgba(0,169,142,.08)}␊
␊
    /* 프로필 드롭다운 */␊
    .nav-right{position:relative;display:flex;align-items:center}␊
    .pc{position:relative;display:inline-block}␊
    .pb{display:flex;align-items:center;gap:12px;background:#f1f5f9;border:2px solid #e2e8f0;border-radius:12px;padding:8px 16px;cursor:pointer;transition:.3s;text-decoration:none!important}␊
    .pb:hover{border-color:#00A98E;background:#f0fdf4}␊
    .pi-def{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#00A98E,#00D4B8);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:1em}␊
    .pi-img{width:36px;height:36px;border-radius:50%;object-fit:cover;border:2px solid #e2e8f0}␊
    .p-info{display:flex;flex-direction:column;align-items:flex-start}␊
    .p-name{font-weight:600;font-size:.9em;color:#1e293b;line-height:1.2}␊
    .p-time{font-size:.72em;color:#64748b;line-height:1.2}␊
    .p-arrow{color:#94a3b8;font-size:.7em;transition:transform .3s}␊
    .pc:hover .p-arrow{transform:rotate(180deg)}␊
␊
    /* 드롭다운 메뉴 */␊
    .dd-wrap{display:none;position:absolute;top:100%;right:0;padding-top:8px;z-index:9999}␊
    .dd-menu{background:#fff;border:1px solid #e2e8f0;border-radius:12px;box-shadow:0 20px 25px -5px rgba(0,0,0,.1),0 10px 10px -5px rgba(0,0,0,.04);min-width:220px;padding:8px 0;overflow:hidden}␊
    .pc:hover .dd-wrap{display:block}␊
    .dd-menu a{display:flex;align-items:center;gap:10px;padding:11px 18px;color:#374151;text-decoration:none;font-size:.88em;font-weight:500;transition:.2s}␊
    .dd-menu a:hover{background:#f0fdf4;color:#00A98E}␊
    .dd-div{border-top:1px solid #e5e7eb;margin:6px 0}␊
    .dd-lbl{padding:6px 18px;font-size:.72em;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:1px}␊
    .dd-ui{padding:12px 18px;border-bottom:1px solid #f1f5f9}␊
    .dd-un{font-weight:700;color:#1e293b;font-size:.95em}␊
    .dd-ur{font-size:.78em;color:#64748b;margin-top:2px}␊
␊
    /* 검색창 기본 리셋 */␊
    div[data-testid="stTextInput"]>div{background:transparent!important}␊
    div[data-testid="stTextInput"]{background:transparent!important}␊
    div[data-testid="stTextInput"] button{display:none!important}␊
    div[data-testid="stTextInput"] [data-testid="InputInstructions"]{display:none!important}␊
    ␊
    /* 기본 검색창 스타일 (일반 페이지용) */␊
    div[data-testid="stTextInput"] input {␊
        border: 2px solid #e2e8f0;␊
        border-radius: 16px;␊
        padding: 14px 20px;␊
        font-size: 1em;␊
        background: #fff;␊
        transition: .3s;␊
        box-shadow: none;␊
    }␊
    ␊
    div[data-testid="stTextInput"] input:focus {␊
        border-color: #00A98E;␊
        box-shadow: 0 0 0 3px rgba(0,169,142,.1);␊
    }␊
␊
    /* 홈 검색 헤더 */␊
    .sh{text-align:center;margin-bottom:32px;padding:40px 0 20px}␊
    .sh h1{font-size:2.2em;font-weight:700;color:#1e293b;margin-bottom:12px}␊
    .sh p{font-size:1.1em;color:#64748b;margin-bottom:28px}␊
␊
    /* 섹션 헤더 */␊
    .sec-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;padding-bottom:12px;border-bottom:2px solid #e5e7eb}␊
    .sec-t{font-size:1.4em;font-weight:700;color:#1e293b}␊
    .sec-ts{font-size:.75em;color:#64748b;font-weight:400;margin-left:8px}␊
    .va-link{font-size:.9em;color:#00A98E;text-decoration:none;font-weight:600;padding:8px 16px;border-radius:8px;transition:.3s}␊
    .va-link:hover{background:rgba(0,169,142,.1)}␊
␊
    /* 모델 카드 */␊
    .mc{background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:20px;margin-bottom:16px;transition:.3s;cursor:pointer;text-decoration:none!important;display:block;color:inherit!important}␊
    .mc:hover{border-color:#00A98E;box-shadow:0 10px 25px -5px rgba(0,169,142,.1);transform:translateY(-2px)}␊
    .mc-h{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px}␊
    .mc-t{font-weight:700;font-size:1.05em;color:#1e293b;margin-bottom:4px}␊
    .mc-v{font-size:.78em;color:#64748b;font-weight:500}␊
    .mc-b{display:flex;gap:6px;flex-wrap:wrap}␊
    .mc-d{font-size:.88em;color:#475569;margin-bottom:10px;line-height:1.5}␊
    .mc-th{margin-bottom:10px;display:flex;flex-wrap:wrap;gap:6px}␊
    .mc-m{display:flex;justify-content:space-between;align-items:center;font-size:.78em;color:#64748b;padding-top:10px;border-top:1px solid #f1f5f9}␊
    .mc-st{display:flex;gap:14px}␊
␊
    /* 배지 */␊
    .b-log{display:inline-block;background:#dbeafe;color:#1d4ed8;padding:4px 12px;border-radius:8px;font-size:.75em;font-weight:700;border:1px solid #93c5fd}␊
    .b-type{display:inline-block;background:#d1fae5;color:#059669;padding:4px 12px;border-radius:8px;font-size:.75em;font-weight:700;border:1px solid #6ee7b7}␊
    .b-ver{display:inline-block;background:#f8fafc;color:#475569;padding:4px 12px;border-radius:8px;font-size:.75em;font-weight:600;border:1px solid #e2e8f0}␊
    .b-threat{display:inline-block;background:#fef3c7;color:#d97706;padding:4px 10px;border-radius:12px;font-size:.75em;font-weight:600;border:1px solid #fcd34d}␊
    .b-st{display:inline-block;padding:4px 10px;border-radius:12px;font-size:.7em;font-weight:700;text-transform:uppercase;letter-spacing:.5px}␊
    .st-a{background:#dcfce7;color:#166534;border:1px solid #86efac}␊
    .st-p{background:#fef3c7;color:#92400e;border:1px solid #fcd34d}␊
    .st-t{background:#e0e7ff;color:#3730a3;border:1px solid #a5b4fc}␊
␊
    /* 빈 상태 */␊
    .empty{text-align:center;padding:60px 20px;color:#64748b;border:2px dashed #e5e7eb;border-radius:16px;background:#f8fafc;margin:20px 0}␊
    .empty-i{font-size:3em;margin-bottom:16px;opacity:.5}␊
    .empty-t{font-size:1.2em;font-weight:600;color:#374151;margin-bottom:8px}␊
␊
    /* 페이지네이션 */␊
    .pg{display:flex;justify-content:center;gap:8px;margin-top:32px;padding:20px 0}␊
    .pg-b{display:flex;align-items:center;justify-content:center;width:40px;height:40px;border:1px solid #e5e7eb;border-radius:8px;background:#fff;color:#374151;text-decoration:none;font-weight:600;transition:.3s}␊
    .pg-b:hover{border-color:#00A98E;color:#00A98E;background:#f0fdf4}␊
    .pg-b.on{background:#00A98E;border-color:#00A98E;color:#fff}␊
␊
    /* 버튼 */␊
    .stButton>button{border-radius:12px!important;font-weight:600!important;border:2px solid #e5e7eb!important;background:#fff!important;color:#374151!important}␊
    .stButton>button:hover{border-color:#00A98E!important;color:#00A98E!important;background:#f0fdf4!important}␊
    .stButton>button[kind="primary"]{background:#00A98E!important;border-color:#00A98E!important;color:#fff!important}␊
    .stButton>button[kind="primary"]:hover{background:#059669!important;border-color:#059669!important}␊
␊
    /* Docs 게시판 행 */␊
    .doc-row{display:flex;align-items:center;padding:14px 0;border-bottom:1px solid #f1f5f9;transition:.2s}␊
    .doc-row:hover{background:#f0fdf4}␊
␊
    /* JSON 에디터 카드 스타일 (흰 배경) */␊
    .json-editor-card {␊
        padding: 1rem;␊
        overflow: hidden;␊
        border: 1px solid #e2e8f0;␊
        border-radius: 12px;␊
        background-color: #ffffff;␊
        backdrop-filter: blur(8px);␊
    }␊
    .json-editor-wrap {␊
        display: flex;␊
        flex-direction: column;␊
        gap: 0.5rem;␊
        position: relative;␊
        z-index: 10;␊
        border: 1px solid #cbd5e1;␊
        border-radius: 8px;␊
        overflow: hidden;␊
    }␊
    .json-editor-terminal {␊
        display: flex;␊
        flex-direction: column;␊
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;␊
    }␊
    .json-editor-head {␊
        display: flex;␊
        align-items: center;␊
        justify-content: space-between;␊
        overflow: hidden;␊
        min-height: 40px;␊
        padding-inline: 12px;␊
        background-color: #f8fafc;␊
        border-bottom: 1px solid #e2e8f0;␊
    }␊
    .json-editor-title {␊
        display: flex;␊
        align-items: center;␊
        gap: 8px;␊
        height: 2.5rem;␊
        user-select: none;␊
        font-weight: 600;␊
        overflow: hidden;␊
        text-overflow: ellipsis;␊
        white-space: nowrap;␊
        color: #475569;␊
        font-size: 0.9em;␊
    }␊
    .json-editor-title > svg {␊
        height: 18px;␊
        width: 18px;␊
        color: #00A98E;␊
    }␊
    .json-search-box {␊
        display: flex;␊
        align-items: center;␊
        gap: 4px;␊
        padding: 4px 8px;␊
        border: 1px solid #e2e8f0;␊
        border-radius: 6px;␊
        background-color: #ffffff;␊
    }␊
    .json-search-box input {␊
        border: none;␊
        outline: none;␊
        background: transparent;␊
        width: 150px;␊
        font-size: 0.85em;␊
        padding: 2px;␊
        color: #475569;␊
    }␊
    .json-search-box input::placeholder {␊
        color: #94a3b8;␊
    }␊
    .json-editor-body {␊
        display: flex;␊
        flex-direction: column;␊
        position: relative;␊
        overflow-x: auto;␊
        overflow-y: auto;␊
        padding: 1rem;␊
        max-height: 600px;␊
        line-height: 1.6;␊
        color: #1e293b;␊
        background-color: #ffffff;␊
        white-space: pre;␊
        font-size: 14px;␊
    }␊
    .json-line {␊
        display: flex;␊
        align-items: flex-start;␊
    }␊
    .json-line-number {␊
        color: #94a3b8;␊
        min-width: 40px;␊
        text-align: right;␊
        padding-right: 12px;␊
        user-select: none;␊
        font-size: 0.85em;␊
    }␊
    .json-line-content {␊
        flex: 1;␊
    }␊
    /* JSON 신택스 하이라이팅 */␊
    .json-key { color: #7c3aed; font-weight: 600; }␊
    .json-string { color: #059669; }␊
    .json-number { color: #dc2626; }␊
    .json-boolean { color: #2563eb; }␊
    .json-null { color: #6b7280; }␊
    .json-bracket { color: #475569; font-weight: 700; }␊
    .json-highlight { background-color: #fef3c7; }␊
␊
    /* 반응형 */␊
    @media(max-width:900px){.nav-menu a{font-size:.85em}.p-info{display:none}}␊
    ␊
    /* ===== 홈 화면 검색바 스타일 (최후 순위 - 최고 우선순위) ===== */␊
    .sh ~ div div[data-testid="stHorizontalBlock"] input[type="text"],␊
    .home-page-container div[data-testid="stHorizontalBlock"] input[type="text"],␊
    .home-page-container input[type="text"] {␊
        height: 50px !important;␊
        padding: 0 1.5rem !important;␊
        border: 2px solid transparent !important;␊
        border-radius: 12px !important;␊
        background-color: #D9E8D8 !important;␊
        color: #0d0c22 !important;␊
        box-shadow: 0 0 5px #C1D9BF, 0 0 0 10px #f5f5f5eb !important;␊
        transition: all 0.3s ease !important;␊
        font-size: 1em !important;␊
    }␊
    ␊
    .sh ~ div div[data-testid="stHorizontalBlock"] input[type="text"]::placeholder,␊
    .home-page-container div[data-testid="stHorizontalBlock"] input[type="text"]::placeholder,␊
    .home-page-container input[type="text"]::placeholder {␊
        color: #666 !important;␊
    }␊
    ␊
    .sh ~ div div[data-testid="stHorizontalBlock"] input[type="text"]:focus,␊
    .home-page-container div[data-testid="stHorizontalBlock"] input[type="text"]:focus,␊
    .home-page-container input[type="text"]:focus {␊
        border-color: #00A98E !important;␊
        background-color: #e3f2e1 !important;␊
        box-shadow: 0 0 8px #00A98E, 0 0 0 10px #f5f5f5eb !important;␊
    }␊
    ␊
    /* 홈 화면 필터 버튼 스타일 */␊
    .sh ~ div div[data-testid="stHorizontalBlock"] button[kind="secondary"],␊
    .home-page-container div[data-testid="stHorizontalBlock"] button[kind="secondary"],␊
    .home-page-container button[kind="secondary"] {␊
        height: 50px !important;␊
        min-height: 50px !important;␊
        background: rgba(255, 255, 255, 0.95) !important;␊
        border: 2px solid #cbd5e0 !important;␊
        border-radius: 12px !important;␊
        color: #475569 !important;␊
        font-size: 1.8rem !important;␊
        font-weight: 300 !important;␊
        padding: 0 !important;␊
        transition: all 0.2s ease !important;␊
        box-shadow: 0 2px 4px rgba(0,0,0,0.05) !important;␊
    }␊
    ␊
    .sh ~ div div[data-testid="stHorizontalBlock"] button[kind="secondary"]:hover,␊
    .home-page-container div[data-testid="stHorizontalBlock"] button[kind="secondary"]:hover,␊
    .home-page-container button[kind="secondary"]:hover {␊
        background: #ffffff !important;␊
        border-color: #00A98E !important;␊
        color: #00A98E !important;␊
        box-shadow: 0 4px 12px rgba(0, 169, 142, 0.15) !important;␊
        transform: translateY(-1px) !important;␊
    }␊
</style>␊
""", unsafe_allow_html=True)␊
␊
# ===== 라우팅 =====␊
qp = st.query_params␊
def _g(n, d=""): v = qp.get(n, d); return (v[0] if v else d) if isinstance(v, list) else v␊
␊
if _g("logout"):␊
    st.session_state.is_logged_in = False␊
    st.query_params.clear()␊
    st.rerun()␊
␊
menu = _g("menu", "home")␊
page = _g("page", "list")␊
model_id = _g("model_id")␊
user_name = st.session_state.user_name or "hub"␊
login_time = st.session_state.login_time or "-"␊
␊
# ===== 네비게이션 =====␊
def _ac(m): return "act" if menu == m else ""␊
st.markdown(f"""␊
<div class="top-nav"><div class="nav-inner">␊
    <div class="nav-left">␊
        <a target="_self" href="?menu=home&auth=1" class="nav-logo-link" onclick="event.preventDefault(); window.location.replace(this.href);"><div class="logo-t">IGLOO</div><div class="logo-s">AI MODEL HUB</div></a>
        <div class="nav-menu">␊
            <a target="_self" href="?menu=notice&auth=1" class="{_ac('notice')}" onclick="event.preventDefault(); window.location.replace(this.href);">공지사항</a>
            <a target="_self" href="?menu=models&page=list&auth=1" class="{_ac('models')}" onclick="event.preventDefault(); window.location.replace(this.href);">Models</a>
            <a target="_self" href="?menu=docs&auth=1" class="{_ac('docs')}" onclick="event.preventDefault(); window.location.replace(this.href);">Docs</a>
        </div>␊
    </div>␊
    <div class="nav-right">␊
        <div class="pc">␊
            <div class="pb">␊
                {picon}␊
                <div class="p-info"><div class="p-name">{user_name}</div><div class="p-time">{login_time}</div></div>␊
                <div class="p-arrow">▼</div>␊
            </div>␊
            <div class="dd-wrap"><div class="dd-menu">␊
                <div class="dd-ui"><div class="dd-un">🟢 {user_name}</div><div class="dd-ur">IGLOO AI Model Hub</div></div>␊
                <div class="dd-lbl">관리</div>␊
                <a target="_self" href="?menu=management&auth=1" onclick="event.preventDefault(); window.location.replace(this.href);">➕ Model Management</a>
                <a target="_self" href="?menu=docs_write&auth=1" onclick="event.preventDefault(); window.location.replace(this.href);">➕ Docs</a>
                <div class="dd-div"></div>␊
                <a target="_self" href="?logout=1" onclick="event.preventDefault(); window.location.replace(this.href);">🚪 로그아웃</a>
            </div></div>␊
        </div>␊
    </div>␊
</div></div>␊
""", unsafe_allow_html=True)␊
␊
# ===== 유틸 =====␊
def _ut(d):␊
    try:␊
        n = (datetime.now() - datetime.strptime(d, '%Y-%m-%d')).days␊
        return "오늘" if n == 0 else f"{n}일 전"␊
    except: return d␊
␊
def _sc(s): return {'active':'st-a','pending':'st-p','test':'st-t','테스트':'st-t','보류':'st-p'}.get(s,'st-a')␊
␊
def _card(m, created=False):␊
    tags = "".join([f'<span class="b-threat">{t}</span>' for t in m.get('threat_tags',[])[:3]])␊
    dt = f"📅 {m.get('created_at','-')}" if created else f"🔄 {_ut(m.get('updated_at',''))}"␊
    return f"""<a target="_self" href="?menu=models&page=detail&model_id={m['id']}&auth=1" class="mc" onclick="event.preventDefault(); window.location.replace(this.href);">
    <div class="mc-h"><div><div class="mc-t">{m['name']}</div><div class="mc-v">{m['version']} · {m['algorithm']}</div></div>␊
    <div class="mc-b"><span class="b-log">{m['log_type']}</span><span class="b-type">{m['type']}</span></div></div>␊
    <div class="mc-d">{m.get('summary','')}</div><div class="mc-th">{tags}</div>␊
    <div class="mc-m"><div class="mc-st"><span>{dt}</span><span>⬇️ {m.get('downloads',0)}</span><span>👁️ {m.get('views',0)}</span></div>␊
    <span class="b-st {_sc(m.get('status','active'))}">{m.get('status','active')}</span></div></a>"""␊
␊
def highlight_json(json_str, search_term=""):␊
    """JSON 문자열에 신택스 하이라이팅 및 검색 하이라이팅 적용"""␊
    import re␊
    ␊
    # 라인별로 분할␊
    lines = json_str.split('\n')␊
    highlighted_lines = []␊
    ␊
    for i, line in enumerate(lines, 1):␊
        # 검색어 하이라이팅␊
        if search_term and search_term in line:␊
            line = line.replace(search_term, f'<span class="json-highlight">{search_term}</span>')␊
        ␊
        # JSON 신택스 하이라이팅␊
        # 키 (따옴표로 둘러싸인 문자열 뒤에 콜론이 오는 경우)␊
        line = re.sub(r'"([^"]+)"\s*:', r'<span class="json-key">"\1"</span>:', line)␊
        # 문자열 값␊
        line = re.sub(r':\s*"([^"]*)"', r': <span class="json-string">"\1"</span>', line)␊
        # 숫자␊
        line = re.sub(r'\b(\d+\.?\d*)\b', r'<span class="json-number">\1</span>', line)␊
        # boolean␊
        line = re.sub(r'\b(true|false)\b', r'<span class="json-boolean">\1</span>', line)␊
        # null␊
        line = re.sub(r'\bnull\b', r'<span class="json-null">null</span>', line)␊
        # 괄호␊
        line = re.sub(r'([{}[\]])', r'<span class="json-bracket">\1</span>', line)␊
        ␊
        highlighted_lines.append(f'<div class="json-line"><span class="json-line-number">{i}</span><span class="json-line-content">{line}</span></div>')␊
    ␊
    return '\n'.join(highlighted_lines)␊
␊
# ==================== 홈 ====================␊
if menu == "home":␊
    # 홈 화면 전용 스타일 (여기서 직접 정의하면 우선순위가 높음)␊
    st.markdown("""␊
    <style>␊
    /* 홈 화면 검색바 강제 스타일 적용 (.sh 이후의 HorizontalBlock만 선택) */␊
    .sh ~ div div[data-testid="stHorizontalBlock"] input[type="text"],␊
    .home-page-container div[data-testid="stHorizontalBlock"] input[type="text"] {␊
        height: 50px !important;␊
        padding: 0 1.5rem !important;␊
        border: 2px solid transparent !important;␊
        border-radius: 12px !important;␊
        background-color: #D9E8D8 !important;␊
        color: #0d0c22 !important;␊
        box-shadow: 0 0 5px #C1D9BF, 0 0 0 10px #f5f5f5eb !important;␊
        transition: all 0.3s ease !important;␊
        font-size: 1em !important;␊
    }␊
    ␊
    .sh ~ div div[data-testid="stHorizontalBlock"] input[type="text"]::placeholder,␊
    .home-page-container div[data-testid="stHorizontalBlock"] input[type="text"]::placeholder {␊
        color: #666 !important;␊
    }␊
    ␊
    .sh ~ div div[data-testid="stHorizontalBlock"] input[type="text"]:focus,␊
    .home-page-container div[data-testid="stHorizontalBlock"] input[type="text"]:focus {␊
        border-color: #00A98E !important;␊
        background-color: #e3f2e1 !important;␊
        box-shadow: 0 0 8px #00A98E, 0 0 0 10px #f5f5f5eb !important;␊
    }␊
    ␊
    /* 홈 화면 필터 버튼 */␊
    .sh ~ div div[data-testid="stHorizontalBlock"] button[kind="secondary"],␊
    .home-page-container div[data-testid="stHorizontalBlock"] button[kind="secondary"] {␊
        height: 50px !important;␊
        min-height: 50px !important;␊
        background: rgba(255, 255, 255, 0.95) !important;␊
        border: 2px solid #cbd5e0 !important;␊
        border-radius: 12px !important;␊
        color: #475569 !important;␊
        font-size: 1.8rem !important;␊
        font-weight: 300 !important;␊
        padding: 0 !important;␊
        transition: all 0.2s ease !important;␊
        box-shadow: 0 2px 4px rgba(0,0,0,0.05) !important;␊
    }␊
    ␊
    .sh ~ div div[data-testid="stHorizontalBlock"] button[kind="secondary"]:hover,␊
    .home-page-container div[data-testid="stHorizontalBlock"] button[kind="secondary"]:hover {␊
        background: #ffffff !important;␊
        border-color: #00A98E !important;␊
        color: #00A98E !important;␊
        box-shadow: 0 4px 12px rgba(0, 169, 142, 0.15) !important;␊
        transform: translateY(-1px) !important;␊
    }␊
    </style>␊
    """, unsafe_allow_html=True)␊
    ␊
    # 홈 화면 전체 컨테이너 시작␊
    st.markdown('<div class="home-page-container">', unsafe_allow_html=True)␊
    ␊
    st.markdown('<div class="sh"><h1>어떤 모델을 찾으시나요?</h1><p>IGLOO AI Model Hub에서 보안 위협 탐지 모델을 검색해보세요</p></div>', unsafe_allow_html=True)␊
␊
    # 검색바와 필터 버튼을 나란히 배치␊
    col1, col2 = st.columns([0.93, 0.07])␊
    ␊
    with col1:␊
        hs = st.text_input("", placeholder="🔍 모델명, 알고리즘, 위협 유형으로 검색하세요...", label_visibility="collapsed", key="hs")␊
    ␊
    with col2:␊
        if st.button("☰", key="hf", help="고급 필터", use_container_width=True):␊
            st.session_state.show_advanced_filters = not st.session_state.show_advanced_filters␊
␊
    if hs:␊
        st.query_params.update({"menu": "models", "page": "list", "search": hs, "auth": "1"})␊
        st.rerun()␊
␊
    if st.session_state.show_advanced_filters:␊
        with st.container(border=True):␊
            fc1, fc2, fc3 = st.columns(3)␊
            with fc1: sl = st.multiselect("로그 타입", ["WAF","WEB","Firewall","IDS","Syslog","Network","EDR"], key="hl")␊
            with fc2: sm = st.multiselect("모델 유형", ["지도학습","비지도학습"], key="hm")␊
            with fc3: sth = st.multiselect("위협 유형", ["SQL Injection","DDoS","XSS","Brute Force","Malware","Data Exfiltration","웹쉘","이상 트래픽"], key="ht")␊
            if st.button("🔍 모델 검색", type="primary", use_container_width=True):␊
                p = {"menu":"models","page":"list","auth":"1"}␊
                if sl: p["log_types"]=",".join(sl)␊
                if sm: p["model_types"]=",".join(sm)␊
                if sth: p["threats"]=",".join(sth)␊
                st.query_params.update(p)␊
                st.rerun()␊
␊
    st.markdown('<hr style="border:none;border-top:2px solid #e5e7eb;margin:40px 0 32px;">', unsafe_allow_html=True)␊
␊
    active = [m for m in store["models"] if m.get('status','active') == 'active']␊
    cl, cr = st.columns(2)␊
    with cl:␊
        st.markdown('<div class="sec-h"><div class="sec-t">Recently Added <span class="sec-ts">최근 등록</span></div><a target="_self" href="?menu=models&page=list&sort=created&auth=1" class="va-link" onclick="event.preventDefault(); window.location.replace(this.href);">전체보기 →</a></div>', unsafe_allow_html=True)
        for m in sorted(active, key=lambda x: x.get('created_at',''), reverse=True)[:4]:␊
            st.markdown(_card(m, True), unsafe_allow_html=True)␊
        if not active:␊
            st.markdown('<div class="empty"><div class="empty-i">📦</div><div class="empty-t">등록된 모델이 없습니다</div></div>', unsafe_allow_html=True)␊
    with cr:␊
        st.markdown('<div class="sec-h"><div class="sec-t">Recently Updated <span class="sec-ts">최근 업데이트</span></div><a target="_self" href="?menu=models&page=list&sort=updated&auth=1" class="va-link" onclick="event.preventDefault(); window.location.replace(this.href);">전체보기 →</a></div>', unsafe_allow_html=True)
        for m in sorted(active, key=lambda x: x.get('updated_at',''), reverse=True)[:4]:␊
            st.markdown(_card(m), unsafe_allow_html=True)␊
        if not active:␊
            st.markdown('<div class="empty"><div class="empty-i">🔄</div><div class="empty-t">업데이트된 모델이 없습니다</div></div>', unsafe_allow_html=True)␊
    ␊
    # 홈 화면 전체 컨테이너 닫기␊
    st.markdown('</div>', unsafe_allow_html=True)␊
␊
# ==================== Models (B안) ====================␊
elif menu == "models" and page == "list":␊
    url_s = _g("search","")␊
    url_l = [x for x in _g("log_types","").split(",") if x]␊
    url_t = [x for x in _g("model_types","").split(",") if x]␊
    url_th = [x for x in _g("threats","").split(",") if x]␊
    url_sort = _g("sort","updated")␊
␊
    sb, ct = st.columns([1, 3])␊
    with sb:␊
        st.markdown("#### 📊 로그 타입")␊
        sel_l = st.multiselect("로그", ["WAF","WEB","Firewall","IDS","Syslog","Network","EDR"], default=url_l, key="sl", label_visibility="collapsed")␊
        st.markdown("#### 🤖 모델 유형")␊
        sel_t = st.multiselect("유형", ["지도학습","비지도학습"], default=url_t, key="st2", label_visibility="collapsed")␊
        st.markdown("#### 🎯 위협 유형")␊
        sel_th = st.multiselect("위협", ["SQL Injection","XSS","DDoS","Malware","Data Exfiltration","Brute Force","웹쉘","이상 트래픽","내부정보유출"], default=url_th, key="sth2", label_visibility="collapsed")␊
        st.markdown("---")␊
        st.markdown("#### 📋 정렬")␊
        sm = {"최신 업데이트순":"updated","등록일순":"created","다운로드순":"downloads","조회수순":"views","이름순":"name"}␊
        di = list(sm.values()).index(url_sort) if url_sort in sm.values() else 0␊
        sb_sort = st.selectbox("정렬", list(sm.keys()), index=di, key="ss", label_visibility="collapsed")␊
        st.markdown("---")␊
        st.markdown("#### 📌 상태")␊
        sa = st.checkbox("사용 중", True, key="sa")␊
        ste = st.checkbox("테스트", True, key="ste")␊
        sp = st.checkbox("보류", False, key="sp")␊
␊
    with ct:␊
        search_q = st.text_input("", placeholder="🔍 모델명, 로그타입, 위협 유형, 설명 등으로 검색...", value=url_s, label_visibility="collapsed", key="ms")␊
␊
        allowed = []␊
        if sa: allowed.append('active')␊
        if ste: allowed.append('test')␊
        if sp: allowed.append('pending')␊
        fm = [m for m in store["models"] if m.get('status','active') in allowed]␊
␊
        if search_q:␊
            q = search_q.lower()␊
            fm = [m for m in fm if␊
                  q in m['name'].lower() or␊
                  q in m.get('summary','').lower() or␊
                  q in m.get('description','').lower() or␊
                  q in m.get('log_type','').lower() or␊
                  q in m.get('algorithm','').lower() or␊
                  q in m.get('detection_target','').lower() or␊
                  any(q in t.lower() for t in m.get('threat_tags',[]))]␊
        if sel_l: fm = [m for m in fm if m['log_type'] in sel_l]␊
        if sel_t: fm = [m for m in fm if m['type'] in sel_t]␊
        if sel_th: fm = [m for m in fm if any(t in m.get('threat_tags',[]) for t in sel_th)]␊
␊
        sf, sr = {"최신 업데이트순":('updated_at',True),"등록일순":('created_at',True),"다운로드순":('downloads',True),"조회수순":('views',True),"이름순":('name',False)}[sb_sort]␊
        fm = sorted(fm, key=lambda x: x.get(sf,''), reverse=sr)␊
        total = len(fm)␊
␊
        af = sel_l + sel_t + sel_th␊
        if search_q: af.insert(0, f"'{search_q}'")␊
        if af:␊
            st.markdown(f'<div style="background:#f0f9ff;border:1px solid #0ea5e9;border-radius:12px;padding:14px 18px;margin:0 0 20px"><span style="color:#0c4a6e;font-weight:600">🔍 검색 결과: {total}개</span><span style="color:#075985;font-size:.85em;margin-left:12px">{" · ".join(af[:5])}</span></div>', unsafe_allow_html=True)␊
        else:␊
            st.markdown(f"### 📦 전체 모델 ({total}개)")␊
␊
        PER = 9␊
        tp = math.ceil(total/PER) if total > 0 else 1␊
        cp = max(1, min(int(_g("p","1")), tp))␊
        pm = fm[(cp-1)*PER:cp*PER]␊
␊
        if not pm:␊
            st.markdown('<div class="empty"><div class="empty-i">🔍</div><div class="empty-t">검색 결과가 없습니다</div></div>', unsafe_allow_html=True)␊
        else:␊
            for i in range(0, len(pm), 3):␊
                cols = st.columns(3)␊
                for j in range(3):␊
                    if i+j < len(pm):␊
                        with cols[j]: st.markdown(_card(pm[i+j]), unsafe_allow_html=True)␊
␊
        if tp > 1:␊
            bp = {k:v for k,v in dict(qp).items() if k != 'p'}␊
            ph = '<div class="pg">'␊
            for pn in range(max(1,cp-2), min(tp,cp+2)+1):␊
                u = "?"+"&".join(f"{k}={v}" for k,v in {**bp,"p":str(pn)}.items())␊
                ph += f'<span class="pg-b on">{pn}</span>' if pn==cp else f'<a target="_self" href="{u}" class="pg-b" onclick="event.preventDefault(); window.location.replace(this.href);">{pn}</a>'
            ph += '</div>'␊
            st.markdown(ph, unsafe_allow_html=True)␊
␊
# ==================== 모델 상세 (돌아가기 버튼 제거) ====================␊
elif menu == "models" and page == "detail" and model_id:␊
    sel = next((m for m in store["models"] if str(m['id']) == str(model_id)), None)␊
    if sel:␊
        sel['views'] = sel.get('views',0) + 1␊
␊
        c1, c2 = st.columns([2,1])␊
        with c1:␊
            st.markdown(f"# {sel['name']}")␊
            st.markdown(f'<div style="display:flex;gap:8px;margin:12px 0 20px;flex-wrap:wrap"><span class="b-ver">{sel["version"]}</span><span class="b-log">{sel["log_type"]}</span><span class="b-type">{sel["type"]}</span><span class="b-st {_sc(sel.get("status","active"))}">{sel.get("status","active")}</span></div>', unsafe_allow_html=True)␊
            st.markdown(f"### {sel.get('summary','')}")␊
            st.markdown("#### 🎯 탐지 위협")␊
            st.markdown(" ".join([f'<span class="b-threat">{t}</span>' for t in sel.get('threat_tags',[])]), unsafe_allow_html=True)␊
            st.markdown("#### 📝 상세 설명")␊
            st.write(sel.get('description','상세 설명이 없습니다.'))␊
            if sel.get('features'):␊
                st.markdown("#### 🔍 주요 Features")␊
                st.markdown(" ".join([f"<span style='background:#f1f5f9;border:1px solid #e2e8f0;padding:6px 12px;border-radius:8px;font-size:.85em;color:#475569;display:inline-block;margin:2px'>{f}</span>" for f in sel['features']]), unsafe_allow_html=True)␊
        with c2:␊
            with st.container(border=True):␊
                st.markdown("#### ℹ️ 모델 정보")␊
                for l,v in [("🧠 알고리즘",sel['algorithm']),("📊 유형",sel['type']),("📋 로그 타입",sel['log_type']),("📦 버전",sel['version']),("💾 크기",sel['size']),("📅 등록일",sel['created_at']),("🔄 업데이트",sel['updated_at'])]:␊
                    st.markdown(f"**{l}:** {v}")␊
            mc1,mc2 = st.columns(2)␊
            with mc1: st.metric("⬇️ 다운로드", sel['downloads'])␊
            with mc2: st.metric("👁️ 조회수", sel['views'])␊
            if sel.get('has_file') and sel['id'] in store["model_files"]:␊
                fi = store["model_files"][sel['id']]␊
                if st.download_button("⬇️ 다운로드", data=fi['data'], file_name=fi['filename'], mime=fi['type'], use_container_width=True, type="primary"):␊
                    sel['downloads'] += 1␊
            if st.button("📝 설정 파일 편집", use_container_width=True):␊
                st.query_params.update({"menu":"models","page":"json_editor","model_id":str(model_id),"auth":"1"}); st.rerun()␊
            with st.expander("💬 피드백"):␊
                fr = st.selectbox("평점", [5,4,3,2,1], format_func=lambda x: "⭐"*x)␊
                ft = st.text_area("의견", placeholder="이 모델에 대한 의견을 남겨주세요...")␊
                if st.button("제출", use_container_width=True):␊
                    if ft.strip():␊
                        store["feedback"].append({'model_id':sel['id'],'model_name':sel['name'],'rating':fr,'feedback':ft,'timestamp':datetime.now().strftime("%Y-%m-%d %H:%M:%S"),'user':user_name})␊
                        st.success("✅ 제출 완료!"); st.rerun()␊
␊
        st.markdown("<br>", unsafe_allow_html=True)␊
        t1,t2,t3,t4 = st.tabs(["⚙️ 파라미터","📌 필수 필드","🎯 MITRE ATT&CK","📊 데이터셋"])␊
        with t1:␊
            try: st.json(json.loads(sel.get('parameters','{}')))␊
            except: st.code(sel.get('parameters','{}'), language='json')␊
        with t2:␊
            if sel.get('required_fields'):␊
                for f in sel['required_fields']: st.markdown(f"- `{f}`")␊
            st.warning("⚠️ 환경별로 로그 필드명이 다를 수 있습니다.")␊
        with t3:␊
            if sel.get('mitre_tactics'): st.markdown("**전술:** " + ", ".join([f"`{t}`" for t in sel['mitre_tactics']]))␊
            if sel.get('mitre_techniques'): st.markdown("**기술:** " + ", ".join([f"`{t}`" for t in sel['mitre_techniques']]))␊
        with t4:␊
            if sel.get('dataset_settings'): st.json(sel['dataset_settings'])␊
    else:␊
        st.error("❌ 모델을 찾을 수 없습니다.")␊
␊
# ==================== JSON 편집기 (개선됨) ====================␊
elif menu == "models" and page == "json_editor" and model_id:␊
    sel = next((m for m in store["models"] if str(m['id']) == str(model_id)), None)␊
    if sel:␊
        st.markdown(f"## 📝 설정 파일 편집: {sel['name']}")␊
        st.markdown("**임시 편집 모드** — 원본은 변경되지 않습니다. 편집 후 다운로드 버튼을 눌러 저장하세요.")␊
        ␊
        # 사용자 세션별 키␊
        tk = f"{user_name}_{model_id}"␊
        ␊
        # 업로드된 JSON 파일에서 초기 데이터 가져오기 (fields 포함)␊
        if tk not in st.session_state.temp_json_editor:␊
            # 실제 업로드된 JSON 파일 전체를 사용␊
            # Management 탭에서 업로드 시 저장된 JSON 데이터 사용␊
            if sel['id'] in store["model_files"]:␊
                try:␊
                    uploaded_json = json.loads(store["model_files"][sel['id']]['data'].decode('utf-8'))␊
                    st.session_state.temp_json_editor[tk] = uploaded_json␊
                except:␊
                    # 파일이 없거나 파싱 실패 시 기본 템플릿 사용␊
                    st.session_state.temp_json_editor[tk] = {␊
                        "data": [{␊
                            "ruleName": sel['name'],␊
                            "note": sel.get('summary',''),␊
                            "algorithm": sel['algorithm'].replace(" ","").lower(),␊
                            "algorithmSettings": json.loads(sel.get('parameters','{}')),␊
                            "logType": [sel['log_type'].lower()],␊
                            "formatTime": {"unit":"MINUTE","amount":"10"},␊
                            "datasetSettings": sel.get('dataset_settings',{}),␊
                            "fadingFactor": sel.get('trigger_settings',{}).get('fadingFactor',''),␊
                            "boundType": sel.get('trigger_settings',{}).get('boundType',''),␊
                            "sensitivity": sel.get('trigger_settings',{}).get('sensitivity',''),␊
                            "options": {␊
                                "mitre": [{"tacticsId":t,"techniquesId":""} for t in sel.get('mitre_tactics',[])]␊
                            }␊
                        }],␊
                        "rulegroups": [{"name": sel.get('detection_target','')}],␊
                        "fields": []  # fields 필드 추가␊
                    }␊
            else:␊
                # 기본 템플릿␊
                st.session_state.temp_json_editor[tk] = {␊
                    "data": [{␊
                        "ruleName": sel['name'],␊
                        "note": sel.get('summary',''),␊
                        "algorithm": sel['algorithm'].replace(" ","").lower(),␊
                        "algorithmSettings": json.loads(sel.get('parameters','{}')),␊
                        "logType": [sel['log_type'].lower()],␊
                        "formatTime": {"unit":"MINUTE","amount":"10"},␊
                        "datasetSettings": sel.get('dataset_settings',{}),␊
                        "fadingFactor": sel.get('trigger_settings',{}).get('fadingFactor',''),␊
                        "boundType": sel.get('trigger_settings',{}).get('boundType',''),␊
                        "sensitivity": sel.get('trigger_settings',{}).get('sensitivity',''),␊
                        "options": {␊
                            "mitre": [{"tacticsId":t,"techniquesId":""} for t in sel.get('mitre_tactics',[])]␊
                        }␊
                    }],␊
                    "rulegroups": [{"name": sel.get('detection_target','')}],␊
                    "fields": []␊
                }␊
        ␊
        # JSON 에디터 카드␊
        st.markdown('<div class="json-editor-card"><div class="json-editor-wrap"><div class="json-editor-terminal">', unsafe_allow_html=True)␊
        ␊
        # 헤더 (제목 + 검색창)␊
        st.markdown(f'''␊
        <div class="json-editor-head">␊
            <div class="json-editor-title">␊
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">␊
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>␊
                    <polyline points="14 2 14 8 20 8"></polyline>␊
                    <line x1="12" y1="18" x2="12" y2="12"></line>␊
                    <line x1="9" y1="15" x2="15" y2="15"></line>␊
                </svg>␊
                {sel['name']}_config.json␊
            </div>␊
            <div class="json-search-box">␊
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">␊
                    <circle cx="11" cy="11" r="8"></circle>␊
                    <path d="m21 21-4.35-4.35"></path>␊
                </svg>␊
                <input type="text" placeholder="Search..." id="json-search-input" onkeyup="highlightSearch(this.value)">␊
            </div>␊
        </div>␊
        ''', unsafe_allow_html=True)␊
        ␊
        # JSON 내용을 textarea로 수정 가능하게␊
        current_json = json.dumps(st.session_state.temp_json_editor[tk], indent=2, ensure_ascii=False)␊
        ␊
        # 실제 편집 가능한 텍스트 영역␊
        edited_json = st.text_area(␊
            "JSON 편집",␊
            value=current_json,␊
            height=500,␊
            key=f"json_edit_{tk}",␊
            label_visibility="collapsed"␊
        )␊
        ␊
        # JSON body (하이라이팅 적용된 미리보기)␊
        search_term = st.session_state.get('json_search_term', '')␊
        highlighted_html = highlight_json(edited_json, search_term)␊
        ␊
        st.markdown(f'</div></div></div>', unsafe_allow_html=True)␊
        ␊
        # 버튼들␊
        c1,c2,c3 = st.columns([2,1,1])␊
        with c1:␊
            try:␊
                pj = json.loads(edited_json)␊
                st.success("✅ JSON 유효")␊
                st.session_state.temp_json_editor[tk] = pj␊
            except json.JSONDecodeError as e:␊
                st.error(f"❌ JSON 오류: {e}")␊
                pj = None␊
        ␊
        with c2:␊
            if st.button("🔄 초기화", key=f"reset_{tk}"):␊
                # 초기화: 세션에서 해당 키 삭제하여 다시 로드되도록␊
                if tk in st.session_state.temp_json_editor:␊
                    del st.session_state.temp_json_editor[tk]␊
                st.rerun()␊
        ␊
        with c3:␊
            if pj:␊
                st.download_button(␊
                    "💾 다운로드",␊
                    data=json.dumps(pj, indent=2, ensure_ascii=False).encode('utf-8'),␊
                    file_name=f"{sel['name'].replace(' ','_')}_config.json",␊
                    mime="application/json",␊
                    type="primary",␊
                    use_container_width=True␊
                )␊
␊
# ==================== Management ====================␊
elif menu == "management":␊
    st.markdown("## 🛠️ Model Management")␊
    st.markdown("<br>", unsafe_allow_html=True)␊
    tab1,tab2,tab3,tab4 = st.tabs(["➕ 모델 등록","📊 모델 관리","💬 피드백","📋 통계"])␊
␊
    with tab1:␊
        st.markdown("### 새 모델 등록")␊
        reg = st.radio("등록 방식:", ["🖋️ 수동 입력","📄 JSON 파일 자동 입력"], horizontal=True)␊
␊
        jd = None␊
        if reg == "📄 JSON 파일 자동 입력":␊
            st.markdown("#### 1️⃣ JSON 설정 파일 업로드")␊
            uj = st.file_uploader("모델 설정 JSON 파일을 업로드하세요", type=['json'], key="json_up")␊
            if uj:␊
                try:␊
                    raw = json.load(uj)␊
                    d0 = raw.get('data', [{}])␊
                    if isinstance(d0, list): d0 = d0[0] if d0 else {}␊
                    rg = raw.get('rulegroups', [{}])␊
                    if isinstance(rg, list): rg = rg[0] if rg else {}␊
␊
                    jd = {␊
                        'ruleName': d0.get('ruleName', ''),␊
                        'note': d0.get('note', ''),␊
                        'ruleGroupName': rg.get('name', '') or d0.get('ruleGroupName', ''),␊
                        'algorithm': d0.get('algorithm', ''),␊
                        'algorithmSettings': d0.get('algorithmSettings', {}),␊
                        'logType': d0.get('logType', []),␊
                        'formatTime': d0.get('formatTime', {}),␊
                        'datasetAnalyzeType': d0.get('datasetAnalyzeType', ''),␊
                        'datasetSettings': d0.get('datasetSettings', {}),␊
                        'fadingFactor': d0.get('fadingFactor', ''),␊
                        'boundType': d0.get('boundType', ''),␊
                        'sensitivity': d0.get('sensitivity', ''),␊
                        'mitre_list': d0.get('options', {}).get('mitre', []),␊
                        'fields': raw.get('fields', []),␊
                        'raw_json': raw  # 전체 JSON 저장␊
                    }␊
                    st.session_state['_jd_cache'] = jd␊
                    st.success(f"✅ 파일 로드 완료! 모델명: **{jd['ruleName']}**")␊
                    with st.expander("📋 파싱된 주요 정보"):␊
                        st.json({k:v for k,v in jd.items() if k not in ['fields', 'raw_json']})␊
                except Exception as e:␊
                    st.error(f"❌ JSON 파싱 오류: {e}")␊
            elif '_jd_cache' in st.session_state:␊
                jd = st.session_state['_jd_cache']␊
            st.markdown("#### 2️⃣ 자동 입력된 정보 확인 및 수정")␊
        else:␊
            st.markdown("#### 모델 정보 입력")␊
            if '_jd_cache' in st.session_state:␊
                del st.session_state['_jd_cache']␊
␊
        with st.form("reg_form"):␊
            c1, c2 = st.columns(2)␊
            with c1:␊
                model_name = st.text_input("모델명 *", value=jd['ruleName'] if jd else '')␊
                detection_target = st.text_input("탐지 목적 *", value=jd['ruleGroupName'] if jd else '')␊
                model_version = st.text_input("버전 *", value="v1.0.0")␊
␊
                type_opts = ["지도학습","비지도학습"]␊
                auto_type_idx = 0␊
                if jd:␊
                    alg = jd.get('algorithm','').lower()␊
                    if alg in ['randomforest','svm','logisticregression','xgboost','decisiontree']:␊
                        auto_type_idx = 0␊
                    elif alg in ['isolationforest','robustrandomcutforest','rrcf','autoencoder','dbscan','oneclasssvm']:␊
                        auto_type_idx = 1␊
                model_type = st.selectbox("모델 유형 *", type_opts, index=auto_type_idx)␊
␊
                alg_map = {␊
                    "지도학습": ["Random Forest","SVM","Logistic Regression","XGBoost","Decision Tree"],␊
                    "비지도학습": ["RRCF","Isolation Forest","Autoencoder","DBSCAN","One-Class SVM"]␊
                }␊
                auto_alg_idx = 0␊
                if jd:␊
                    name_map = {'robustrandomcutforest':'RRCF','rrcf':'RRCF','isolationforest':'Isolation Forest','randomforest':'Random Forest','svm':'SVM','xgboost':'XGBoost','autoencoder':'Autoencoder','dbscan':'DBSCAN','decisiontree':'Decision Tree','logisticregression':'Logistic Regression','oneclasssvm':'One-Class SVM'}␊
                    mapped = name_map.get(jd.get('algorithm','').lower(), '')␊
                    if mapped in alg_map[model_type]:␊
                        auto_alg_idx = alg_map[model_type].index(mapped)␊
                algorithm = st.selectbox("알고리즘 *", alg_map[model_type], index=auto_alg_idx)␊
␊
            with c2:␊
                log_opts = ["WAF","WEB","Firewall","IDS","Syslog","Network","EDR"]␊
                auto_log_idx = 0␊
                if jd and jd.get('logType'):␊
                    lt = jd['logType'][0].lower() if isinstance(jd['logType'], list) and jd['logType'] else ''␊
                    lmap = {'fw':'Firewall','waf':'WAF','web':'WEB','ids':'IDS','ips':'IDS','syslog':'Syslog','network':'Network','edr':'EDR'}␊
                    ml = lmap.get(lt, '')␊
                    if ml in log_opts: auto_log_idx = log_opts.index(ml)␊
                log_type = st.selectbox("로그 타입 *", log_opts, index=auto_log_idx)␊
␊
                threat_tags = st.multiselect("위협 태그 *", ["SQL Injection","XSS","DDoS","Malware","Data Exfiltration","Brute Force","웹쉘","이상 트래픽","내부정보유출","Command Injection"])␊
␊
                m_tactics_val = ''␊
                m_tech_val = ''␊
                if jd and jd.get('mitre_list') and isinstance(jd['mitre_list'], list):␊
                    tacs = [m.get('tacticsId','') for m in jd['mitre_list'] if isinstance(m,dict) and m.get('tacticsId')]␊
                    techs = [m.get('techniquesId','') for m in jd['mitre_list'] if isinstance(m,dict) and m.get('techniquesId')]␊
                    m_tactics_val = ', '.join(tacs)␊
                    m_tech_val = ', '.join(techs)␊
                mitre_tactics = st.text_input("MITRE Tactics", value=m_tactics_val)␊
                mitre_techniques = st.text_input("MITRE Techniques", value=m_tech_val)␊
␊
                summary = st.text_input("한줄 설명 *", value=jd['note'] if jd else '')␊
                model_status = st.selectbox("상태 *", ["active","pending","test"], format_func=lambda x: {"active":"사용","pending":"보류","test":"테스트"}[x])␊
␊
            detailed_desc = st.text_area("상세 설명", height=80)␊
            uploaded_file = st.file_uploader("모델 파일 업로드", type=['pkl','h5','pt','pth','onnx','joblib','json'], key="mf_up")␊
␊
            with st.expander("🔧 고급 설정 (파라미터 / 데이터셋 / 트리거)", expanded=True if jd else False):␊
                ca, cb = st.columns(2)␊
                with ca:␊
                    auto_params = json.dumps(jd['algorithmSettings'], indent=2, ensure_ascii=False) if jd and jd.get('algorithmSettings') else '{}'␊
                    model_params = st.text_area("모델 파라미터 (JSON)", value=auto_params, height=120)␊
␊
                    auto_fields = ""␊
                    if jd and jd.get('datasetSettings'):␊
                        ds = jd['datasetSettings']␊
                        parts = []␊
                        parts.extend(ds.get('features', []))␊
                        parts.extend(ds.get('keyFields', []))␊
                        parts.extend(ds.get('anomalySubject', ds.get('anomalySplit', [])))␊
                        auto_fields = ", ".join(parts) if parts else ""␊
                    req_fields = st.text_area("필수 로그 필드 (쉼표 구분)", value=auto_fields or "timestamp, src_ip, dst_ip")␊
␊
                with cb:␊
                    auto_ds = {}␊
                    if jd:␊
                        auto_ds = {␊
                            "logType": jd.get('logType', []),␊
                            "formatTime": jd.get('formatTime', {}),␊
                            "datasetAnalyzeType": jd.get('datasetAnalyzeType', ''),␊
                            "datasetSettings": jd.get('datasetSettings', {})␊
                        }␊
                    dataset_cfg = st.text_area("데이터셋 설정 (JSON)", value=json.dumps(auto_ds, indent=2, ensure_ascii=False) if auto_ds else '{}', height=120)␊
␊
                    auto_tr = {}␊
                    if jd:␊
                        for k in ['fadingFactor','boundType','sensitivity']:␊
                            v = jd.get(k, '')␊
                            if v != '': auto_tr[k] = v␊
                    trigger_cfg = st.text_area("트리거 설정 (JSON)", value=json.dumps(auto_tr, indent=2, ensure_ascii=False) if auto_tr else '{}', height=100)␊
␊
            submitted = st.form_submit_button("📦 모델 등록", type="primary", use_container_width=True)␊
            if submitted:␊
                if model_name and detection_target and threat_tags and summary:␊
                    new_id = max([m['id'] for m in store["models"]], default=0) + 1␊
                    file_size = "0 MB"␊
                    if uploaded_file:␊
                        file_size = f"{uploaded_file.size/(1024*1024):.2f} MB"␊
                        # JSON 파일이면 원본 JSON 저장, 아니면 바이너리 저장␊
                        if uploaded_file.type == "application/json":␊
                            store["model_files"][new_id] = {␊
                                'filename': uploaded_file.name,␊
                                'data': uploaded_file.getvalue(),␊
                                'type': uploaded_file.type␊
                            }␊
                        else:␊
                            store["model_files"][new_id] = {␊
                                'filename': uploaded_file.name,␊
                                'data': uploaded_file.getvalue(),␊
                                'type': uploaded_file.type␊
                            }␊
                    elif jd and 'raw_json' in jd:␊
                        # JSON 자동 입력 시 원본 JSON 저장␊
                        store["model_files"][new_id] = {␊
                            'filename': f"{model_name}_config.json",␊
                            'data': json.dumps(jd['raw_json'], indent=2, ensure_ascii=False).encode('utf-8'),␊
                            'type': 'application/json'␊
                        }␊
␊
                    new_model = {␊
                        'id': new_id, 'name': model_name, 'algorithm': algorithm, 'type': model_type,␊
                        'log_type': log_type, 'version': model_version, 'size': file_size,␊
                        'model_id': f"model_{uuid.uuid4().hex[:8]}", 'status': model_status,␊
                        'summary': summary, 'description': detailed_desc, 'detection_target': detection_target,␊
                        'threat_tags': threat_tags, 'required_fields': [f.strip() for f in req_fields.split(',') if f.strip()],␊
                        'created_at': datetime.now().strftime("%Y-%m-%d"), 'updated_at': datetime.now().strftime("%Y-%m-%d"),␊
                        'downloads': 0, 'views': 0, 'has_file': uploaded_file is not None or (jd and 'raw_json' in jd),␊
                        'mitre_tactics': [t.strip() for t in mitre_tactics.split(',') if t.strip()],␊
                        'mitre_techniques': [t.strip() for t in mitre_techniques.split(',') if t.strip()],␊
                        'parameters': model_params, 'features': []␊
                    }␊
                    try:␊
                        if dataset_cfg: new_model['dataset_settings'] = json.loads(dataset_cfg)␊
                        if trigger_cfg: new_model['trigger_settings'] = json.loads(trigger_cfg)␊
                    except: pass␊
␊
                    store["models"].append(new_model)␊
                    st.success(f"✅ '{model_name}' 등록 완료!")␊
                    if '_jd_cache' in st.session_state:␊
                        del st.session_state['_jd_cache']␊
                else:␊
                    st.error("⚠️ 필수 항목(*)을 모두 입력해주세요")␊
␊
    with tab2:␊
        st.markdown("### 등록된 모델 관리")␊
        if not store["models"]:␊
            st.info("등록된 모델이 없습니다.")␊
        else:␊
            sf = st.selectbox("상태", ["전체","active","pending","test"], format_func=lambda x: {"전체":"전체","active":"사용","pending":"보류","test":"테스트"}.get(x,x))␊
            ml = store["models"] if sf == "전체" else [m for m in store["models"] if m.get('status','active') == sf]␊
            for model in ml:␊
                with st.container(border=True):␊
                    mc1,mc2,mc3 = st.columns([3,2,1])␊
                    with mc1:␊
                        st.markdown(f"### {model['name']}")␊
                        st.markdown(f"**{model['version']}** | {model['algorithm']} | {model['type']}")␊
                        st.markdown(" ".join([f'<span class="b-threat">{t}</span>' for t in model.get('threat_tags',[])]), unsafe_allow_html=True)␊
                    with mc2:␊
                        st.markdown(f"등록: {model['created_at']} | 업데이트: {model['updated_at']}")␊
                        st.markdown(f"⬇️ {model.get('downloads',0)} | 👁️ {model.get('views',0)}")␊
                    with mc3:␊
                        ns = st.selectbox("상태",["active","pending","test"],index=["active","pending","test"].index(model.get('status','active')),format_func=lambda x:{"active":"사용","pending":"보류","test":"테스트"}[x],key=f"st_{model['id']}")␊
                        if ns != model.get('status','active'):␊
                            model['status'] = ns; model['updated_at'] = datetime.now().strftime("%Y-%m-%d"); st.rerun()␊
                        if st.button("🗑️ 삭제", key=f"d_{model['id']}", use_container_width=True):␊
                            st.session_state[f"cd_{model['id']}"] = True␊
                        if st.session_state.get(f"cd_{model['id']}"):␊
                            st.warning(f"'{model['name']}' 삭제?")␊
                            dc1,dc2 = st.columns(2)␊
                            with dc1:␊
                                if st.button("확인",key=f"cf_{model['id']}",type="primary"):␊
                                    store["models"] = [m for m in store["models"] if m['id']!=model['id']]; st.rerun()␊
                            with dc2:␊
                                if st.button("취소",key=f"cc_{model['id']}"):␊
                                    st.session_state[f"cd_{model['id']}"]=False; st.rerun()␊
␊
    with tab3:␊
        st.markdown("### 피드백")␊
        if not store["feedback"]: st.info("피드백이 없습니다.")␊
        else:␊
            avg = sum(f['rating'] for f in store["feedback"]) / len(store["feedback"])␊
            fc1,fc2 = st.columns(2)␊
            with fc1: st.metric("총 피드백", f"{len(store['feedback'])}개")␊
            with fc2: st.metric("평균 평점", f"{avg:.1f}/5.0")␊
            for fb in reversed(store["feedback"]):␊
                with st.container(border=True):␊
                    st.markdown(f"**{fb['model_name']}** — {'⭐'*fb['rating']}")␊
                    st.markdown(f"_{fb['feedback']}_ ({fb['user']}, {fb['timestamp']})")␊
␊
    with tab4:␊
        st.markdown("### 📊 통계")␊
        c1,c2,c3,c4 = st.columns(4)␊
        with c1: st.metric("전체", len(store["models"]))␊
        with c2: st.metric("사용 중", len([m for m in store["models"] if m.get('status','active')=='active']))␊
        with c3: st.metric("다운로드", f"{sum(m.get('downloads',0) for m in store['models']):,}")␊
        with c4: st.metric("조회수", f"{sum(m.get('views',0) for m in store['models']):,}")␊
        if store["models"]:␊
            cc1,cc2 = st.columns(2)␊
            with cc1:␊
                lc = {}␊
                for m in store["models"]: lc[m['log_type']] = lc.get(m['log_type'],0)+1␊
                st.bar_chart(pd.DataFrame(list(lc.items()), columns=['타입','수']).set_index('타입'))␊
            with cc2:␊
                tc = {}␊
                for m in store["models"]: tc[m['type']] = tc.get(m['type'],0)+1␊
                st.bar_chart(pd.DataFrame(list(tc.items()), columns=['유형','수']).set_index('유형'))␊
␊
# ==================== 공지사항 ====================␊
elif menu == "notice":␊
    st.markdown("## 📢 공지사항")␊
    st.caption("IGLOO AI Model Hub 운영 및 업데이트 공지")␊
    notices = [␊
        {'title':'🔔 IGLOO AI Model Hub v2.0 정식 출시','date':'2024-02-11','author':'관리자','content':'전면 개편된 UI/UX, 향상된 검색/필터링, 웹 기반 JSON 편집기, 피드백 시스템.','imp':True},␊
        {'title':'📋 JSON 설정 파일 편집 기능 추가','date':'2024-02-10','author':'관리자','content':'환경별 로그 필드명 차이를 해소하기 위해 웹 기반 JSON 편집 기능을 추가했습니다.','imp':False},␊
        {'title':'🛠️ 정기 시스템 점검 안내','date':'2024-02-08','author':'관리자','content':'2024년 2월 15일 02:00~06:00 점검 예정.','imp':False}␊
    ]␊
    for n in notices:␊
        with st.container(border=True):␊
            tc1,tc2 = st.columns([3,1])␊
            with tc1: st.markdown(f"### {'🔥 ' if n['imp'] else ''}{n['title']}")␊
            with tc2: st.markdown(f"**{n['date']}** · {n['author']}")␊
            with st.expander("자세히 보기", expanded=n['imp']): st.markdown(n['content'])␊
␊
# ==================== Docs (돌아가기 버튼 제거) ====================␊
elif menu == "docs" and _g("page","") != "view":␊
    st.markdown("## 📚 Documentation")␊
    st.caption("IGLOO AI Model Hub 사용 가이드 및 기술 문서")␊
    st.markdown("<br>", unsafe_allow_html=True)␊
␊
    cats = sorted(set([d['category'] for d in store["docs"]]))␊
    sel_cat = st.selectbox("카테고리", ["전체"] + cats, key="dc")␊
    dl = store["docs"] if sel_cat == "전체" else [d for d in store["docs"] if d['category'] == sel_cat]␊
␊
    if dl:␊
        st.markdown("---")␊
        hc = st.columns([0.4, 4.5, 1.2, 1, 1, 0.6])␊
        with hc[0]: st.markdown("**#**")␊
        with hc[1]: st.markdown("**제목**")␊
        with hc[2]: st.markdown("**카테고리**")␊
        with hc[3]: st.markdown("**작성자**")␊
        with hc[4]: st.markdown("**작성일**")␊
        with hc[5]: st.markdown("**조회**")␊
        st.markdown("---")␊
␊
        for doc in dl:␊
            rc = st.columns([0.4, 4.5, 1.2, 1, 1, 0.6])␊
            with rc[0]:␊
                st.caption(str(doc['id']))␊
            with rc[1]:␊
                fi = " 📎" if doc.get('file_attached') else ""␊
                if st.button(f"{doc['title']}{fi}", key=f"doc_{doc['id']}"):␊
                    st.query_params.update({"menu":"docs","page":"view","doc_id":str(doc['id']),"auth":"1"})␊
                    st.rerun()␊
            with rc[2]:␊
                st.caption(doc['category'])␊
            with rc[3]:␊
                st.caption(doc['author'])␊
            with rc[4]:␊
                st.caption(doc['date'])␊
            with rc[5]:␊
                st.caption(str(doc['views']))␊
    else:␊
        st.markdown('<div class="empty"><div class="empty-i">📄</div><div class="empty-t">등록된 문서가 없습니다</div></div>', unsafe_allow_html=True)␊
␊
elif menu == "docs" and _g("page","") == "view":␊
    did = int(_g("doc_id","0"))␊
    doc = next((d for d in store["docs"] if d['id'] == did), None)␊
    if doc:␊
        doc['views'] += 1␊
        st.markdown(f"## {doc['title']}")␊
        st.markdown(f"**{doc['category']}** · {doc['author']} · {doc['date']} · 조회 {doc['views']}")␊
        st.markdown("---")␊
        st.markdown(doc['content'])␊
        if doc.get('file_attached'):␊
            st.download_button("📎 첨부파일", data=doc['content'].encode('utf-8'), file_name=f"{doc['title']}.md", mime="text/markdown")␊
    else:␊
        st.error("문서를 찾을 수 없습니다.")␊
␊
# ==================== Docs 작성 (돌아가기 버튼 제거) ====================␊
elif menu == "docs_write":␊
    st.markdown("## ✏️ 새 문서 작성")␊
    with st.form("doc_form"):␊
        dt = st.text_input("문서 제목 *")␊
        dcat = st.selectbox("카테고리 *", ["사용자 가이드","기술 문서","운영 가이드","API 문서","FAQ"])␊
        dcont = st.text_area("내용 *", height=300, placeholder="마크다운 형식으로 작성 가능합니다.")␊
        dfile = st.file_uploader("첨부파일 (선택)", type=['pdf','docx','txt','md','json','zip'])␊
        if st.form_submit_button("📋 문서 등록", type="primary"):␊
            if dt and dcont:␊
                store["docs"].append({'id':len(store["docs"])+1,'title':dt,'category':dcat,'author':user_name,'date':datetime.now().strftime("%Y-%m-%d"),'views':0,'content':dcont,'file_attached':dfile is not None})␊
                st.success(f"✅ '{dt}' 등록 완료!")␊
            else: st.error("⚠️ 필수 항목을 입력해주세요")␊
