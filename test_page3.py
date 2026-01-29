import streamlit as st
import pandas as pd
import json
from datetime import datetime

# 페이지 설정
st.set_page_config(page_title="Model Hub", layout="wide")

# 세션 상태 초기화
if 'models' not in st.session_state:
    st.session_state.models = []
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = False
if 'model_files' not in st.session_state:
    st.session_state.model_files = {}

# CSS 스타일
st.markdown("""
<style>
    /* 전체 배경 */
    .main {
        background-color: #f5f7fa;
    }
    
    /* 위협 태그 */
    .threat-tag {
        display: inline-block;
        background-color: #fff3e0;
        color: #e65100;
        padding: 5px 12px;
        border-radius: 16px;
        margin-right: 6px;
        margin-bottom: 8px;
        font-size: 0.8em;
        font-weight: 600;
        border: 1px solid #ffb74d;
    }
    
    /* 일반 태그 */
    .tag {
        display: inline-block;
        background-color: #e3f2fd;
        color: #1565c0;
        padding: 5px 12px;
        border-radius: 16px;
        margin-right: 6px;
        margin-bottom: 8px;
        font-size: 0.8em;
        border: 1px solid #90caf9;
    }
    
    /* 배지 */
    .version-badge {
        display: inline-block;
        background-color: #f5f5f5;
        color: #616161;
        padding: 4px 10px;
        border-radius: 8px;
        font-size: 0.75em;
        margin-right: 8px;
    }
    
    .log-badge {
        display: inline-block;
        background-color: #e8eaf6;
        color: #3f51b5;
        padding: 4px 10px;
        border-radius: 12px;
        font-size: 0.75em;
        font-weight: 600;
    }
    
    /* Metric 스타일 */
    div[data-testid="stMetric"] {
        background-color: #fafafa;
        padding: 10px;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

# 페이지 라우팅
query_params = st.query_params
page = query_params.get("page", "list")
model_id = query_params.get("model_id", None)

# 사이드바
if page == "list":
    with st.sidebar:
        st.title("🔐 사용자 모드")
        is_admin = st.checkbox("관리자 모드", value=st.session_state.is_admin)
        st.session_state.is_admin = is_admin
        
        st.markdown("---")
        st.title("🔍 필터")
        
        search_query = st.text_input("모델 검색", placeholder="모델명 검색...")
        model_type_filter = st.multiselect("모델 유형", ["지도학습", "비지도학습"])
        threat_filter = st.multiselect(
            "위협 유형",
            ["SQL Injection", "XSS", "DDoS", "Malware", "Data Exfiltration", 
             "Privilege Escalation", "Brute Force", "웹쉘", "이상 트래픽"]
        )
        log_type_filter = st.multiselect("로그 타입", ["WAF", "WEB", "Firewall", "IDS", "Syslog", "Network"])
        sort_by = st.selectbox("정렬 기준", ["최신순", "다운로드순", "조회순", "이름순"])

# ==================== 리스트 페이지 ====================
if page == "list":
    st.title("🤖 ML Model Hub")
    st.markdown("### 이상 탐지 모델 저장소")

    # 통계
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("전체 모델", len(st.session_state.models))
    with col2:
        st.metric("총 다운로드", sum([m.get('downloads', 0) for m in st.session_state.models]))
    with col3:
        st.metric("총 조회수", sum([m.get('views', 0) for m in st.session_state.models]))

    st.markdown("---")

    # 관리자 - 모델 추가
    if st.session_state.is_admin:
        with st.expander("➕ 새 모델 추가"):
            with st.form("add_model_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    model_name = st.text_input("모델명 *")
                    algorithm = st.text_input("사용 알고리즘 *")
                    model_type = st.selectbox("모델 유형 *", ["지도학습", "비지도학습"])
                    log_type = st.selectbox("로그 타입 *", ["WAF", "WEB", "Firewall", "IDS", "Syslog", "Network"])
                
                with col2:
                    version = st.text_input("버전", "v1.0.0")
                    detection_target = st.text_input("탐지 목적")
                    data_count = st.number_input("데이터 개수", min_value=0, value=10000)
                
                uploaded_file = st.file_uploader("모델 파일", type=['pkl', 'h5', 'pt', 'pth', 'onnx', 'joblib', 'json'])
                threat_tags = st.multiselect(
                    "위협 태그 *",
                    ["SQL Injection", "XSS", "DDoS", "Malware", "Data Exfiltration", 
                     "Privilege Escalation", "Brute Force", "웹쉘", "이상 트래픽"]
                )
                
                summary = st.text_input("한줄 설명 *")
                model_desc = st.text_area("상세 설명")
                features = st.text_area("주요 Feature (쉼표 구분)")
                tags = st.text_input("일반 태그 (쉼표 구분)")
                params = st.text_area("파라미터 (JSON)", '{"shingle_size": 4, "num_trees": 100}')
                required_fields = st.text_area("필수 필드 (쉼표 구분)", "timestamp, src_ip, dst_ip, protocol")
                
                submitted = st.form_submit_button("모델 추가", use_container_width=True)
                
                if submitted and model_name and algorithm and threat_tags and summary:
                    new_id = len(st.session_state.models) + 1
                    file_size = "0 MB"
                    
                    if uploaded_file:
                        file_size = f"{uploaded_file.size / (1024*1024):.2f} MB"
                        st.session_state.model_files[new_id] = {
                            'filename': uploaded_file.name,
                            'data': uploaded_file.getvalue(),
                            'type': uploaded_file.type
                        }
                    
                    new_model = {
                        'id': new_id,
                        'name': model_name,
                        'algorithm': algorithm,
                        'type': model_type,
                        'log_type': log_type,
                        'version': version,
                        'size': file_size,
                        'summary': summary,
                        'description': model_desc,
                        'detection_target': detection_target,
                        'threat_tags': threat_tags,
                        'features': [f.strip() for f in features.split(',') if f.strip()],
                        'tags': [t.strip() for t in tags.split(',') if t.strip()],
                        'parameters': params,
                        'required_fields': [f.strip() for f in required_fields.split(',') if f.strip()],
                        'data_count': data_count,
                        'created_at': datetime.now().strftime("%Y-%m-%d"),
                        'updated_at': datetime.now().strftime("%Y-%m-%d"),
                        'downloads': 0,
                        'views': 0,
                        'has_file': uploaded_file is not None
                    }
                    st.session_state.models.append(new_model)
                    st.success(f"✅ 모델 '{model_name}' 추가 완료!")
                    st.rerun()
                elif submitted:
                    st.error("⚠️ 필수 항목을 입력해주세요")

    # 필터링
    filtered_models = st.session_state.models
    if search_query:
        filtered_models = [m for m in filtered_models if search_query.lower() in m['name'].lower()]
    if model_type_filter:
        filtered_models = [m for m in filtered_models if m['type'] in model_type_filter]
    if log_type_filter:
        filtered_models = [m for m in filtered_models if m['log_type'] in log_type_filter]
    if threat_filter:
        filtered_models = [m for m in filtered_models if any(t in m.get('threat_tags', []) for t in threat_filter)]

    # 정렬
    sort_keys = {
        "최신순": lambda x: x['updated_at'],
        "다운로드순": lambda x: x['downloads'],
        "조회순": lambda x: x['views'],
        "이름순": lambda x: x['name']
    }
    filtered_models = sorted(filtered_models, key=sort_keys[sort_by], reverse=(sort_by != "이름순"))

    # 모델 카드
    st.subheader(f"📦 모델 목록 ({len(filtered_models)}개)")

    if len(filtered_models) == 0:
        st.info("등록된 모델이 없거나 필터 조건에 맞는 모델이 없습니다.")
    else:
        # 3열 그리드
        for i in range(0, len(filtered_models), 3):
            cols = st.columns(3)
            
            for j in range(3):
                if i + j < len(filtered_models):
                    model = filtered_models[i + j]
                    
                    with cols[j]:
                        # 카드 컨테이너 - border=True 사용
                        with st.container(border=True):
                            # 모델명
                            st.markdown(f"### {model['name']}")
                            
                            # 버전과 로그타입
                            st.markdown(
                                f'<span class="version-badge">{model["version"]}</span>'
                                f'<span class="log-badge">{model["log_type"]}</span>',
                                unsafe_allow_html=True
                            )
                            
                            # 알고리즘
                            st.caption(f"**{model['algorithm']}** | {model['type']}")
                            
                            st.markdown("<br>", unsafe_allow_html=True)
                            
                            # 위협 TAG
                            threat_tags_html = "".join([
                                f'<span class="threat-tag">{tag}</span>' 
                                for tag in model.get('threat_tags', [])
                            ])
                            st.markdown(threat_tags_html, unsafe_allow_html=True)
                            
                            # 한줄 설명
                            st.write(model.get('summary', ''))
                            
                            # 일반 태그
                            if model.get('tags'):
                                tags_html = "".join([
                                    f'<span class="tag">{tag}</span>' 
                                    for tag in model.get('tags', [])
                                ])
                                st.markdown(tags_html, unsafe_allow_html=True)
                            
                            st.markdown("---")
                            
                            # 통계
                            stat1, stat2, stat3 = st.columns(3)
                            with stat1:
                                st.metric("다운로드", model['downloads'])
                            with stat2:
                                st.metric("조회수", model['views'])
                            with stat3:
                                st.metric("데이터", f"{model.get('data_count', 0):,}")
                            
                            # 크기 및 날짜
                            st.caption(f"크기: {model['size']} | 업데이트: {model['updated_at']}")
                            
                            # 상세보기 버튼
                            if st.button("📋 상세보기", key=f"view_{model['id']}", use_container_width=True):
                                for m in st.session_state.models:
                                    if m['id'] == model['id']:
                                        m['views'] += 1
                                st.query_params.update({"page": "detail", "model_id": str(model['id'])})
                                st.rerun()

# ==================== 상세 페이지 ====================
elif page == "detail" and model_id:
    selected_model = next((m for m in st.session_state.models if str(m['id']) == str(model_id)), None)
    
    if selected_model:
        if st.button("⬅️ 목록으로"):
            st.query_params.clear()
            st.rerun()
        
        st.markdown("---")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown(f"# {selected_model['name']}")
            st.markdown(f"### {selected_model.get('summary', '')}")
            
            st.markdown("#### 🎯 탐지 위협")
            threat_html = "".join([f'<span class="threat-tag">{tag}</span>' for tag in selected_model.get('threat_tags', [])])
            st.markdown(threat_html, unsafe_allow_html=True)
            
            st.markdown("#### 📝 상세 설명")
            st.write(selected_model.get('description', '상세 설명이 없습니다.'))
            
            st.markdown("#### 🔍 주요 Feature")
            if selected_model.get('features'):
                for f in selected_model['features']:
                    st.markdown(f"- {f}")
            else:
                st.write("등록된 Feature 없음")
        
        with col2:
            st.markdown("#### ℹ️ 기본 정보")
            st.markdown(f"**알고리즘:** {selected_model['algorithm']}")
            st.markdown(f"**모델 유형:** {selected_model['type']}")
            st.markdown(f"**로그 타입:** {selected_model['log_type']}")
            st.markdown(f"**버전:** {selected_model['version']}")
            st.markdown(f"**크기:** {selected_model['size']}")
            st.markdown(f"**데이터:** {selected_model.get('data_count', 0):,}개")
            st.markdown(f"**등록일:** {selected_model['created_at']}")
            
            st.markdown("---")
            st.metric("다운로드", selected_model['downloads'])
            st.metric("조회수", selected_model['views'])
            st.markdown("---")
            
            # 다운로드
            if selected_model.get('has_file') and selected_model['id'] in st.session_state.model_files:
                file_info = st.session_state.model_files[selected_model['id']]
                if st.download_button(
                    "⬇️ 모델 다운로드",
                    data=file_info['data'],
                    file_name=file_info['filename'],
                    mime=file_info['type'],
                    use_container_width=True
                ):
                    selected_model['downloads'] += 1
            else:
                st.info("파일 없음")
            
            if st.session_state.is_admin:
                if st.button("🗑️ 삭제", use_container_width=True):
                    st.session_state.models = [m for m in st.session_state.models if m['id'] != selected_model['id']]
                    if selected_model['id'] in st.session_state.model_files:
                        del st.session_state.model_files[selected_model['id']]
                    st.query_params.clear()
                    st.rerun()
        
        st.markdown("---")
        tab1, tab2 = st.tabs(["⚙️ 파라미터", "📌 필수 필드"])
        
        with tab1:
            st.code(selected_model.get('parameters', '{}'), language='json')
        
        with tab2:
            if selected_model.get('required_fields'):
                for field in selected_model['required_fields']:
                    st.markdown(f"- `{field}`")
            st.warning("⚠️ 필드명 다를 시 JSON 수정 필요")