import streamlit as st
import requests
import pandas as pd
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import re

# --- 1. KONFIGURASI HALAMAN ---
st.set_page_config(
    page_title="Domain Scanner - Yang Mulya Dery",
    page_icon="🕵️‍♂️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- 2. CSS KUSTOM (Tema Terminal/Hacker) ---
st.markdown("""
    <style>
    .stApp {
        background-color: #050505;
        color: #22c55e;
        font-family: 'Courier New', Courier, monospace;
    }
    h1, h2, h3, p, span, div { color: #22c55e !important; }
    .stTextInput>div>div>input {
        background-color: #111111;
        color: #4ade80;
        border: 1px solid #166534;
        border-radius: 5px;
    }
    .stButton>button {
        background-color: #166534;
        color: #ffffff !important;
        border: 1px solid #22c55e;
        width: 100%;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #15803d;
        border-color: #4ade80;
        box-shadow: 0 0 10px rgba(34, 197, 94, 0.5);
    }
    .stProgress > div > div > div > div { background-color: #22c55e; }
    [data-testid="stDataFrame"] {
        background-color: #111111;
        border: 1px solid #166534;
    }
    </style>
""", unsafe_allow_html=True)

# --- 3. VARIABEL & LOGIKA PEMINDAIAN ---
WORDLIST = [
    'www', 'mail', 'api', 'dev', 'staging', 'admin', 'test', 'portal', 
    'secure', 'vpn', 'remote', 'blog', 'shop', 'smtp', 'ns1', 'ns2', 
    'm', 'app', 'web', 'cdn', 'static', 'beta', 'cpanel', 'webmail',
    'dashboard', 'support', 'docs', 'forum', 'store', 'go', 'cloud', 'system'
]

@st.cache_data
def generate_targets(base_domain):
    targets = []
    targets.append({'Tipe': 'Utama', 'Domain': base_domain})
    targets.append({'Tipe': 'Utama', 'Domain': f'www.{base_domain}'})

    parts = base_domain.split('.')
    tld = parts[-1] if len(parts) > 1 else ''
    name = '.'.join(parts[:-1])

    for word in WORDLIST:
        targets.append({'Tipe': 'Subdomain (Awal)', 'Domain': f'{word}.{base_domain}'})
        if tld:
            targets.append({'Tipe': 'Variasi (Akhir)', 'Domain': f'{name}-{word}.{tld}'})
            targets.append({'Tipe': 'Variasi (Awal)', 'Domain': f'{word}-{name}.{tld}'})

    seen = set()
    unique_targets = []
    for t in targets:
        if t['Domain'] not in seen:
            seen.add(t['Domain'])
            unique_targets.append(t)
            
    return unique_targets

def resolve_dns(target, session):
    hostname = target['Domain']
    tipe = target['Tipe']
    try:
        url = f"https://dns.google/resolve?name={hostname}&type=A"
        # Menggunakan session yang sama untuk mempercepat koneksi
        response = session.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('Status') == 0 and 'Answer' in data:
                ip_records = [ans['data'] for ans in data['Answer'] if ans['type'] == 1]
                if ip_records:
                    return {
                        "Tipe": tipe,
                        "Hostname": hostname,
                        "Alamat IP": ", ".join(ip_records),
                        "Status": "🟢 Aktif"
                    }
    except Exception:
        pass
    return None

# --- 4. ANTARMUKA PENGGUNA (UI) ---
st.title("🕵️‍♂️ Domain Reconnaissance")
st.markdown("**Terminal Root - Yang Mulya Dery** | Pemindai subdomain tersembunyi & IP.")
st.markdown("---")

col1, col2 = st.columns([3, 1])
with col1:
    target_domain = st.text_input("Target Domain", placeholder="Masukkan domain (contoh: tesla.com)", label_visibility="collapsed")
with col2:
    start_btn = st.button("Mulai Scan 🚀")

if start_btn:
    clean_domain = re.sub(r'^(https?://)?(www\.)?', '', target_domain.strip().lower()).split('/')[0]
    
    if not clean_domain or '.' not in clean_domain:
        st.error("Yang Mulya Dery, mohon masukkan format domain yang valid (contoh: google.com).")
    else:
        targets = generate_targets(clean_domain)
        total = len(targets)
        
        st.info(f"Memulai pemindaian untuk {total} variasi domain...")
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        results = []

        processed = 0
        
        # Menginisialisasi requests Session untuk koneksi yang lebih cepat
        session = requests.Session()
        
        # Meningkatkan jumlah worker menjadi 50 agar proses paralel jauh lebih cepat
        with ThreadPoolExecutor(max_workers=50) as executor:
            # Mengirimkan session ke dalam fungsi resolve_dns
            futures = {executor.submit(resolve_dns, t, session): t for t in targets}
            for future in concurrent.futures.as_completed(futures):
                processed += 1
                
                # Update progress bar
                progress = int((processed / total) * 100)
                progress_bar.progress(progress)
                
                # Membatasi update teks UI agar Streamlit tidak lag (update tiap 5 item atau di akhir)
                if processed % 5 == 0 or processed == total:
                    status_text.text(f"Mengecek [{processed}/{total}]...")
                
                res = future.result()
                if res:
                    results.append(res)
        
        status_text.text("Pemindaian selesai!")
        
        st.markdown("### 🟢 Hasil Pemindaian")
        if results:
            st.success(f"Ditemukan {len(results)} domain aktif!")
            df = pd.DataFrame(results)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.warning("Tidak ada subdomain aktif yang ditemukan untuk target ini.")
