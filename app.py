import os
import re
import requests
import mailparser
from flask import Flask, render_template, request

app = Flask(__name__)

LINKS_FILE = "links.txt"

def normalize_link(link: str) -> str:
    """
    توحيد صيغة الرابط قبل المقارنة:
    - تحويل لأحرف صغيرة
    - إزالة http:// أو https://
    - إزالة '/' في النهاية
    """
    link = link.strip().lower()
    if link.startswith("http://"):
        link = link[len("http://"):]
    elif link.startswith("https://"):
        link = link[len("https://"):]
    link = link.rstrip("/")
    return link

def load_malicious_links():
    """
    يقرأ ملف links.txt ويعيد مجموعة من الروابط الخبيثة بعد تطبيعها.
    """
    if not os.path.exists(LINKS_FILE):
        return set()
    malicious = set()
    with open(LINKS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if raw:
                malicious.add(normalize_link(raw))
    return malicious

@app.route('/')
def index():
    """
    الصفحة الرئيسية (index.html) بنموذج لإدخال رابط (URL) + نموذج لرفع EML.
    """
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    تحليل رابط (URL):
      - إضافة http:// لو بلا بروتوكول (اختياري)
      - جلب الصفحة للبحث عن كلمات مشبوهة (اختياري)
      - مقارنة الرابط بـ links.txt
      - عرض النتيجة في result.html
    """
    url = request.form.get('url_input')
    if not url:
        return "No URL provided!"

    # إضافة http:// لو الرابط بلا بروتوكول
    if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
        url = "http://" + url

    # جلب الصفحة والبحث عن كلمات مشبوهة
    suspicious_found = []
    page_status = None
    try:
        r = requests.get(url, timeout=10)
        page_status = r.status_code
        if r.status_code == 200:
            text_lower = r.text.lower()
            suspicious_keywords = ["login", "verify", "account", "password", "urgent"]
            for kw in suspicious_keywords:
                if kw in text_lower:
                    suspicious_found.append(kw)
    except Exception as e:
        page_status = f"Error: {str(e)}"

    # فحص وجود الرابط في links.txt
    malicious_links = load_malicious_links()
    normalized_input = normalize_link(url)
    is_malicious = (normalized_input in malicious_links)

    results = {
        'url': url,                 # الرابط الأصلي
        'page_status': page_status, # كود الاستجابة أو الخطأ
        'suspicious_found': suspicious_found,
        'is_malicious': is_malicious
    }

    return render_template('result.html', results=results)

@app.route('/analyze_mail', methods=['POST'])
def analyze_mail():
    """
    تحليل بريد (EML):
      - استخراج الروابط
      - لكل رابط: مقارنة بـ links.txt
      - لو رابط واحد ضار => any_malicious=True
      - عرض النتيجة في result_mail.html
    """
    if 'eml_file' not in request.files:
        return "No EML file uploaded!"
    file = request.files['eml_file']
    if file.filename == '':
        return "File name is empty!"

    eml_path = "temp.eml"
    file.save(eml_path)

    mail_obj = mailparser.parse_from_file(eml_path)
    subject = mail_obj.subject or ""
    from_ = mail_obj.from_ or []
    to_ = mail_obj.to or []

    # نجمع نص الرسالة
    body_text = ""
    if mail_obj.text_plain:
        body_text += mail_obj.text_plain[0]
    if mail_obj.text_html:
        body_text += mail_obj.text_html[0]

    # استخراج الروابط
    urls = re.findall(r"http[s]?://[^\s]+", body_text)

    malicious_links = load_malicious_links()
    analysis_results = []
    any_malicious = False

    # اختياريا: البحث عن كلمات مشبوهة في نص البريد
    suspicious_keywords = ["login", "verify", "account", "password", "urgent"]
    found_keywords = []
    for kw in suspicious_keywords:
        if kw in body_text.lower():
            found_keywords.append(kw)

    for link in urls:
        normalized_link = normalize_link(link)
        is_mal = (normalized_link in malicious_links)
        if is_mal:
            any_malicious = True

        analysis_results.append({
            "url": link,
            "is_malicious": is_mal
        })

    # حذف الملف المؤقت
    if os.path.exists(eml_path):
        os.remove(eml_path)

    return render_template(
        'result_mail.html',
        subject=subject,
        from_=from_,
        to_=to_,
        analysis_results=analysis_results,
        any_malicious=any_malicious,
        found_keywords=found_keywords
    )

if __name__ == '__main__':
    app.run(debug=True)
