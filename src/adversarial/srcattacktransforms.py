#Môi trường: pip install tldextract idna rapidfuzz



import random
import urllib.parse
import tldextract
import idna

# ==========================================
# 1. HÀM KIỂM TRA HỢP LỆ (validate_transform)
# ==========================================
def validate_transform(orig_url: str, trans_url: str, transform_type: str, benign_domains_set: set) -> bool:
    """
    Kiểm tra tính hợp lệ của URL sau biến đổi theo đúng yêu cầu bài toán.
    """
    # 1. Check độ dài <= 2048
    if len(trans_url) > 2048:
        return False
        
    # 2. Parse được bằng urllib
    try:
        parsed_orig = urllib.parse.urlparse(orig_url)
        parsed_trans = urllib.parse.urlparse(trans_url)
        if not parsed_trans.scheme or not parsed_trans.netloc:
            return False
    except Exception:
        return False

    ext_orig = tldextract.extract(orig_url)
    ext_trans = tldextract.extract(trans_url)
    
    orig_reg_domain = ext_orig.registered_domain.lower()
    trans_reg_domain = ext_trans.registered_domain.lower()

    # 3. Với T1-T4: Bắt buộc giữ nguyên registered domain
    if transform_type in ['T1', 'T2', 'T3', 'T4']:
        if orig_reg_domain != trans_reg_domain:
            return False

    # 4. Registered domain mới không trùng với danh sách benign/Tranco
    if trans_reg_domain in benign_domains_set:
        return False

    return True


# ==========================================
# 2. BỘ BIẾN ĐỔI T1–T7
# ==========================================

# --- NHÓM MIỄN PHÍ (T1 - T4) ---

def T1_add_param_or_path(url: str) -> str:
    """T1: Thêm tham số tracking/path trông bình thường"""
    parsed = urllib.parse.urlparse(url)
    dummy_params = [
        "utm_source=mail&ref=home",
        "session_id=892374&lang=en",
        "redirect_to=dashboard",
        "v=1.2.4"
    ]
    query = parsed.query
    new_param = random.choice(dummy_params)
    query = f"{query}&{new_param}" if query else new_param
    return urllib.parse.urlunparse(parsed._replace(query=query))

def T2_add_subdomain(url: str) -> str:
    """T2: Thêm/đổi thứ tự subdomain trên domain của mình"""
    parsed = urllib.parse.urlparse(url)
    subdomains = ["account.support", "verify.secure", "login.auth", "myaccount", "update"]
    ext = tldextract.extract(url)
    new_sub = random.choice(subdomains)
    
    if ext.subdomain:
        new_netloc = f"{new_sub}.{ext.subdomain}.{ext.registered_domain}"
    else:
        new_netloc = f"{new_sub}.{ext.registered_domain}"
        
    return urllib.parse.urlunparse(parsed._replace(netloc=new_netloc))

def T3_replace_keywords(url: str) -> str:
    """T3: Thay từ khóa đáng ngờ bằng từ trung tính"""
    suspicious_map = {
        "login": "member",
        "verify": "check",
        "secure": "portal",
        "account": "user",
        "update": "info",
        "bank": "service"
    }
    new_url = url
    for word, replacement in suspicious_map.items():
        if word in new_url.lower():
            new_url = new_url.replace(word, replacement)
    
    # Nếu không tìm thấy từ nào để thay, thêm path trung tính đơn giản
    if new_url == url:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.rstrip('/') + '/index'
        new_url = urllib.parse.urlunparse(parsed._replace(path=path))
    return new_url

def T4_http_to_https(url: str) -> str:
    """T4: Đổi http -> https"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == 'http':
        return urllib.parse.urlunparse(parsed._replace(scheme='https'))
    return url  # Giữ nguyên nếu đã là https hoặc không có scheme


# --- NHÓM TỐN PHÍ (T5 - T7) ---

def T5_insert_hyphen(url: str) -> str:
    """T5: Chèn dấu gạch nối vào domain"""
    ext = tldextract.extract(url)
    domain_name = ext.domain
    if len(domain_name) > 3:
        idx = len(domain_name) // 2
        new_domain_name = domain_name[:idx] + "-" + domain_name[idx:]
        new_reg_domain = f"{new_domain_name}.{ext.suffix}"
        
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.replace(ext.registered_domain, new_reg_domain)
        return urllib.parse.urlunparse(parsed._replace(netloc=netloc))
    return url

def T6_typosquatting(url: str) -> str:
    """T6: Typosquatting (viết sai tả/thay ký tự tương tự)"""
    char_map = {'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '4', 's': '5'}
    ext = tldextract.extract(url)
    domain_name = ext.domain
    
    new_domain_name = list(domain_name)
    changed = False
    for i, ch in enumerate(new_domain_name):
        if ch in char_map:
            new_domain_name[i] = char_map[ch]
            changed = True
            break  # Chỉ thay 1 ký tự
            
    if not changed and len(domain_name) > 2:
        # Lặp lại 1 ký tự nếu không có ký tự thay thế
        new_domain_name.insert(1, domain_name[0])

    new_domain_str = "".join(new_domain_name)
    new_reg_domain = f"{new_domain_str}.{ext.suffix}"
    
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.replace(ext.registered_domain, new_reg_domain)
    return urllib.parse.urlunparse(parsed._replace(netloc=netloc))

def T7_homoglyph_punycode(url: str) -> str:
    """T7: Homoglyph Unicode (IDN), lưu ở dạng punycode (xn--)"""
    # Thay ký tự 'a' Latin bằng 'а' Cyrillic (U+0430) hoặc 'e' -> 'е' (U+0435)
    homoglyphs = {'a': '\u0430', 'e': '\u0435', 'o': '\u043e', 'p': '\u0440'}
    
    ext = tldextract.extract(url)
    domain_name = ext.domain
    
    new_domain_list = list(domain_name)
    for i, ch in enumerate(new_domain_list):
        if ch in homoglyphs:
            new_domain_list[i] = homoglyphs[ch]
            break
            
    unicode_domain = "".join(new_domain_list) + "." + ext.suffix
    
    try:
        # Mã hóa sang punycode
        punycode_domain = idna.encode(unicode_domain).decode('ascii')
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.replace(ext.registered_domain, punycode_domain)
        return urllib.parse.urlunparse(parsed._replace(netloc=netloc))
    except Exception:
        return url


# ==========================================
# 3. SCRIPT TEST MẪU (TEST & PRINT OUTPUT)
# ==========================================
if __name__ == "__main__":
    # Tạo danh sách Benign giả định để test hàm validate
    dummy_benign_domains = {"paypal.com", "google.com", "facebook.com", "tranco-list.eu"}

    # Danh sách mẫu URL độc hại test
    sample_malicious_urls = [
        "http://secure-login-paypal.com/verify/account",
        "http://update-bank-info.net/login.php",
        "http://verify-user-portal.org/secure",
    ]

    transforms = {
        'T1': T1_add_param_or_path,
        'T2': T2_add_subdomain,
        'T3': T3_replace_keywords,
        'T4': T4_http_to_https,
        'T5': T5_insert_hyphen,
        'T6': T6_typosquatting,
        'T7': T7_homoglyph_punycode,
    }

    print("=== KẾT QUẢ TEST BIẾN ĐỔI (TEST & VALIDATE) ===")
    for code, trans_fn in transforms.items():
        print(f"\n--- Loại {code} ---")
        count = 0
        for orig in sample_malicious_urls:
            transformed = trans_fn(orig)
            is_valid = validate_transform(orig, transformed, code, dummy_benign_domains)
            print(f"Gốc : {orig}")
            print(f"Sau : {transformed}")
            print(f"Hợp lệ: {is_valid}")
            if is_valid:
                count += 1
        print(f"=> Đã test xong {code}, Tỷ lệ hợp lệ mẫu: {count}/{len(sample_malicious_urls)}")