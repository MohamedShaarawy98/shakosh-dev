// ============================================================
//  ضربة شاكوش — منصة هندسية لتقنيات المصاعد
// ============================================================
#include "httplib.h"
#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <algorithm>
#include <map>
#include <chrono>
#include <mutex>
#include <random>

using namespace std;

// هيكل بيانات لتتبع طلبات كل مستخدم
struct RateLimitInfo {
    int count = 0;
    chrono::steady_clock::time_point reset_time;
};

static map<string, RateLimitInfo> ip_tracker;
static mutex rate_limit_mtx;
const int MAX_REQUESTS_PER_MINUTE = 12; // الحد الأقصى للطلبات العامة في الدقيقة

// ============================================================
//  متغيرات البيئة الأمنية
// ============================================================
static string CF_VERIFY_SECRET = getenv("CF_VERIFY_SECRET") ? getenv("CF_VERIFY_SECRET") : "";
// تم تغيير اسم الهيدر ليتطابق مع كلاودفلير وتفادي حظر الكلمات التي تبدأ بـ "cf-"
static string SECURE_HEADER_NAME = "X-Verify-Secret"; 

// ============================================================
//  دوال تحويل وحماية آمنة
// ============================================================
static int safe_stoi(const string& s, int default_val = 0) {
    try {
        if (s.empty()) return default_val;
        return stoi(s);
    } catch (...) {
        return default_val;
    }
}

static float safe_stof(const string& s, float default_val = 0.0f) {
    try {
        if (s.empty()) return default_val;
        return stof(s);
    } catch (...) {
        return default_val;
    }
}

static int clamp_int(int v, int lo, int hi) {
    return max(lo, min(hi, v));
}

static float clamp_float(float v, float lo, float hi) {
    return max(lo, min(hi, v));
}

static string html_escape(const string& data) {
    string buffer;
    buffer.reserve(data.size());
    for (size_t pos = 0; pos != data.size(); ++pos) {
        switch (data[pos]) {
            case '&':  buffer.append("&amp;");       break;
            case '\"': buffer.append("&quot;");      break;
            case '\'': buffer.append("&apos;");      break;
            case '<':  buffer.append("&lt;");        break;
            case '>':  buffer.append("&gt;");        break;
            default:   buffer.append(&data[pos], 1); break;
        }
    }
    return buffer;
}

// توليد nonce عشوائي لاستخدامه في CSP (يسمح بسكريبت محدد فقط بدون unsafe-inline)
static string generate_nonce() {
    random_device rd;
    mt19937_64 gen(rd());
    uint64_t a = gen();
    uint64_t b = gen();
    ostringstream oss;
    oss << hex << a << b;
    return oss.str();
}

// ============================================================
//  ترويسات الأمان
// ============================================================

// هيدرز ثابتة لا تتغير حسب الصفحة
static void set_security_headers(httplib::Response& res) {
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-XSS-Protection", "1; mode=block");
    res.set_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
    res.set_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    res.set_header("Server", "Hammer-Engine/1.0");
}

// CSP منفصلة لأنها تتغير حسب الصفحة
static void set_csp(httplib::Response& res, const string& script_nonce = "") {
    string script_src = script_nonce.empty()
        ? "script-src 'none'; "
        : ("script-src 'self' 'nonce-" + script_nonce + "'; ");

    string csp = "default-src 'self'; "
                 "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                 "font-src https://fonts.gstatic.com; "
                 + script_src +
                 "connect-src 'self'; "
                 "frame-ancestors 'none'; "
                 "base-uri 'self'; "
                 "form-action 'self';";

    res.headers.erase("Content-Security-Policy");
    res.set_header("Content-Security-Policy", csp);
}

// دالة استخراج الـ IP الحقيقي للزائر خلف كلوفلير
static string get_client_ip(const httplib::Request& req) {
    if (req.has_header("CF-Connecting-IP")) {
        return req.get_header_value("CF-Connecting-IP");
    }
    if (req.has_header("X-Forwarded-For")) {
        string xff = req.get_header_value("X-Forwarded-For");
        size_t comma = xff.find(',');
        if (comma != string::npos) {
            return xff.substr(0, comma);
        }
        return xff;
    }
    return req.remote_addr;
}

// دالة فحص وتطبيق نظام الـ Rate Limiting (عام)
static bool is_rate_limited(const string& ip) {
    lock_guard<mutex> lock(rate_limit_mtx);
    auto now = chrono::steady_clock::now();

    if (ip_tracker.size() > 500) {
        for (auto it = ip_tracker.begin(); it != ip_tracker.end(); ) {
            if (now >= it->second.reset_time) {
                it = ip_tracker.erase(it);
            } else {
                ++it;
            }
        }
    }

    if (ip_tracker.find(ip) == ip_tracker.end() || now >= ip_tracker[ip].reset_time) {
        ip_tracker[ip].count = 1;
        ip_tracker[ip].reset_time = now + chrono::minutes(1);
        return false;
    }

    ip_tracker[ip].count++;
    if (ip_tracker[ip].count > MAX_REQUESTS_PER_MINUTE) {
        return true;
    }

    return false;
}

static void send_rate_limit_error(httplib::Response& res) {
    ostringstream os;
    os << "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
       << "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
       << "<style>"
       << "body{background-color:#0B0F19; font-family:'Cairo', sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; direction:rtl;}"
       << ".limit-card{background:#111827; border:2px solid #F59E0B; padding:40px; border-radius:15px; text-align:center; max-width:500px; width:90%; box-shadow:0 10px 25px rgba(245,158,11,0.15); border: 1px solid #1F2937;}"
       << ".limit-card h2{color:#F59E0B; font-size:22px; margin-top:0;}"
       << ".limit-card p{color:#9CA3AF; font-size:15px; line-height:1.6; margin-bottom:25px;}"
       << "</style></head><body>"
       << "<div class='limit-card'>"
       << "<h2>⚠️ تم تجاوز حد الطلبات المسموح به</h2>"
       << "<p>لقد قمت بإرسال عدد كبير من الطلبات في وقت قصير (الحد الأقصى هو 12 طلباً في الدقيقة).<br>يرجى الانتظار دقيقة واحدة ثم إعادة المحاولة بشكل طبيعي.</p>"
       << "</div></body></html>";
    res.status = 429;
    res.set_content(os.str(), "text/html; charset=utf-8");
}

// ============================================================
//  كلاس المصعد هندسياً (بدون أي تعديل على المنطق أو الأسعار)
// ============================================================
class Elevator {
private:
    const float P_BRACKET = 0.0f;
    const float P_BOLT = 0.0f;
    const float P_ROPE = 0.0f;
    const float P_FISH = 0.0f;
    const float P_RAIL = 0.0f;

public:
    string get_door_type(int sa) {
        if (sa >= 210 && sa <= 250)      return "Auto 80 CO || Auto 90 CO || Auto 100 CO";
        else if (sa >= 190 && sa < 210)  return "Auto 80 CO || Auto 90 CO || Auto 100 SI";
        else if (sa >= 190 && sa < 195)  return "Auto 80 CO || Auto 90 CO || Auto 100 SI";
        else if (sa >= 175 && sa < 190)  return "Auto 80 CO || Auto 100 SI || Auto 90 SI";
        else if (sa >= 167 && sa < 175)  return "Auto 90 SI || Auto 80 CO";
        else if (sa >= 160 && sa < 167)  return "Auto 90 SI || Auto 70 CO";
        else if (sa >= 155 && sa < 160)  return "Auto 80 SI || Auto 70 CO";
        else if (sa >= 145 && sa < 155)  return "Auto 80 SI";
        else if (sa >= 128 && sa < 145)  return "Auto 70 SI";
        else if (sa >= 120 && sa < 128)  return "Semi Auto 80";
        else if (sa >= 110 && sa < 120)  return "Semi Auto 70";
        return "No standard door";
    }

    int get_cabin_dbg(int w) { return w - 30; }
    int get_cwt_dbg(int v) {
        if (v >= 100 && v <= 110) return 72;
        if (v > 110 && v <= 120) return 82;
        if (v > 120 && v <= 125) return 92;
        if (v > 125 && v <= 210) return 102;
        return 0;
    }
    int get_cabin_width(int cw) { return cw - 40; }
    int get_cabin_depth(int cd) { return cd - 60; }

    float get_shaft_height(float f, float pit_m, float overhead_m, string t) {
        float typical_floors_height = (f - 1) * 3.2f;
        float total_h = typical_floors_height + pit_m + overhead_m;
        return (t == "MRL") ? total_h + 1.5f : total_h;
    }

    int calc_brackets(float h) { return (h / 2.0) * 4; }
    int calc_bolts(int b) { return b * 4; }
    float calc_ropes(float h) { return ((h * 2) + 5) * 4; }

    float get_p_bracket() { return P_BRACKET; }
    float get_p_bolt() { return P_BOLT; }
    float get_p_rope() { return P_ROPE; }
    float get_p_fish() { return P_FISH; }
    float get_p_rail() { return P_RAIL; }
};

// ============================================================
//  الستايل الموحد الاحترافي (CSS المطور لمنصة هرمش المخصصة)
// ============================================================
static string get_global_css() {
    return "<style>"
           "font-family:'Cairo', sans-serif; background-color:#0B0F19; color:#F3F4F6; direction:rtl; margin:0; padding:0; min-height:100vh; display:flex; flex-direction:column;}"
           ".navbar{background-color:#111827; border-bottom:1px solid #1F2937; padding:15px 30px; display:flex; justify-content:space-between; align-items:center; box-shadow:0 4px 6px rgba(0,0,0,0.2);}"
           ".navbar-brand{color:#F59E0B; font-size:1.6rem; font-weight:700; text-decoration:none; display:flex; align-items:center; gap:10px;}"
           ".navbar-menu{display:flex; gap:20px;}"
           ".navbar-link{color:#9CA3AF; text-decoration:none; font-weight:600; font-size:0.95rem; transition:0.3s; padding:8px 16px; border-radius:8px;}"
           ".navbar-link:hover{color:#F59E0B; background-color:#1F2937;}"
           ".hero-section{text-align:center; padding:60px 20px; background:radial-gradient(circle at top, #1e293b 0%, #0b0f19 70%);}"
           ".hero-section h1{color:#F59E0B; font-size:2.8rem; margin:0 0 10px 0; font-weight:700;}"
           ".hero-section p{color:#9CA3AF; font-size:1.1rem; margin:0 auto; max-width:600px; line-height:1.6;}"
           ".container{max-width:1000px; margin:0 auto; padding:30px 20px; flex:1; width:100%; box-sizing:border-box;}"
           ".alert-box{background:rgba(239,68,68,0.1); border:1px dashed #EF4444; padding:20px; border-radius:12px; text-align:center; margin-bottom:30px; box-shadow:0 4px 12px rgba(239,68,68,0.05);}"
           ".alert-box h4{color:#FCA5A5; margin:0 0 6px 0; font-size:1.1rem; font-weight:700;}"
           ".alert-box p{color:#FEE2E2; margin:0; font-size:0.95rem; line-height:1.6;}"
           ".grid-nav{display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:25px; width:100%;}"
           ".nav-card{background:#111827; border:1px solid #1F2937; padding:30px; border-radius:16px; text-decoration:none; color:#F3F4F6; transition:0.3s; display:flex; flex-direction:column; box-shadow:0 4px 6px rgba(0,0,0,0.1);}"
           ".nav-card:hover{border-color:#F59E0B; transform:translateY(-5px); box-shadow:0 12px 20px rgba(245,158,11,0.1);}"
           ".nav-card h3{color:#F59E0B; font-size:1.35rem; margin:0 0 12px 0; font-weight:700;}"
           ".nav-card p{color:#9CA3AF; font-size:0.9rem; line-height:1.6; margin:0;}"
           ".disabled{opacity:0.4; cursor:not-allowed; position:relative;}"
           ".disabled:hover{transform:none; border-color:#1F2937; box-shadow:none;}"
           ".card{background:#111827; border:1px solid #1F2937; padding:40px; border-radius:16px; box-shadow:0 10px 25px rgba(0,0,0,0.3);}"
           ".card h2{color:#F59E0B; font-size:1.6rem; margin-top:0; margin-bottom:10px; font-weight:700; border-bottom:1px solid #1F2937; padding-bottom:15px;}"
           ".sub-title{color:#9CA3AF; margin-bottom:30px; font-size:0.95rem;}"
           ".f-group{margin-bottom:25px; text-align:right;}"
           ".f-group label{font-weight:600; color:#D1D5DB; display:block; margin-bottom:10px; font-size:0.95rem;}"
           "input,select{width:100%; padding:14px; border:1px solid #1F2937; border-radius:10px; box-sizing:border-box; text-align:center; font-size:1rem; font-family:'Cairo', sans-serif; background-color:#1F2937; color:#F3F4F6; transition:0.3s; font-weight:600;}"
           "input:focus, select:focus{outline:none; border-color:#F59E0B; background-color:#111827; box-shadow:0 0 0 3px rgba(245,158,11,0.15);}"
           "button, .btn-action{background:linear-gradient(135deg, #D97706, #B45309); color:white; border:none; padding:16px; border-radius:10px; width:100%; font-size:1rem; font-weight:700; font-family:'Cairo', sans-serif; cursor:pointer; box-shadow:0 4px 12px rgba(180,83,9,0.2); transition:0.3s; text-decoration:none; display:inline-block; text-align:center; box-sizing:border-box;}"
           "button:hover, .btn-action:hover{background:linear-gradient(135deg, #B45309, #92400E); transform:translateY(-1px); box-shadow:0 6px 18px rgba(180,83,9,0.3);}"
           ".table-container{width:100%; overflow-x:auto; background:#111827; border-radius:12px; border:1px solid #1F2937; margin-top:15px;}"
           ".tbl{width:100%; border-collapse:collapse; text-align:right;}"
           ".tbl th{background:#1F2937; padding:14px 18px; color:#D1D5DB; font-weight:600; border-bottom:1px solid #1F2937; font-size:0.95rem; width:45%;}"
           ".tbl td{padding:14px 18px; border-bottom:1px solid #1F2937; color:#F3F4F6; font-size:0.95rem; font-weight:600;}"
           ".btbl{width:100%; border-collapse:collapse; text-align:center;}"
           ".btbl th{background:#1F2937; color:#F59E0B; padding:14px; font-weight:600; font-size:0.95rem; border-bottom:2px solid #1F2937;}"
           ".btbl td{padding:14px; border-bottom:1px solid #1F2937; color:#E5E7EB; font-size:0.95rem; font-weight:600;}"
           ".btbl tr:nth-child(even){background-color:#161E2E;}"
           ".inv{background:linear-gradient(135deg, rgba(245,158,11,0.05), rgba(217,119,6,0.1)); padding:20px; border-radius:12px; border:1px dashed #D97706; margin-top:30px; text-align:center; font-size:1.2rem; font-weight:700; color:#F59E0B; box-shadow:0 4px 12px rgba(217,119,6,0.1);}"
           ".actions{display:flex; justify-content:space-between; margin-top:35px; gap:20px;}"
           ".btn-print{background:linear-gradient(135deg, #059669, #047857); box-shadow:0 4px 12px rgba(4,120,87,0.2); color:white; border:none; padding:14px 25px; border-radius:10px; font-weight:700; font-family:'Cairo', sans-serif; cursor:pointer; font-size:0.95rem; flex:1; transition:0.3s;}"
           ".btn-print:hover{background:linear-gradient(135deg, #047857, #065F46); transform:translateY(-1px);}"
           ".btn-secondary{background:linear-gradient(135deg, #2563EB, #1D4ED8); box-shadow:0 4px 12px rgba(29,78,216,0.2); text-decoration:none; color:white; padding:14px 25px; border-radius:10px; font-weight:700; font-size:0.95rem; text-align:center; flex:1; transition:0.3s; display:inline-block; font-family:'Cairo', sans-serif; box-sizing:border-box;}"
           ".btn-secondary:hover{background:linear-gradient(135deg, #1D4ED8, #1E40AF); transform:translateY(-1px);}"
           ".footer{margin-top:auto; padding:30px 0; font-size:13px; color:#4B5563; text-align:center; font-weight:600; border-top:1px solid #1F2937; background-color:#111827;}"
           "@media print{.btn-print, .btn-secondary, h2, h3, .navbar, .footer {display:none;} .card{box-shadow:none; padding:0; border:none; background:none; color:#000;} .tbl th{background:#eee; color:#000;} .tbl td, .btbl td{color:#000;}}"
           "</style>";
}

// ============================================================
//  الدالة الرئيسية
// ============================================================
int main() {
    httplib::Server svr;
    Elevator elevator;

    if (CF_VERIFY_SECRET.empty()) {
        cerr << "[تحذير أمان] CF_VERIFY_SECRET غير مفعّل. الموقع غير محمي من الوصول المباشر متجاوزاً كلاودفلير. "
             << "يرجى ضبط متغير البيئة وإضافة Transform Rule في كلاودفلير (راجع ملف README)." << endl;
    }

    // ------------------------------------------------------------
    // نقطة الحماية المركزية: تُنفَّذ قبل أي مسار (route) في الموقع
    // ------------------------------------------------------------
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);
        set_csp(res); // افتراضي: بلا سكريبت إطلاقًا

        // 1) فرض التحقق من أن الطلب ممرر عبر كلاودفلير بالهيدر المخصص الجديد
        if (!CF_VERIFY_SECRET.empty()) {
            if (!req.has_header(SECURE_HEADER_NAME.c_str()) || req.get_header_value(SECURE_HEADER_NAME.c_str()) != CF_VERIFY_SECRET) {
                res.status = 403;
                res.set_content("Access Denied. Direct access to origin server is forbidden.", "text/plain; charset=utf-8");
                return httplib::Server::HandlerResponse::Handled;
            }
        }

        // 2) تطبيق الحد العام للطلبات بالدقيقة
        string client_ip = get_client_ip(req);
        if (is_rate_limited(client_ip)) {
            send_rate_limit_error(res);
            return httplib::Server::HandlerResponse::Handled;
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });

    // 1️⃣ الصفحة الرئيسية
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
                      + get_global_css() +
                      "</head><body>"
                      "<nav class='navbar'>"
                      "<a href='/' class='navbar-brand'>🛠️ ضربة شاكوش</a>"
                      "<div class='navbar-menu'>"
                      "<a href='/calculator' class='navbar-link'>الحاسبة</a>"
                      "<a href='/blog' class='navbar-link'>المقالات</a>"
                      "</div>"
                      "</nav>"
                      "<div class='hero-section'>"
                      "<h1>منصة ضربة شاكوش 🛠️</h1>"
                      "<p>البيئة الهندسية المتكاملة والمطورة لحساب مقاسات وتصفيات المصاعد والتحكم البرمجي الميكانيكي</p>"
                      "</div>"
                      "<div class='container'>"
                      "<div class='alert-box'>"
                      "<h4>⚠️ تنبيه فني هام جداً</h4>"
                      "<p>المنصة حالياً تحت المرحلة التجريبية والتطوير الهندسي المستمر. يمكنك استخدام الحاسبة ومراجعة الكميات الناتجة، ولكن يرجى عدم الاعتماد القطعي والنهائي على المقاسات الناتجة في الرفع الفعلي للمواقع دون مراجعتها يدوياً من قِبلك هندسياً.</p>"
                      "</div>"
                      "<div class='grid-nav'>"
                      "<a href='/calculator' class='nav-card'><h3>🛗  حاسبة مقاسات البضاعة</h3><p>النظام الذكي لتصفية أبعاد بئر المصعد وحساب مساحات الكابينة والمواد الهندسية للمشوار بأعلى دقة قياسية.</p></a>"
                      "<a href='/blog' class='nav-card'><h3>📚 مقالات وشروحات عملي</h3><p>مخططات طرق هندسة وصيانة كروت التحكم الإلكترونية، ومبادئ البرمجة والتحكم بالروبوتات للمحركات.</p></a>"
                      "<div class='nav-card disabled'><h3>🦾  تحكم الروبوتات والـ CNC</h3><p>(قريباً) واجهات معالجة وحساب معاملات الحركة والمحاور الميكانيكية المتقدمة المبنية بالكامل بكود C++.</p></div>"
                      "</div>"
                      "</div>"
                      "<div class='footer'>إنشاء وتطوير: مهندس محمد الشعراوي © 2026</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 2️⃣ صفحة واجهة إدخال بيانات الحاسبة
    svr.Get("/calculator", [](const httplib::Request&, httplib::Response& res) {
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
                      + get_global_css() +
                      "</head><body>"
                      "<nav class='navbar'>"
                      "<a href='/' class='navbar-brand'>🛠️ ضربة شاكوش</a>"
                      "<div class='navbar-menu'>"
                      "<a href='/calculator' class='navbar-link' style='color:#F59E0B;'>الحاسبة</a>"
                      "<a href='/blog' class='navbar-link'>المقالات</a>"
                      "</div>"
                      "</nav>"
                      "<div class='container' style='max-width:600px;'>"
                      "<div class='card'><h2>🧮 حاسبة المقاسات والبضاعة الذكية</h2>"
                      "<div class='sub-title'>النظام الرقمي المطور لتصفية وحساب بضاعة المصاعد فوراً</div>"
                      "<form action='/calculate' method='post'>"
                      "<div class='f-group'><label>📦 نوع نظام الهندسة والمحرك:</label><select name='m_type'><option value='MR'>غرفة محرك أعلى البئر (MR)</option><option value='MRL'>بدون غرفة محرك (MRL)</option></select></div>"
                      "<div class='f-group'><label>📏 عرض البئر الحُر القياسي (CM):</label><input type='number' name='width' required min='80' max='250' placeholder='مثال: 160'></div>"
                      "<div class='f-group'><label>📐 عمق البئر الحُر القياسي (CM):</label><input type='number' name='depth' required min='80' max='250' placeholder='مثال: 160'></div>"
                      "<div class='f-group'><label>🏢 عدد أدوار المبنى الإجمالي (الوقفات):</label><input type='number' name='floors' required min='1' max='60' placeholder='أدخل إجمالي عدد الوقفات'></div>"
                      "<div class='f-group'><label>🕳️ عمق الحفرة السفلي Pit (CM):</label><input type='number' name='depth_pit' required min='10' max='500' value='100'></div>"
                      "<div class='f-group'><label>🏠 الارتفاع العلوي الأخير Overhead (CM):</label><input type='number' name='overhead' required min='100' max='800' value='400'></div>"
                      "<button type='submit'>🚀 تحليل الأبعاد وتصفية المقايسة</button></form>"
                      "<a href='/' style='display:block; text-align:center; margin-top:20px; color:#9CA3AF; text-decoration:none; font-weight:600; font-size:14px;'>⬅️ العودة للبوابة الرئيسية</a></div>"
                      "</div>"
                      "<div class='footer'>إنشاء وتطوير: مهندس محمد الشعراوي © 2026</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 3️⃣ صفحة تقرير المقايسة
    svr.Post("/calculate", [&elevator](const httplib::Request& req, httplib::Response& res) {
        string m_type = html_escape(req.get_param_value("m_type"));
        if (m_type != "MR" && m_type != "MRL") { m_type = "MR"; }

        int w = safe_stoi(req.get_param_value("width"), 0);
        int d = safe_stoi(req.get_param_value("depth"), 0);
        float f = safe_stof(req.get_param_value("floors"), 0.0f);
        int original_pit = safe_stoi(req.get_param_value("depth_pit"), 100);
        int original_overhead = safe_stoi(req.get_param_value("overhead"), 400);

        if (w < 110 || d < 100) {
            ostringstream error_os;
            error_os << "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                     << "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
                     + get_global_css() +
                     "</head><body>"
                     << "<div style='display:flex; align-items:center; justify-content:center; min-height:100vh; width:100%;'>"
                     << "<div class='card' style='max-width:500px; text-align:center; border-color:#EF4444;'>"
                     << "<h2 style='color:#EF4444; border-bottom:1px solid #1F2937;'>⚠️ عذراً، أبعاد البئر غير مطابقة للمواصفات</h2>"
                     << "<p style='color:#9CA3AF; line-height:1.6; margin-bottom:25px;'>أبعاد بئر المصعد المدخلة (العرض: " << w << " سم، العمق: " << d << " سم) أقل من الحد الأدنى الفني القياسي المسموح به للحساب الرقمي الآلي بالمنصة.<br><br><b>الحد الأدنى المطلوب فنيّاً:</b> عرض لا يقل عن 110 سم، وعمق لا يقل عن 100 سم.</p>"
                     << "<a href='/calculator' class='btn-action' style='background:linear-gradient(135deg, #EF4444, #DC2626); box-shadow:0 4px 12px rgba(220,38,38,0.2);'>🔄 العودة وتعديل المقاسات</a>"
                     << "</div></div></body></html>";
            res.set_content(error_os.str(), "text/html; charset=utf-8");
            return;
        }

        string pit_display_text, overhead_display_text;

        if (original_pit < 60 || original_pit > 200) {
            pit_display_text = "<span style='color:#EF4444; background:rgba(239,68,68,0.1); padding:4px 8px; border-radius:6px; border:1px solid rgba(239,68,68,0.2); font-size:13px;'>⚠️ مقاس غير قياسي (" + to_string(original_pit) + " CM) - يرجى المراجعة</span>";
        } else {
            pit_display_text = to_string(original_pit) + " CM";
        }

        if (original_overhead < 350 || original_overhead > 600) {
            overhead_display_text = "<span style='color:#EF4444; background:rgba(239,68,68,0.1); padding:4px 8px; border-radius:6px; border:1px solid rgba(239,68,68,0.2); font-size:13px;'>⚠️ مقاس غير قياسي (" + to_string(original_overhead) + " CM) - يرجى المراجعة</span>";
        } else {
            overhead_display_text = to_string(original_overhead) + " CM";
        }

        w = clamp_int(w, 80, 250);
        d = clamp_int(d, 80, 250);
        f = clamp_float(f, 1.0f, 60.0f);
        float pit_clamped = clamp_float((float)original_pit, 10.0f, 500.0f);
        float overhead_clamped = clamp_float((float)original_overhead, 100.0f, 800.0f);

        float pit_m = pit_clamped / 100.0f;
        float overhead_m = overhead_clamped / 100.0f;

        string door = elevator.get_door_type(w);
        int cabin_dbg = elevator.get_cabin_dbg(w);
        int cwt_dbg = elevator.get_cwt_dbg(w);
        int cab_w = elevator.get_cabin_width(w);
        int cab_d = elevator.get_cabin_depth(d);

        float h = elevator.get_shaft_height(f, pit_m, overhead_m, m_type);

        int brackets = elevator.calc_brackets(h);
        int bolts = elevator.calc_bolts(brackets);
        float ropes = elevator.calc_ropes(h);
        int fishplates = ((int)f) * 4;
        float rail_qty = (h * 4) / 5.0f;

        float c_brackets = brackets * elevator.get_p_bracket();
        float c_bolts = bolts * elevator.get_p_bolt();
        float c_ropes = ropes * elevator.get_p_rope();
        float c_fishplates = fishplates * elevator.get_p_fish();
        float c_rail = rail_qty * elevator.get_p_rail();

        float total = c_brackets + c_bolts + c_ropes + c_fishplates + c_rail;

        string cwt_display_text;
        if (cwt_dbg == 0) {
            cwt_display_text = "<span style='color:#EF4444; background:rgba(239,68,68,0.1); padding:4px 8px; border-radius:6px; border:1px solid rgba(239,68,68,0.2); font-size:13px;'>⚠️ مقاس غير قياسي - يرجى المراجعة يدوياً</span>";
        } else {
            cwt_display_text = to_string(cwt_dbg) + " CM";
        }

        string nonce = generate_nonce();
        set_csp(res, nonce);

        ostringstream os;
        os << "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
           << "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
           + get_global_css() +
           "</head><body>"
           << "<nav class='navbar'>"
           << "<a href='/' class='navbar-brand'>🛠️ ضربة شاكوش</a>"
           << "<div class='navbar-menu'>"
           << "<a href='/calculator' class='navbar-link'>الحاسبة</a>"
           << "<a href='/blog' class='navbar-link'>المقالات</a>"
           << "</div>"
           << "</nav>"
           << "<div class='container' style='max-width:700px;'>"
           << "<div class='card'><h2>📋 تقرير تصفية الأبعاد الفنية والمقايسة</h2>"
           << "<h3 style='color:#F59E0B; font-size:1.1rem; margin-top:25px; margin-bottom:12px; font-weight:700;'>📐 أولاً: البيانات الهندسية الناتجة</h3>"
           << "<div class='table-container'><table class='tbl'>"
           << "<tr><th>نوع الباب الافتراضي للمساحة:</th><td style='color:#60A5FA;'>" << door << "</td></tr>"
           << "<tr><th>مقاس DBG الكابينة الحُر:</th><td>" << cabin_dbg << " CM</td></tr>"
           << "<tr><th>مقاس DBG الثقل (CWT):</th><td>" << cwt_display_text << "</td></tr>"
           << "<tr><th>صافي عرض الكابينة الداخلي:</th><td>" << cab_w << " CM</td></tr>"
           << "<tr><th>صافي عمق الكابينة الداخلي:</th><td>" << cab_d << " CM</td></tr>"
           << "<tr><th>مقاس عمق الحفرة المدخل:</th><td>" << pit_display_text << "</td></tr>"
           << "<tr><th>مقاس الارتفاع العلوي المدخل:</th><td>" << overhead_display_text << "</td></tr>"
           << "<tr><th>إجمالي مشوار البئر المحسوب:</th><td style='color:#F59E0B;'>" << h << " متر</td></tr>"
           << "</table></div>"
           << "<h3 style='color:#F59E0B; font-size:1.1rem; margin-top:30px; margin-bottom:12px; font-weight:700;'>Box ثانياً: كمية البضاعة والمواد المحسوبة للمشوار</h3>"
           << "<div class='table-container'><table class='btbl'><thead><tr><th>اسم الصنف ومواصفاته الفنية</th><th>الكمية المطلوبة</th><th>التكلفة التقديرية</th></tr></thead><tbody>"
           << "<tr><td>كوابيل السكك الحديدية للمصعد</td><td>" << brackets << " قطعة 🛑</td><td>" << c_brackets << " SAR</td></tr>"
           << "<tr><td>مسامير وجوايط التثبيت الميكانيكية</td><td>" << bolts << " مسمار 🔩</td><td>" << c_bolts << " SAR</td></tr>"
           << "<tr><td>حبال واير الفولاذ القياسية</td><td>" << ropes << " متر 🧵</td><td>" << c_ropes << " SAR</td></tr>"
           << "<tr><td>لقم ربط السكك (التقفيل الهندسي)</td><td>" << fishplates << " لقمة 🗜️</td><td>" << c_fishplates << " SAR</td></tr>"
           << "<tr><td>قضبان السكك الحديدية (الريل القياسي)</td><td>" << rail_qty << " قضيب (5م) 🛤️</td><td>" << c_rail << " SAR</td></tr>"
           << "</tbody></table></div>"
           << "<div class='inv'>💰 إجمالي القيمة المالية التقديرية للمواد: " << total << " SAR</div>"
           << "<div class='actions'>"
           << "<button class='btn-print' id='printBtn'>🖨️ طباعة التقرير الفني / حفظ PDF</button>"
           << "<a class='btn-secondary' href='/calculator'>🔄 حساب مقايسة جديدة</a>"
           << "</div></div></div>"
           << "<div class='footer'>إنشاء وتطوير: مهندس محمد الشعراوي © 2026</div>"
           << "<script nonce='" << nonce << "'>"
           << "document.getElementById('printBtn').addEventListener('click', function(){ window.print(); });"
           << "</script>"
           << "</body></html>";
        res.set_content(os.str(), "text/html; charset=utf-8");
    });

    // 4️⃣ مسار المقالات
    svr.Get("/blog", [](const httplib::Request&, httplib::Response& res) {
        string blog_html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                           "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
                           + get_global_css() +
                           "</head><body>"
                           "<nav class='navbar'>"
                           "<a href='/' class='navbar-brand'>🛠️ ضربة شاكوش</a>"
                           "<div class='navbar-menu'>"
                           "<a href='/calculator' class='navbar-link'>الحاسبة</a>"
                           "<a href='/blog' class='navbar-link' style='color:#F59E0B;'>المقالات</a>"
                           "</div>"
                           "</nav>"
                           "<div class='container' style='max-width:800px;'>""<h1>📚 بوابة ضربة شاكوش للمقالات والشروحات الهندسية</h1>"
                           "<div class='card' style='margin-top:20px;'><h2>قريباً: شرح مخططات DWG وهندسة تركيب المصاعد</h2><p style='color:#9CA3AF; line-height:1.6;'>هنا سيتم رفع الشروحات الفنية المفصلة لتركيب السكك والمقاسات القياسية لكوابين المصاعد بمختلف الأنظمة (هيدروليك وجيرلس)...</p></div>"
                           "<div class='card' style='margin-top:25px;'><h2>قريباً: التحكم البرمجي بالـ C++ وكروت صيانة الروبوتات</h2><p style='color:#9CA3AF; line-height:1.6;'>شرح عملي وهندسي مفصل لكيفية تحويل الأوامر والمعادلات الحسابية والبرمجية إلى إشارات ميكانيكية دقيقة للـ CNC ومحركات التوجيه الميكانيكي...</p></div>"
                           "<div style='text-align:center; margin-top:35px;'><a class='btn-secondary' href='/' style='max-width:250px;'>🧮 العودة للبوابة الرئيسية</a></div>"
                           "</div>"
                           "<div class='footer'>إنشاء وتطوير: مهندس محمد الشعراوي © 2026</div>"
                           "</body></html>";
        res.set_content(blog_html, "text/html; charset=utf-8");
    });

    // تشغيل السيرفر
    const char* port_env = getenv("PORT");
    int port = port_env ? safe_stoi(port_env, 8080) : 8080;
    cout << "🚀 الخادم يعمل على المنفذ " << port << endl;
    svr.listen("0.0.0.0", port);
    return 0;
}
