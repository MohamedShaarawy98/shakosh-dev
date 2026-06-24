// ============================================================
//  منصة ضربة شاكوش — هيدر احترافي مستوحى من image_eb139e.png
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

struct RateLimitInfo {
    int count = 0;
    chrono::steady_clock::time_point reset_time;
};

static map<string, RateLimitInfo> ip_tracker;
static mutex rate_limit_mtx;
const int MAX_REQUESTS_PER_MINUTE = 12;

static string CF_VERIFY_SECRET = getenv("CF_VERIFY_SECRET") ? getenv("CF_VERIFY_SECRET") : "";
static string SECURE_HEADER_NAME = "X-Verify-Secret"; 

static int safe_stoi(const string& s, int default_val = 0) {
    try { if (s.empty()) return default_val; return stoi(s); } catch (...) { return default_val; }
}

static float safe_stof(const string& s, float default_val = 0.0f) {
    try { if (s.empty()) return default_val; return stof(s); } catch (...) { return default_val; }
}

static string html_escape(const string& data) {
    string buffer; buffer.reserve(data.size());
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

static string generate_nonce() {
    random_device rd; mt19937_64 gen(rd());
    uint64_t a = gen(), b = gen();
    ostringstream oss; oss << hex << a << b;
    return oss.str();
}

static void set_security_headers(httplib::Response& res) {
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-XSS-Protection", "1; mode=block");
    res.set_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
    res.set_header("Server", "Hammer-Engine/1.0");
}

static void set_csp(httplib::Response& res, const string& script_nonce = "") {
    string script_src = script_nonce.empty() ? "script-src 'none'; " : ("script-src 'self' 'nonce-" + script_nonce + "'; ");
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

static string get_client_ip(const httplib::Request& req) {
    if (req.has_header("CF-Connecting-IP")) return req.get_header_value("CF-Connecting-IP");
    return req.remote_addr;
}

static bool is_rate_limited(const string& ip) {
    lock_guard<mutex> lock(rate_limit_mtx);
    auto now = chrono::steady_clock::now();
    if (ip_tracker.find(ip) == ip_tracker.end() || now >= ip_tracker[ip].reset_time) {
        ip_tracker[ip].count = 1; ip_tracker[ip].reset_time = now + chrono::minutes(1); return false;
    }
    ip_tracker[ip].count++;
    return ip_tracker[ip].count > MAX_REQUESTS_PER_MINUTE;
}

class Elevator {
public:
    string get_door_type(int sa) {
        if (sa >= 210 && sa <= 250)      return "Auto 80 CO || Auto 90 CO || Auto 100 CO";
        else if (sa >= 190 && sa < 210)  return "Auto 80 CO || Auto 90 CO || Auto 100 SI";
        else if (sa >= 175 && sa < 190)  return "Auto 80 CO || Auto 100 SI || Auto 90 SI";
        else if (sa >= 167 && sa < 175)  return "Auto 90 SI || Auto 80 CO";
        else if (sa >= 160 && sa < 167)  return "Auto 90 SI || Auto 70 CO";
        else if (sa >= 155 && sa < 160)  return "Auto 80 SI || Auto 70 CO";
        else if (sa >= 145 && sa < 155)  return "Auto 80 SI";
        else if (sa >= 128 && sa < 145)  return "Auto 70 SI";
        else if (sa >= 120 && sa < 128)  return "Semi Auto 80";
        else if (sa >= 110 && sa < 120)  return "Semi Auto 70";
        return "تصفية خاصة - مراجعة يدوية";
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
        float h = (f - 1) * 3.2f + pit_m + overhead_m;
        return (t == "MRL") ? h + 1.5f : h;
    }
};

// ============================================================
//  الستايل المحدث بالكامل ليتطابق مع ألوان وهيدر image_eb139e.png
// ============================================================
static string get_modern_blue_css() {
    return "<style>"
           "*{box-sizing:border-box;}"
           "body{font-family:'Cairo', sans-serif; background-color:#0b0f19; color:#f3f4f6; direction:rtl; text-align:right; margin:0; padding:0; min-height:100vh; display:flex; flex-direction:column;}"
           
           // الهيدر المتطابق مع الصورة تماماً
           ".navbar{background-color:#0f172a; border-bottom:1px solid #1e293b; padding:15px 30px; display:flex; justify-content:space-between; align-items:center; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);}"
           ".nav-right{display:flex; align-items:center; gap:25px;}"
           ".navbar-brand{color:#ffffff; font-size:1.4rem; font-weight:700; text-decoration:none; margin-left:10px; border-left:1px solid #334155; padding-left:20px;}"
           ".nav-links{display:flex; align-items:center; gap:20px; list-style:none; margin:0; padding:0;}"
           ".nav-links a{color:#cbd5e1; font-size:1rem; font-weight:600; text-decoration:none; transition:0.2s;}"
           ".nav-links a:hover{color:#38bdf8;}"
           
           // الأيقونات جهة اليسار مثل الصورة تماماً
           ".nav-left{display:flex; align-items:center; gap:20px;}"
           ".nav-icon{color:#94a3b8; cursor:pointer; display:flex; align-items:center; justify-content:center; transition:0.2s; text-decoration:none;}"
           ".nav-icon:hover{color:#38bdf8;}"
           ".nav-icon svg{width:22px; height:22px; fill:currentColor;}"
           
           // حاوي البيانات والحاسبة
           ".container{max-width:900px; margin:0 auto; padding:50px 20px; flex:1; width:100%;}"
           ".card{background:#1e293b; border:1px solid #334155; padding:40px; border-radius:12px; box-shadow:0 20px 25px -5px rgba(0,0,0,0.3); text-align:right;}"
           ".card h2{color:#ffffff; font-size:1.6rem; margin-top:0; margin-bottom:15px; font-weight:700; border-bottom:1px solid #334155; padding-bottom:15px;}"
           ".sub-title{color:#94a3b8; margin-bottom:35px; font-size:0.95rem; line-height:1.6;}"
           ".f-group{margin-bottom:24px; text-align:right;}"
           ".f-group label{font-weight:600; color:#e2e8f0; display:block; margin-bottom:12px; font-size:0.95rem;}"
           "input,select{width:100%; padding:14px; border:1px solid #334155; border-radius:8px; text-align:right; font-size:1rem; font-family:'Cairo', sans-serif; background-color:#0f172a; color:#f3f4f6; transition:0.3s; font-weight:600; padding-right:15px; direction:rtl;}"
           "input:focus, select:focus{outline:none; border-color:#38bdf8; box-shadow:0 0 0 3px rgba(56,189,248,0.2);}"
           "button, .btn-action{background:linear-gradient(135deg, #0284c7, #0369a1); color:#ffffff; border:none; padding:16px; border-radius:8px; width:100%; font-size:1.1rem; font-weight:700; cursor:pointer; transition:0.3s; text-decoration:none; display:inline-block; text-align:center;}"
           "button:hover, .btn-action:hover{background:linear-gradient(135deg, #0369a1, #075985); transform:translateY(-1px);}"
           
           // الجداول والروابط التنافسية
           ".table-container{width:100%; overflow-x:auto; background:#0f172a; border-radius:8px; border:1px solid #334155; margin-top:20px;}"
           ".tbl{width:100%; border-collapse:collapse; text-align:right;}"
           ".tbl th{background:#1e293b; padding:15px; color:#38bdf8; font-weight:600; border-bottom:1px solid #334155; font-size:1rem; text-align:right; width:45%;}"
           ".tbl td{padding:15px; border-bottom:1px solid #334155; color:#f3f4f6; font-size:1rem; font-weight:600; text-align:right;}"
           ".actions{display:flex; justify-content:space-between; margin-top:35px; gap:20px;}"
           ".btn-print{background:linear-gradient(135deg, #16a34a, #15803d); color:white; border:none; padding:15px 25px; border-radius:8px; font-weight:700; cursor:pointer; flex:1; transition:0.3s; text-align:center; font-family:'Cairo';}"
           ".btn-print:hover{background:linear-gradient(135deg, #15803d, #166534);}"
           ".btn-secondary{background:linear-gradient(135deg, #4f46e5, #4338ca); color:white; padding:15px 25px; border-radius:8px; font-weight:700; text-align:center; flex:1; transition:0.3s; display:inline-block; text-decoration:none; font-family:'Cairo';}"
           ".btn-secondary:hover{background:linear-gradient(135deg, #4338ca, #3730a3);}"
           ".grid-nav{display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:25px; width:100%;}"
           ".nav-card{background:#1e293b; border:1px solid #334155; padding:30px; border-radius:12px; text-decoration:none; color:#f3f4f6; transition:0.3s; display:flex; flex-direction:column; text-align:right;}"
           ".nav-card:hover{border-color:#38bdf8; transform:translateY(-3px); box-shadow:0 10px 20px rgba(0,0,0,0.2);}"
           ".nav-card h3{color:#38bdf8; font-size:1.3rem; margin:0 0 12px 0;}"
           ".nav-card p{color:#94a3b8; font-size:0.95rem; line-height:1.6; margin:0;}"
           
           // التذييل المطلوب
           ".footer{margin-top:auto; padding:25px 0; font-size:15px; color:#94a3b8; text-align:center; border-top:1px solid #334155; background-color:#0f172a; font-weight:600;}"
           "@media print{.btn-print, .btn-secondary, h2, h3, .navbar, .footer {display:none;} .card{box-shadow:none; padding:0; border:none; background:none; color:#000;} .tbl th{background:#eee; color:#000;} .tbl td{color:#000;}}"
           "</style>";
}

// ============================================================
//  بناء الهيدر المتطابق ديناميكياً
// ============================================================
static string get_navbar_html() {
    return "<nav class='navbar'>"
           "  <div class='nav-right'>"
           "    <a href='/' class='navbar-brand'>ضربة شاكوش</a>"
           "    <ul class='nav-links'>"
           "      <li><a href='/'>مسارات</a></li>"
           "      <li><a href='/calculator'>دورات</a></li>"
           "      <li><a href='/calculator'>كورسات</a></li>"
           "      <li><a href='/calculator'>مشاريع</a></li>"
           "      <li><a href='/blog'>كتب</a></li>"
           "      <li><a href='/blog'>مقالات</a></li>"
           "      <li><a href='/calculator'>أسئلة</a></li>"
           "      <li><a href='/calculator'>أدوات</a></li>"
           "    </ul>"
           "  </div>"
           "  <div class='nav-left'>"
           // أيقونة البحث 🔍
           "    <a class='nav-icon' title='بحث'><svg viewBox='0 0 24 24'><path d='M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z'/></svg></a>"
           // أيقونة الوضع الداكن/الهلال 🌙
           "    <a class='nav-icon' title='الوضع الداكن' style='color:#00f0ff;'><svg viewBox='0 0 24 24'><path d='M12.3 2a10 10 0 0 0-1.9 19.8 10 10 0 0 0 11.8-11.8A10 10 0 0 1 12.3 2z'/></svg></a>"
           // أيقونة الحساب الشخصي 👤
           "    <a class='nav-icon' title='الحساب الشخصي'><svg viewBox='0 0 24 24'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z'/></svg></a>"
           "  </div>"
           "</nav>";
}

// ============================================================
//  الدالة الرئيسية
// ============================================================
int main() {
    httplib::Server svr;
    Elevator elevator;

    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);
        set_csp(res);

        if (!CF_VERIFY_SECRET.empty()) {
            if (!req.has_header(SECURE_HEADER_NAME.c_str()) || req.get_header_value(SECURE_HEADER_NAME.c_str()) != CF_VERIFY_SECRET) {
                res.status = 403; res.set_content("Forbidden.", "text/plain");
                return httplib::Server::HandlerResponse::Handled;
            }
        }
        if (is_rate_limited(get_client_ip(req))) {
            res.status = 429; res.set_content("Too Many Requests.", "text/plain");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // 1️⃣ الصفحة الرئيسية
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
                      + get_modern_blue_css() +
                      "</head><body>"
                      + get_navbar_html() +
                      "<div class='container'>"
                      "<div class='grid-nav'>"
                      "<a href='/calculator' class='nav-card'><h3>🛗 حاسبة المقاسات الهندسية</h3><p>ابدأ تصفية أبعاد البئر فوراً وحساب المقاسات الصافية للكابينة والثقل بضغطة واحدة.</p></a>"
                      "<a href='/blog' class='nav-card'><h3>📚 المكتبة والشروحات الفنية</h3><p>مراجعة شروحات التركيب الميكانيكي، صيانة الكروت، ومبادئ التحكم البرمجي.</p></a>"
                      "</div>"
                      "</div>"
                      "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 2️⃣ واجهة الحاسبة
    svr.Get("/calculator", [](const httplib::Request&, httplib::Response& res) {
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
                      + get_modern_blue_css() +
                      "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:650px;'>"
                      "<div class='card'><h2>🧮 حاسبة مقاسات بئر المصعد البضاعة</h2>"
                      "<div class='sub-title'>الرجاء إدخال المقاسات الحُرّة للبئر أدناه للبدء في الحساب التلقائي المباشر:</div>"
                      "<form action='/calculate' method='post'>"
                      "<div class='f-group'><label>👑 نوع النظام ونوع المحرك:</label><select name='m_type'><option value='MR'>غرفة محرك أعلى البئر (MR)</option><option value='MRL'>بدون غرفة محرك (MRL)</option></select></div>"
                      "<div class='f-group'><label>📐 عرض البئر الحُر الصافي (CM):</label><input type='number' name='width' required min='80' max='250' placeholder='مثال: 160'></div>"
                      "<div class='f-group'><label>📏 عمق البئر الحُر الصافي (CM):</label><input type='number' name='depth' required min='80' max='250' placeholder='مثال: 160'></div>"
                      "<div class='f-group'><label>🏢 إجمالي عدد الأدوار (الوقفات):</label><input type='number' name='floors' required min='1' max='60' placeholder='أدخل عدد الوقفات الإجمالي'></div>"
                      "<div class='f-group'><label>🕳️ عمق حفرة المصعد Pit (CM):</label><input type='number' name='depth_pit' required min='10' max='500' value='100'></div>"
                      "<div class='f-group'><label>🏠 ارتفاع الدور الأخير Overhead (CM):</label><input type='number' name='overhead' required min='100' max='800' value='400'></div>"
                      "<button type='submit'>🏛️ إجراء التصفية وحساب الكميات</button></form>"
                      "</div></div>"
                      "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 3️⃣ معالجة واستخراج تقرير المقايسة الفنية
    svr.Post("/calculate", [&elevator](const httplib::Request& req, httplib::Response& res) {
        string m_type = html_escape(req.get_param_value("m_type"));
        if (m_type != "MR" && m_type != "MRL") m_type = "MR";

        int w = safe_stoi(req.get_param_value("width"), 0);
        int d = safe_stoi(req.get_param_value("depth"), 0);
        float f = safe_stof(req.get_param_value("floors"), 0.0f);
        int p = safe_stoi(req.get_param_value("depth_pit"), 100);
        int oh = safe_stoi(req.get_param_value("overhead"), 400);

        if (w < 110 || d < 100) {
            string err = "<html><head><meta charset='UTF-8'>" + get_modern_blue_css() + "</head><body>"
                         "<div style='display:flex; align-items:center; justify-content:center; min-height:100vh;'>"
                         "<div class='card' style='border-color:#ef4444; max-width:500px;'>"
                         "<h2 style='color:#ef4444;'>⚠️ الأبعاد المدخلة غير متوافقة</h2>"
                         "<p style='color:#94a3b8;'>المقاسات الحالية أقل من الحد الأدنى القياسية (العرض الأدنى 110سم، والعمق 100سم).</p>"
                         "<a href='/calculator' class='btn-action' style='background:#ef4444;'>🔄 العودة وتعديل المقاسات</a>"
                         "</div></div>"
                         "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                         "</body></html>";
            res.set_content(err, "text/html; charset=utf-8"); return;
        }

        string door = elevator.get_door_type(w);
        int cabin_dbg = elevator.get_cabin_dbg(w);
        int cwt_dbg = elevator.get_cwt_dbg(w);
        int cab_w = elevator.get_cabin_width(w);
        int cab_d = elevator.get_cabin_depth(d);
        float h = elevator.get_shaft_height(f, p/100.0f, oh/100.0f, m_type);

        string nonce = generate_nonce(); set_csp(res, nonce);
        ostringstream os;
        os << "<html><head><meta charset='UTF-8'><link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
           + get_modern_blue_css() + "</head><body>"
           << get_navbar_html()
           << "<div class='container' style='max-width:750px;'>"
           << "<div class='card'><h2>📋 تقرير تصفية المقاسات النهائي</h2>"
           << "<div class='table-container'><table class='tbl'>"
           << "<tr><th>نوع باب المصعد المتاح للمساحة:</th><td style='color:#38bdf8;'>" << door << "</td></tr>"
           << "<tr><th>مقاس DBG الكابينة الصافي:</th><td>" << cabin_dbg << " CM</td></tr>"
           << "<tr><th>مقاس DBG ثقل الموازنة (CWT):</th><td>" << (cwt_dbg ? to_string(cwt_dbg) + " CM" : "مراجعة فنية") << "</td></tr>"
           << "<tr><th>صافي العرض الداخلي للكابينة:</th><td>" << cab_w << " CM</td></tr>"
           << "<tr><th>صافي العمق الداخلي للكابينة:</th><td>" << cab_d << " CM</td></tr>"
           << "<tr><th>إجمالي مشوار البئر المحسوب:</th><td style='color:#38bdf8;'>" << h << " متر</td></tr>"
           << "</table></div>"
           << "<div class='actions'>"
           << "<button class='btn-print' id='pBtn'>🖨️ طباعة أو حفظ التقرير</button>"
           << "<a class='btn-secondary' href='/calculator'>🔄 حساب أبعاد جديدة</a>"
           << "</div></div></div>"
           << "<div class='footer'>إنشاء : محمد الشعراوي</div>"
           << "<script nonce='" << nonce << "'>document.getElementById('pBtn').addEventListener('click', function(){ window.print(); });</script>"
           << "</body></html>";
        res.set_content(os.str(), "text/html; charset=utf-8");
    });

    // 4️⃣ صفحة المقالات
    svr.Get("/blog", [](const httplib::Request&, httplib::Response& res) {
        string html = "<html><head><meta charset='UTF-8'>" + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container'>"
                      "<h1>📚 الشروحات والمقالات الهندسية</h1>"
                      "<div class='card'><h2>قريباً: رفع المخططات التنفيذية والتركيبات</h2><p style='color:#94a3b8;'>انتظروا الشروحات التفصيلية لرفع وتصفية المواقع عملياً.</p></div>"
                      "</div>"
                      "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    const char* port_env = getenv("PORT");
    int port = port_env ? safe_stoi(port_env, 8080) : 8080;
    cout << "🚀 Modern Blue Server running on port: " << port << endl;
    svr.listen("0.0.0.0", port);
    return 0;
}
