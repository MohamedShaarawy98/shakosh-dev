/*                      <  وَأَن لَّيْسَ لِلإِنسَانِ إِلاَّ مَا سَعَى * وَأَنَّ سَعْيَهُ سوفَ يُرَى * ثُمَّ يُجْزَاهُ الْجَزَاء الأَوْفَى  >

                                       ============================================================
                                       =                                                          =
                                       =                  منصة ضربة شاكوش الرقمية                 =
                                       =                                                          =
                                       ============================================================
 */          

#include "httplib.h"
#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <algorithm>
#include <map>
#include <vector>
#include <chrono>
#include <mutex>
#include <random>

using namespace std;

// بنية بيانات لتحديد معدل الطلبات لحماية السيرفر من هجمات الحرمان من الخدمة
struct RateLimitInfo {
    int count = 0;
    chrono::steady_clock::time_point reset_time;
};

static map<string, RateLimitInfo> ip_tracker;
static mutex rate_limit_mtx;
const int MAX_REQUESTS_PER_MINUTE = 20; // رفع الحد الأقصى قليلاً لضمان سلاسة التصفح للأدوات

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
    res.set_header("Server", "Hammer-Engine/1.1");
}

static void set_csp(httplib::Response& res, const string& script_nonce = "") {
    string script_src = script_nonce.empty() ? "script-src 'none'; " : ("script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com 'nonce-" + script_nonce + "'; ");
    string csp = "default-src 'self'; "
                 "img-src 'self' data: https://media.darbat-shakosh.com https://flagcdn.com; " // السماح بنطاق الصور والأعلام
                 "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                 "font-src https://fonts.gstatic.com; "
                 + script_src +
                 "connect-src 'self'; "
                 "frame-src https://www.youtube.com; "
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
        else if (sa >= 145 && sa < 155)  return "Auto 80 SI || S";
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

struct Lesson {
    string slug;          
    string track_slug;    
    string type;          
    string title;
    string summary;       
    string content_html;  
    string video_embed_url; 
    int order;             
};

struct Track {
    string slug;        
    string emoji;
    string title;
    string description;
};

static vector<Track> get_tracks() {
    return {
        { "basics", "🧱", "مسار الأساسات الهندسية", "المفاهيم الأولى لتصفية أبعاد بئر المصعد ومكوناته الرئيسية وقراءة المخططات الفنية." },
        { "doors",  "🚪", "مسار أبواب المصاعد", "أنواع الأبواب وأكواد الفتح المختلفة وإزاي تختار النوع المناسب للمساحة المتوفرة لبئر المصعد." },
        { "darbat" , "🔨" , "كورس كهرباء المصاعد الشامل"  , "كورس تطبيقي متخصص في تعليم كل شيء يخص كهرباء الدوائر، الكنترولات، وتوصيل كوابل الأمان."}
    }; 
}

static vector<Lesson> get_lessons() {
    return {
        { "intro-shaft-dimensions", "basics", "video",
          "مقدمة هندسية: فهم أبعاد بئر المصعد الصافية",
          "شرح فني يوضح الفرق بين البئر الحر والـ Pit والـ Overhead وأهميتهم الكبرى في التصفية الميكانيكية.",
          "<p>بئر المصعد بيتكون من 3 قياسات أساسية لازم تكون دقيقة جداً قبل البدء في أي تصفية هندسية: "
          "العرض والعمق الحُرّين للبئر، عمق حفرة الـ Pit أسفل المحطة الأخيرة، وارتفاع الـ Overhead فوق آخر وقفة للمصعد.</p>"
          "<p>أي خطأ بسيط في أي قياس من القياسات الثلاثة بيأثر مباشرة على نوع الباب المتاح ومقاس الكابينة الصافي، "
          "وده اللي بتحسبه الحاسبة الذكية أوتوماتيك من غير الحاجه لجدول ورقي معقد.</p>",
          "https://www.youtube.com/embed/ZluG-pfc2HY", 1},

        { "door-types-explained", "doors", "video",
          "شرح أنواع أبواب المصاعد الأوتوماتيكية والنص أوتوماتيك Auto / Semi",
          "فيديو تفصيلي يوضح الفرق بين أبواب السنتر CO وأبواب التلسكوب الجانبية SI وإزاي تختار المقاس والنوع المناسب لبئرك وعرض فتحة الصاعدة.",
          "",
          "https://www.youtube.com/embed/ZluG-pfc2HY", 1},

          {"darbat-shakosh-one" ,"darbat" , "video", 
            "توصيل الكنترول وقفل دوائر الأمان - الدرس 2",
            "أهمية ترتيب خطوات تأسيس خطوط الكهرباء وربط دوائر السلسلة للامان وضمان الشغل النضيف والمطابق للمواصفات.",
          "<p> أولاً: يتم التأكد من كهرباء المبنى وتغذية المصدر سواء كانت الفازة 220 فولت أو 380 فولت لعمل وتأسيس لوحة الكنترول على هذا الأساس السليم.</p>"
          "<p> ثانياً: تركيب الكنترول وتوصيل المحرك (الماكينة) وقفل دوائر السيفتي الرئيسية {الشوكة - الكالون - الاستوب} ثم اختبار حركة المصعد السريعة والبطيئة لضمان الاستجابة.</p>",
          "https://www.youtube.com/embed/ZluG-pfc2HY", 2},

           {"darbat-shakosh-tow" ,"darbat" , "article", 
            "المبادئ الأولى لكهرباء وكروت المصاعد - الدرس 1",
            "نظرة عامة على لوحة التحكم والروابط الكهربائية وتغذية الفرامل ومغناطيس التهدئة والتوقف الفني.",
          "<p> أولاً: يتم التأكد من كهرباء المبنى وتغذية المصدر سواء كانت الفازة 220 فولت أو 380 فولت لعمل وتأسيس لوحة الكنترول على هذا الأساس السليم.</p>"
          "<img src='https://media.darbat-shakosh.com/IMG_20260618_101939_-٤٢٠١٠.jpg' style='width:100%; max-width:600px; display:block; border-radius:8px; margin:20px auto; border:1px solid var(--border);' alt='خريطة ومخطط المصعد الفني'>"
          "<p> ثانياً: تركيب الكنترول وتوصيل المحرك (الماكينة) وقفل دوائر السيفتي الرئيسية {الشوكة - الكالون - الاستوب} ثم اختبار حركة المصعد السريعة والبطيئة لضمان الاستجابة.</p>",
          "https://www.youtube.com/embed/ZluG-pfc2HY", 1}
    };
}
static vector<Lesson> get_lessons_by_track(const string& track_slug) {
    vector<Lesson> all = get_lessons();
    vector<Lesson> filtered;
    for (auto& l : all) if (l.track_slug == track_slug) filtered.push_back(l);
    sort(filtered.begin(), filtered.end(), [](const Lesson& a, const Lesson& b) { return a.order < b.order; });
    return filtered;
}

static string get_modern_blue_css() {
    return "<style>"
           "*{box-sizing:border-box;}"
           ":root{"
           "--bg:#0a0e16; --surface:#121826; --surface-2:#1a2233; --border:#232c3f;"
           "--accent:#38bdf8; --accent-dim:rgba(56,189,248,0.14); --accent-2:#f5a524;"
           "--text:#f3f4f6; --text-muted:#8b96ab;"
           "--font-display:'Cairo', sans-serif; --font-mono:'JetBrains Mono', 'Cairo', monospace;"
           "}"
           "@media (prefers-reduced-motion: reduce){*{animation-duration:0.01ms !important; transition-duration:0.01ms !important;}}"
           "body{font-family:var(--font-display); background-color:var(--bg); color:var(--text); direction:rtl; text-align:right; margin:0; padding:0; min-height:100vh; display:flex; flex-direction:column;"
           "background-image:linear-gradient(rgba(56,189,248,0.045) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.045) 1px, transparent 1px);"
           "background-size:30px 30px;}"
           "a{outline-offset:3px; text-decoration:none; color:inherit;}"
           ":focus-visible{outline:2px solid var(--accent); outline-offset:2px; border-radius:4px;}"

           // ===== الهيدر المحترف =====
           ".navbar{background-color:var(--surface); border-bottom:1px solid var(--border); padding:14px 28px; display:flex; justify-content:space-between; align-items:center; position:relative; z-index:50; box-shadow:0 4px 6px -1px rgba(0,0,0,0.15);}"
           ".nav-right{display:flex; align-items:center; gap:20px; flex-wrap:wrap;}"
           ".navbar-brand{display:flex; align-items:center; gap:10px; color:#ffffff; font-size:1.25rem; font-weight:800; text-decoration:none; padding-inline-end:22px; border-inline-end:1px solid var(--border);}"
           ".brand-mark{width:34px; height:34px; flex-shrink:0; border-radius:8px; display:flex; align-items:center; justify-content:center; overflow:hidden; border: 1px solid var(--border); background-color: var(--bg);}"
           ".brand-mark img{width:100%; height:100%; object-fit:cover;}"
           ".nav-center{display:flex; align-items:center; gap:18px; flex-wrap:wrap;}"
           ".nav-link{color:#cbd5e1; font-size:1rem; font-weight:600; text-decoration:none; transition:color 0.15s;}"
           ".nav-link:hover{color:var(--accent);}"
           ".nav-dropdown{position:relative;}"
           ".nav-dropdown summary{cursor:pointer; list-style:none; display:flex; align-items:center; gap:6px; color:#cbd5e1; font-weight:600; font-size:1rem; user-select:none;}"
           ".nav-dropdown summary::-webkit-details-marker{display:none;}"
           ".nav-dropdown summary:hover{color:var(--accent);}"
           ".nav-dropdown .chevron{width:13px; height:13px; fill:currentColor; transition:transform 0.2s;}"
           ".nav-dropdown[open] .chevron{transform:rotate(180deg);}"
           ".dropdown-panel{position:absolute; inset-inline-start:0; top:calc(100% + 16px); display:flex; gap:30px; background:var(--surface-2); border:1px solid var(--border); border-radius:12px; padding:18px 22px; min-width:190px; box-shadow:0 20px 25px -5px rgba(0,0,0,0.45); z-index:60; animation:dropdownIn 0.18s ease;}"
           "@keyframes dropdownIn{from{opacity:0; transform:translateY(-6px);} to{opacity:1; transform:translateY(0);}}"
           ".dropdown-col{display:flex; flex-direction:column; gap:11px; min-width:150px;}"
           ".dropdown-panel a, .mobile-panel a{color:#e2e8f0; font-size:0.95rem; font-weight:600; text-decoration:none; transition:color 0.15s;}"
           ".dropdown-panel a:hover{color:var(--accent);}"
           ".desktop-only{display:flex;}"
           ".mobile-only{display:none;}"
           "@media (max-width:860px){.desktop-only{display:none;} .mobile-only{display:flex;} .navbar-brand span:last-child{font-size:1.05rem;}}"

           // ===== شريط الأعلام الفاخر والمظلل تحت الهيدر مباشرة في جهة اليسار (Responsive) =====
           ".flags-strip{background:rgba(18,24,38,0.4); backdrop-filter:blur(10px); -webkit-backdrop-filter:blur(10px); border-bottom:1px solid var(--border); padding:6px 28px; display:flex; justify-content:flex-end; align-items:center; position:relative; z-index:40;}"
           ".flags-badge-box{display:flex; align-items:center; gap:12px; background:rgba(35,44,63,0.5); border:1px solid rgba(56,189,248,0.2); padding:5px 14px; border-radius:30px; box-shadow:inset 0 1px 2px rgba(255,255,255,0.05), 0 4px 10px rgba(0,0,0,0.3); margin-left:auto;}" // جعل الـ margin-left تلقائياً لنقلها لليسار
           ".flag-img-unit{width:22px; height:15px; border-radius:2px; box-shadow:0 2px 4px rgba(0,0,0,0.4); object-fit:cover; display:block;}"
           ".flag-img-sep{color:rgba(139,150,171,0.4); font-size:0.8rem; font-weight:300; user-select:none;}"

           // ===== قائمة الموبايل والتابلت الجانبية =====
           ".nav-left{display:flex; align-items:center; gap:18px;}"
           ".nav-icon{color:#94a3b8; cursor:pointer; display:flex; align-items:center; justify-content:center; transition:0.2s; text-decoration:none; list-style:none;}"
           ".nav-icon::-webkit-details-marker{display:none;}"
           ".nav-icon:hover{color:var(--accent);}"
           ".nav-icon svg{width:22px; height:22px; fill:currentColor;}"
           ".mobile-menu{position:relative;}"
           ".mobile-panel{position:absolute; inset-inline-end:0; top:calc(100% + 14px); background:var(--surface-2); border:1px solid var(--border); border-radius:12px; padding:18px 20px; display:flex; flex-direction:column; gap:4px; min-width:230px; box-shadow:0 20px 25px -5px rgba(0,0,0,0.45); z-index:60; animation:dropdownIn 0.18s ease;}"
           ".mobile-panel a{padding:9px 6px; border-radius:6px; display:block;}"
           ".mobile-panel a:hover{background:rgba(56,189,248,0.1); color:var(--accent);}"
           ".mobile-divider{height:1px; background:var(--border); margin:8px 2px;}"

           // ===== الحاويات والبطاقات الهندسية =====
           ".container{max-width:900px; margin:0 auto; padding:50px 20px; flex:1; width:100%;}"
           ".card{position:relative; background:var(--surface); border:1px solid var(--border); padding:40px; border-radius:12px; box-shadow:0 20px 25px -5px rgba(0,0,0,0.3); text-align:right;}"
           ".card::before, .nav-card::before{content:''; position:absolute; top:-1px; right:-1px; width:18px; height:18px; border-top:2px solid var(--accent); border-right:2px solid var(--accent); border-top-right-radius:6px; opacity:0.6;}"
           ".card::after, .nav-card::after{content:''; position:absolute; bottom:-1px; left:-1px; width:18px; height:18px; border-bottom:2px solid var(--accent); border-left:2px solid var(--accent); border-bottom-left-radius:6px; opacity:0.6;}"
           ".card h2{color:#ffffff; font-size:1.6rem; margin-top:0; margin-bottom:15px; font-weight:700; border-bottom:1px solid var(--border); padding-bottom:15px;}"
           ".sub-title{color:var(--text-muted); margin-bottom:35px; font-size:0.95rem; line-height:1.6;}"
           ".f-group{margin-bottom:24px; text-align:right;}"
           ".f-group label{font-weight:600; color:#e2e8f0; display:block; margin-bottom:12px; font-size:0.95rem;}"
           "input,select{width:100%; padding:14px; border:1px solid var(--border); border-radius:8px; text-align:right; font-size:1rem; font-family:var(--font-display); background-color:var(--bg); color:var(--text); transition:0.3s; font-weight:600; padding-right:15px; direction:rtl;}"
           "input:focus, select:focus{outline:none; border-color:var(--accent); box-shadow:0 0 0 3px rgba(56,189,248,0.2);}"
           "button, .btn-action{background:linear-gradient(135deg, #0284c7, #0369a1); color:#ffffff; border:none; padding:16px; border-radius:8px; width:100%; font-size:1.1rem; font-weight:700; cursor:pointer; transition:0.3s; text-decoration:none; display:inline-block; text-align:center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);}"
           "button:hover, .btn-action:hover{background:linear-gradient(135deg, #0369a1, #075985); transform:translateY(-1px);}"

           // ===== الجداول وجداول تقرير المعاينة =====
           ".table-container{position:relative; width:100%; overflow-x:auto; background:var(--bg); border-radius:8px; border:1px solid var(--border); margin-top:20px;}"
           ".tbl{width:100%; border-collapse:collapse; text-align:right;}"
           ".tbl th{background:var(--surface); padding:15px; color:var(--accent); font-weight:600; border-bottom:1px solid var(--border); font-size:1rem; text-align:right; width:45%;}"
           ".tbl td{padding:15px; border-bottom:1px solid var(--border); color:var(--text); font-size:1rem; font-weight:600; text-align:right; font-family:var(--font-mono);}"
           ".actions{display:flex; justify-content:space-between; margin-top:35px; gap:20px;}"
           ".btn-print{background:linear-gradient(135deg, #16a34a, #15803d); color:white; border:none; padding:15px 25px; border-radius:8px; font-weight:700; cursor:pointer; flex:1; transition:0.3s; text-align:center; font-family:var(--font-display); box-shadow: 0 4px 6px rgba(0,0,0,0.1);}"
           ".btn-print:hover{background:linear-gradient(135deg, #15803d, #166534);}"
           ".btn-secondary{background:linear-gradient(135deg, #4f46e5, #4338ca); color:white; padding:15px 25px; border-radius:8px; font-weight:700; text-align:center; flex:1; transition:0.3s; display:inline-block; text-decoration:none; font-family:var(--font-display); box-shadow: 0 4px 6px rgba(0,0,0,0.1);}"
           ".btn-secondary:hover{background:linear-gradient(135deg, #4338ca, #3730a3);}"
           ".grid-nav{display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:25px; width:100%;}"
           ".nav-card{position:relative; background:var(--surface); border:1px solid var(--border); padding:30px; border-radius:12px; text-decoration:none; color:var(--text); transition:0.3s; display:flex; flex-direction:column; text-align:right;}"
           ".nav-card:hover{border-color:var(--accent); transform:translateY(-3px); box-shadow:0 10px 20px rgba(0,0,0,0.2);}"
           ".nav-card h3{color:var(--accent); font-size:1.3rem; margin:0 0 12px 0;}"
           ".nav-card p{color:var(--text-muted); font-size:0.95rem; line-height:1.6; margin:0;}"

           // ===== مشغلات الفيديوهات الذكية السلسة =====
           ".section-intro{margin-bottom:30px; text-align:right;}"
           ".section-intro h1{color:#ffffff; font-size:1.7rem; font-weight:800; margin:0 0 8px 0;}"
           ".section-intro p{color:var(--text-muted); font-size:1rem; line-height:1.7; margin:0;}"
           ".lesson-tag{display:inline-flex; align-items:center; gap:5px; font-size:0.78rem; font-weight:700; padding:4px 10px; border-radius:20px; margin-bottom:12px; width:fit-content;}"
           ".tag-article{background:rgba(56,189,248,0.14); color:var(--accent);}"
           ".tag-video{background:rgba(245,165,36,0.16); color:var(--accent-2);}"
           ".video-embed{position:relative; width:100%; aspect-ratio:16/9; border-radius:10px; overflow:hidden; background:#000; margin:20px 0; border:1px solid var(--border); box-shadow: 0 4px 12px rgba(0,0,0,0.3);}"
           ".video-embed iframe{position:absolute; inset:0; width:100%; height:100%; border:0;}"
           ".lesson-body{color:#e2e8f0; font-size:1.02rem; line-height:1.9; background: var(--bg); padding: 20px; border-radius: 8px; border: 1px solid var(--border); margin-top: 15px;}"
           ".lesson-body p{margin:0 0 16px 0;}"
           ".track-list{display:flex; flex-direction:column; gap:14px; margin-top:10px;}"
           ".track-item{display:flex; align-items:flex-start; gap:16px; background:var(--bg); border:1px solid var(--border); border-radius:10px; padding:18px 20px; text-decoration:none; transition:0.2s;}"
           ".track-item:hover{border-color:var(--accent); transform:translateX(-3px);}"
           ".track-order{flex-shrink:0; width:34px; height:34px; border-radius:8px; background:var(--surface-2); color:var(--accent); font-family:var(--font-mono); font-weight:700; display:flex; align-items:center; justify-content:center; font-size:0.95rem;}"
           ".track-item-title{color:#f3f4f6; font-weight:700; font-size:1.02rem; margin-bottom:4px;}"

           // ===== التذييل =====
           ".footer{margin-top:auto; padding:25px 0; font-size:15px; color:var(--text-muted); text-align:center; border-top:1px solid var(--border); background-color:var(--surface); font-weight:600;}"
           "@media print{.btn-print, .btn-secondary, h2, h3, .navbar, .flags-strip, .footer {display:none;} .card{box-shadow:none; padding:0; border:none; background:none; color:#000;} .card::before, .card::after{display:none;} .tbl th{background:#eee; color:#000;} .tbl td{color:#000; font-family:inherit;}}"
           "</style>";
}

// التايتل المطلوب "موقع ضربة شاكوش" وربط أيقونة التبويب برابط الـ R2 المباشر
static string get_seo_meta(const string& title, const string& desc) {
    return "<title>موقع ضربة شاكوش</title>"
           "<link rel='icon' type='image/jpeg' href='https://media.darbat-shakosh.com/channels4_profile%20(1).jpg'>"
           "<meta name='description' content='" + desc + "'>"
           "<meta name='keywords' content='حاسبة مقاسات المصاعد, كورس كهرباء المصاعد, تصفية أبعاد بئر المصعد, صيانة المصاعد, ميكانيكا المصاعد, ضربة شاكوش, هندسة المصاعد'>"
           "<meta name='robots' content='index, follow'>";
}

// تعديل نص الهيدر واللوجو، وإضافة كبسولة الأعلام الفاخرة بدون نصوص في جهة اليسار بالترتيب المكتوب
static string get_navbar_html() {
    const string logo_url = "https://media.darbat-shakosh.com/channels4_profile%20(1).jpg"; 
    const string chevron_svg = "<svg class='chevron' viewBox='0 0 24 24'><path d='M7 10l5 5 5-5z'/></svg>";

    return "<nav class='navbar'>"
           "  <div class='nav-right'>"
           "    <a href='/' class='navbar-brand'><span class='brand-mark'><img src='" + logo_url + "' alt='لوجو ضربة شاكوش'></span><span>ضربة شاكوش </span></a>"
           "    <div class='nav-center desktop-only'>"
           "      <a href='/' class='nav-link'>الرئيسية</a>"
           "      <a href='/paths' class='nav-link'>مسارات التعلّم</a>"
           "      <a href='/blog' class='nav-link'>الشروحات والمقالات</a>"
           "      <a href='/calculator' class='nav-link'>الحاسبة الهندسية</a>"
           "      <details class='nav-dropdown'>"
           "        <summary>المزيد " + chevron_svg + "</summary>"
           "        <div class='dropdown-panel'>"
           "          <div class='dropdown-col'>"
           "            <a href='/contact'>اتصل بنا</a>"
           "            <a href='/support'>مركز الدعم</a>"
           "            <a href='/donate'>دعم المنصة</a>"
           "          </div>"
           "        </div>"
           "      </details>"
           "    </div>"
           "  </div>"
           "  <div class='nav-left'>"
           "    <a class='nav-icon' title='بحث الفيديوهات'><svg viewBox='0 0 24 24'><path d='M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z'/></svg></a>"
           "    <a class='nav-icon' title='بوابة المشتركين'><svg viewBox='0 0 24 24'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z'/></svg></a>"
           "    <details class='nav-dropdown mobile-menu mobile-only'>"
           "      <summary class='nav-icon' title='القائمة'><svg viewBox='0 0 24 24'><path d='M3 6h18v2H3zm0 5h18v2H3zm0 5h18v2H3z'/></svg></summary>"
           "      <div class='mobile-panel'>"
           "        <a href='/'>الرئيسية</a>"
           "        <a href='/paths'>مسارات التعلّم</a>"
           "        <a href='/blog'>الشروحات والمقالات</a>"
           "        <a href='/calculator'>الحاسبة الهندسية</a>"
           "        <div class='mobile-divider'></div>"
           "        <a href='/contact'>اتصل بنا</a>"
           "        <a href='/support'>مركز الدعم</a>"
           "        <a href='/donate'>دعم المنصة</a>"
           "      </div>"
           "    </details>"
           "  </div>"
           "</nav>"
           // شريط الأعلام الفاخر الموجه أوتوماتيكياً لجهة اليسار (Left Side) وبدون أي كلمات وبترتيب (فلسطين -> مصر -> السعودية)
           "<div class='flags-strip'>"
           "  <div class='flags-badge-box'>"
           "    <img src='https://flagcdn.com/w40/ps.png' class='flag-img-unit' alt='Gaza Palestine'>"
           "    <span class='flag-img-sep'>|</span>"
           "    <img src='https://flagcdn.com/w40/eg.png' class='flag-img-unit' alt='Egypt'>"
           "    <span class='flag-img-sep'>|</span>"
           "    <img src='https://flagcdn.com/w40/sa.png' class='flag-img-unit' alt='Saudi Arabia'>"
           "  </div>"
           "</div>";
}

// ============================================================
//  الدالة الرئيسية وتشغيل المنصة
// ============================================================
int main() {
    httplib::Server svr;
    Elevator elevator;

    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);
        set_csp(res);

        if (!CF_VERIFY_SECRET.empty()) {
            if (!req.has_header(SECURE_HEADER_NAME.c_str()) || req.get_header_value(SECURE_HEADER_NAME.c_str()) != CF_VERIFY_SECRET) {
                res.status = 403; res.set_content("Forbidden Access.", "text/plain");
                return httplib::Server::HandlerResponse::Handled;
            }
        }
        if (is_rate_limited(get_client_ip(req))) {
            res.status = 429; res.set_content("Too Many Requests. Please wait a moment.", "text/plain");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // 1️⃣ الصفحة الرئيسية
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        string meta = get_seo_meta("المنصة التعليمية والهندسية الأولى للمصاعد", "شروحات فنية متخصصة في ميكانيكا وكهرباء المصاعد وحساب أبعاد الصاعدة هندسياً.");
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + meta + get_modern_blue_css() +
                      "</head><body>"
                      + get_navbar_html() +
                      "<div class='container'>"
                      "<div class='section-intro' style='text-align: center; margin-bottom: 40px;'>"
                      "  <h1 style='color: #ffffff; font-size: 2.2rem;'>مرحباً بك في منصة ضربة شاكوش الرقمية</h1>"
                      "  <p style='color: var(--text-muted); font-size: 1.1rem;'>الأدوات الهندسية الذكية والكورسات التطبيقية المتخصصة في مجال تركيب وصيانة المصاعد.</p>"
                      "</div>"
                      "<div class='grid-nav'>"
                      "  <a href='/calculator' class='nav-card'><h3>🛗 حاسبة المقاسات الهندسية</h3><p>ابدأ تصفية أبعاد البئر فوراً وحساب المقاسات الصافية للكابينة وثقل الموازنة بضغطة واحدة وبشكل معتمد.</p></a>"
                      "  <a href='/paths' class='nav-card'><h3>🧭 مسارات الكورسات والتعلم</h3><p>اكتشف مسار التأسيس ميكانيكياً، وكورس كهرباء المصاعد الشامل لتوصيل اللوحات والكنترولات خطوة بخطوة.</p></a>"
                      "</div>"
                      "</div>"
                      "<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 2️⃣ واجهة الحاسبة
    svr.Get("/calculator", [](const httplib::Request&, httplib::Response& res) {
        string meta = get_seo_meta("حاسبة مقاسات بئر ومقصورة المصاعد", "أداة هندسية لحساب وتصفية مقاسات كابينة المصعد وأبعاد الثقل ونوع الأبواب المتاحة أوتوماتيكياً.");
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + meta + get_modern_blue_css() +
                      "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:650px;'>"
                      "<div class='card'><h2>🧮 حاسبة مقاسات بئر المصعد الفنية</h2>"
                      "<div class='sub-title'>الرجاء إدخال القياسات الحُرّة الصافية المأخوذة من الموقع للبء في الحساب والتصفية التلقائية للمقايسة المعمارية:</div>"
                      "<form action='/calculate' method='post'>"
                      "<div class='f-group'><label>👑 نوع نظام تشغيل المصعد:</label><select name='m_type'><option value='MR'>غرفة محرك أعلى البئر القياسي (MR)</option><option value='MRL'>نظام بدون غرفة محرك علوية (MRL)</option></select></div>"
                      "<div class='f-group'><label>📐 عرض بئر المصعد الحُر الصافي (CM):</label><input type='number' name='width' required min='80' max='250' placeholder='مثال لعرض البئر الحُر: 160'></div>"
                      "<div class='f-group'><label>📏 عمق بئر المصعد الحُر الصافي (CM):</label><input type='number' name='depth' required min='80' max='250' placeholder='مثال لعمق البئر الحُر: 160'></div>"
                      "<div class='f-group'><label>🏢 إجمالي عدد الوقفات (الأدوار الإنشائية):</label><input type='number' name='floors' required min='1' max='60' placeholder='أدخل عدد طوابق المبنى'></div>"
                      "<div class='f-group'><label>🕳️ عمق حفرة المصعد السفلية Pit (CM):</label><input type='number' name='depth_pit' required min='10' max='500' value='100'></div>"
                      "<div class='f-group'><label>🏠 ارتفاع الدور الأخير من بلاطة الوقف للجريد Overhead (CM):</label><input type='number' name='overhead' required min='100' max='800' value='400'></div>"
                      "<button type='submit'>🏛️ استخراج مقاسات الصاعدة الهندسية وتوليد المقايسة</button></form>"
                      "</div></div>"
                      "<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 3️⃣ نظام معالجة وتصدير تقرير المقايسة الفنية لـ PDF
    svr.Post("/calculate", [&elevator](const httplib::Request& req, httplib::Response& res) {
        string m_type = html_escape(req.get_param_value("m_type"));
        if (m_type != "MR" && m_type != "MRL") m_type = "MR";

        int w = safe_stoi(req.get_param_value("width"), 0);
        int d = safe_stoi(req.get_param_value("depth"), 0);
        float f = safe_stof(req.get_param_value("floors"), 0.0f);
        int p = safe_stoi(req.get_param_value("depth_pit"), 100);
        int oh = safe_stoi(req.get_param_value("overhead"), 400);

        if (w < 110 || d < 100) {
            string err = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                         "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                         + get_modern_blue_css() + "</head><body>"
                         "<div style='display:flex; align-items:center; justify-content:center; min-height:100vh;'>"
                         "<div class='card' style='border-color:#ef4444; max-width:500px; text-align:center;'>"
                         "<h2 style='color:#ef4444;'>⚠️ الأبعاد المدخلة غير مطابقة للمواصفات</h2>"
                         "<p style='color:#94a3b8;'>المقاسات الحالية المكتوبة أقل من الحد الأدنى الهندسي لتركيب المصاعد القياسية (العرض المطلوب الأدنى 110سم، والعمق 100سم).</p>"
                         "<a href='/calculator' class='btn-action' style='background:#ef4444;'>🔄 العودة وتعديل أبعاد البئر</a>"
                         "</div></div>"
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
        os << "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
           "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
           "<script src='https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js'></script>"
           + get_modern_blue_css() + "</head><body>"
           << get_navbar_html()
           << "<div class='container' style='max-width:750px;'>"
           << "<div class='card' id='pdf-area'><h2>📋 تقرير تصفية المقاسات النهائي المعتمد</h2>"
           << "<div class='sub-title' style='margin-bottom:20px;'>منصة ضربة شاكوش لحساب أبعاد الكابينة ومقايسات بئر المصاعد الإنشائية:</div>"
           << "<div class='table-container'><table class='tbl'>"
           << "<tr><th>نوع ونظام التشغيل:</th><td>" << (m_type == "MR" ? "غرفة محرك علوية" : "بدون غرفة محرك MRL") << "</td></tr>"
           << "<tr><th>أبعاد البئر المدخلة:</th><td>العرض: " << w << " سم || العمق: " << d << " سم</td></tr>"
           << "<tr><th>نوع وعرض باب المصعد المتاح هندسياً:</th><td style='color:#38bdf8; font-weight:700;'>" << door << "</td></tr>"
           << "<tr><th>مقاس شاسيه DBG الكابينة الصافي:</th><td>" << cabin_dbg << " CM</td></tr>"
           << "<tr><th>مقاس شاسيه DBG ثقل الموازنة (CWT):</th><td>" << (cwt_dbg ? to_string(cwt_dbg) + " CM" : "مراجعة فنية يدوية") << "</td></tr>"
           << "<tr><th>صافي العرض الداخلي لكابينة المصعد:</th><td style='color:#f5a524;'>" << cab_w << " CM</td></tr>"
           << "<tr><th>صافي العمق الداخلي لكابينة المصعد:</th><td style='color:#f5a524;'>" << cab_d << " CM</td></tr>"
           << "<tr><th>إجمالي مشوار البئر والارتفاع الرأسي المحسوب:</th><td style='color:#38bdf8;'>" << h << " متر طولي</td></tr>"
           << "</table></div>"
           << "<p style='margin-top:25px; font-size:0.85rem; color:var(--text-muted); text-align:center;'>تمت التصفية والمطابقة آلياً بالاعتماد على خوارزميات التصفية القياسية للمصاعد.</p>"
           << "</div>" 
           << "<div class='actions' style='max-width:750px; margin: 20px auto 0 auto; padding:0 40px;'>"
           << "  <button class='btn-print' id='pBtn'>📥 تحميل التقرير كملف PDF مخصص</button>"
           << "  <a class='btn-secondary' href='/calculator'>🔄 تصفية مقاسات بئر جديد</a>"
           << "</div></div>"
           <<"<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
           << "<script nonce='" << nonce << "'>"
           << "  document.getElementById('pBtn').addEventListener('click', function(){"
           << "    var element = document.getElementById('pdf-area');"
           << "    var opt = {"
           << "      margin:       0.5,"
           << "      filename:     'Shakosh_Elevator_Report.pdf',"
           << "      image:        { type: 'jpeg', quality: 0.98 },"
           << "      html2canvas:  { scale: 2, backgroundColor: '#121826' },"
           << "      jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }"
           << "    };"
           << "    html2pdf().set(opt).from(element).save();"
           << "  });"
           << "</script>"
           << "</body></html>";
        res.set_content(os.str(), "text/html; charset=utf-8");
    });

    // 4️⃣ صفحة المقالات والفيديوهات 
    svr.Get("/blog", [](const httplib::Request&, httplib::Response& res) {
        auto lessons = get_lessons();
        ostringstream cards;
        for (auto& l : lessons) {
            string tag_class = (l.type == "video") ? "tag-video" : "tag-article";
            string tag_label = (l.type == "video") ? "🎥 درس فيديو" : "📖 مقال فني";
            cards << "<a href='/lesson/" << l.slug << "' class='nav-card'>"
                  << "<span class='lesson-tag " << tag_class << "'>" << tag_label << "</span>"
                  << "<h3>" << html_escape(l.title) << "</h3>"
                  << "<p>" << html_escape(l.summary) << "</p>"
                  << "</a>";
        }
        string meta = get_seo_meta("مكتبة الشروحات الهندسية ودروس الصيانة", "سلسلة المقالات المكتوبة والفيديوهات التطبيقية لتعليم ميكانيكا وتركيبات دوائر أمان المصاعد.");
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + meta + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container'>"
                      "<div class='section-intro'><h1>📚 مكتبة الدروس الفنية والشروحات</h1>"
                      "<p>مقالات هندسية وفيديوهات متخصصة تشرح التصفية الكهربائية والميكانيكية للمصاعد خطوة بخطوة للشغل النظيف والأمان.</p></div>"
                      "<div class='grid-nav'>" + cards.str() + "</div>"
                      "</div>"
                      "<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 4.1️⃣ عرض مقال أو فيديو واحد بالتفصيل
    svr.Get(R"(/lesson/([a-zA-Z0-9\-]+))", [](const httplib::Request& req, httplib::Response& res) {
        string slug = req.matches[1].str();
        auto lessons = get_lessons();
        auto it = find_if(lessons.begin(), lessons.end(), [&](const Lesson& l) { return l.slug == slug; });

        if (it == lessons.end()) {
            res.status = 404;
            string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                          + get_modern_blue_css() + "</head><body>"
                          + get_navbar_html() +
                          "<div class='container' style='display:flex; align-items:center; justify-content:center; min-height:50vh;'>"
                          "<div class='card' style='text-align:center; max-width:450px;'>"
                          "<h2>⚠️ الدرس غير متوفر حالياً</h2>"
                          "<p style='color:#94a3b8; margin-bottom:24px;'>الرابط المطلوب غير متاح أو تم نقله لمسار آخر.</p>"
                          "<a class='btn-secondary' href='/blog'>⬅️ العودة للمكتبة والشروحات</a>"
                          "</div></div>"
                          "</body></html>";
            res.set_content(html, "text/html; charset=utf-8"); return;
        }

        string tag_class = (it->type == "video") ? "tag-video" : "tag-article";
        string tag_label = (it->type == "video") ? "🎥 فيديو تعليمي" : "📖 مقال تقني مخصص";

        ostringstream body;
        if (it->type == "video" && !it->video_embed_url.empty()) {
            body << "<div class='video-embed'><iframe src='" << it->video_embed_url
                 << "' allow='accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture' "
                    "allowfullscreen loading='lazy'></iframe></div>";
        }
        if (!it->content_html.empty()) {
            body << "<div class='lesson-body'><h3>📌 تفاصيل الشرح والمخطط الفني:</h3>" << it->content_html << "</div>";
        }

        string meta = get_seo_meta(it->title, it->summary);
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + meta + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:750px;'>"
                      "<div class='card'>"
                      "<span class='lesson-tag " + tag_class + "'>" + tag_label + "</span>"
                      "<h2>" + html_escape(it->title) + "</h2>"
                      "<div class='sub-title'>" + html_escape(it->summary) + "</div>"
                      + body.str() +
                      "<div class='actions'><a class='btn-secondary' href='/blog'>⬅️ العودة للمكتبة والشروحات</a></div>"
                      "</div></div>"
                      "<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 4.2️⃣ صفحة المسارات (تجميعة الكورسات والمسارات الشاملة)
    svr.Get("/paths", [](const httplib::Request&, httplib::Response& res) {
        auto tracks = get_tracks();
        ostringstream cards;
        for (auto& t : tracks) {
            cards << "<a href='/track/" << t.slug << "' class='nav-card'>"
                  << "<h3>" << t.emoji << " " << html_escape(t.title) << "</h3>"
                  << "<p>" << html_escape(t.description) << "</p>"
                  << "</a>";
        }
        string meta = get_seo_meta("مسارات التعلم والكورسات الهندسية", "تصفح المسارات المرتبة أكاديمياً لتعلم فنيات التركيب الميكانيكي وتأسيس لوحات دوائر الأمان والكنترول للمصاعد.");
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + meta + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container'>"
                      "<div class='section-intro'><h1>🧭 مسارات التعلم الأكاديمية والمهنية</h1>"
                      "<p>كل مسار مخصص لجمع وتدريس الحلقات والدروس بالترتيب الصحيح لضمان الانتقال السلس من مرحلة التأسيس إلى مرحلة الاحتراف.</p></div>"
                      "<div class='grid-nav'>" + cards.str() + "</div>"
                      "</div>"
                      "<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 4.3️⃣ عرض محتويات كورس/مسار تعليمي واحد مرتب بالأرقام
    svr.Get(R"(/track/([a-zA-Z0-9\-]+))", [](const httplib::Request& req, httplib::Response& res) {
        string slug = req.matches[1].str();
        auto tracks = get_tracks();
        auto trackIt = find_if(tracks.begin(), tracks.end(), [&](const Track& t) { return t.slug == slug; });

        if (trackIt == tracks.end()) {
            res.status = 404;
            string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                          + get_modern_blue_css() + "</head><body>"
                          + get_navbar_html() +
                          "<div class='container' style='display:flex; align-items:center; justify-content:center; min-height:50vh;'>"
                          "<div class='card' style='text-align:center; max-width:450px;'>"
                          "<h2>⚠️ المسار التعليمي غير متاح</h2>"
                          "<p style='color:#94a3b8; margin-bottom:24px;'>المسار التدريبي المطلوب قد يكون قيد التحضير.</p>"
                          "<a class='btn-secondary' href='/paths'>⬅️ العودة لجميع المسارات</a>"
                          "</div></div>"
                          "</body></html>";
            res.set_content(html, "text/html; charset=utf-8"); return;
        }

        auto lessons = get_lessons_by_track(slug);
        ostringstream items;
        for (auto& l : lessons) {
            string tag_emoji = (l.type == "video") ? "🎥" : "📖";
            items << "<a href='/lesson/" << l.slug << "' class='track-item'>"
                  << "<span class='track-order'>" << l.order << "</span>"
                  << "<div><div class='track-item-title'>" << tag_emoji << " " << html_escape(l.title) << "</div>"
                  << "<div class='track-item-summary'>" << html_escape(l.summary) << "</div></div>"
                  << "</a>";
        }
        if (lessons.empty()) {
            items << "<p style='color:#8b96ab;'>يتم رفع وتدقيق الدروس الخاصة بهذا الكورس حالياً، تابعنا قريباً.</p>";
        }

        string meta = get_seo_meta(trackIt->title, trackIt->description);
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + meta + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:700px;'>"
                      "<div class='card'>"
                      "<h2>" + trackIt->emoji + " " + html_escape(trackIt->title) + "</h2>"
                      "<div class='sub-title'>" + html_escape(trackIt->description) + "</div>"
                      "<div class='track-list'>" + items.str() + "</div>"
                      "<div class='actions' style='margin-top:25px;'><a class='btn-secondary' href='/paths'>⬅️ العودة لكافة المسارات</a></div>"
                      "</div></div>"
                      "<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 5️⃣ صفحة التواصل الفني والمهني
    svr.Get("/contact", [](const httplib::Request&, httplib::Response& res) {
        string meta = get_seo_meta("اتصل بنا | الدعم الفني", "تواصل مباشرة مع إدارة منصة ضربة شاكوش لطرح الأسئلة الفنية أو الإبلاغ عن مشكلة برمجية.");
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + meta + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:650px;'>"
                      "<div class='card'><h2>📩 تواصل مع الدعم الفني للهندسة</h2>"
                      "<div class='sub-title'>لديك أي استفسار فني خاص بالمقاسات، اقتراح لتطوير الموقع، أو واجهتك مشكلة بالحاسبة؟ تواصل معنا فوراً.</div>"
                      "<a class='btn-action' href='mailto:support@darbat-shakosh.com' style='margin-bottom:14px; display:block;'>📧 راسلنا على البريد الإلكتروني الرسمي للمنصة</a>"
                      "<p style='color:#8b96ab; font-size:0.9rem; text-align:center;'>المراسلات يتم الرد عليها ومراجعتها من المهندس المختص خلال 24 ساعة.</p>"
                      "</div></div>"
                      "<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 6️⃣ مركز المساعدة والأسئلة الشائعة للمصاعد
    svr.Get("/support", [](const httplib::Request&, httplib::Response& res) {
        string meta = get_seo_meta("مركز المساعدة والأسئلة الشائعة الفنية للمصاعد.", "محتاج مساعدة في فهم كيفية حساب أبعاد الـ DBG الصافي وشواكيل التصفية؟");
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + meta + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:650px;'>"
                      "<div class='card'><h2>🛟 مركز الدعم والمساعدة الفنية</h2>"
                      "<div class='sub-title'>محتاج مساعدة في فهم كيفية حساب أبعاد الـ DBG الصافي وشواكيل التصفية؟</div>"
                      "<p style='color:#e2e8f0; line-height:1.8; margin-bottom:24px;'>يمكنك مراجعة المسارات والدروس التعليمية المتاحة بالمكتبة، وفي حال وجود تعارض في المقاسات المعمارية يمكنك فتح تذكرة دعم فني.</p>"
                      "<div class='actions'>"
                      "  <a class='btn-print' href='/blog'>❓ تصفح الشروحات</a>"
                      "  <a class='btn-secondary' href='/contact'>📩 فتح تذكرة دعم</a>"
                      "</div></div></div>"
                      "<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 7️⃣ صفحة دعم المنصة واستمرارية التطوير
    svr.Get("/donate", [](const httplib::Request&, httplib::Response& res) {
        string meta = get_seo_meta("الموقع وحاسبة مقاسات بئر المصاعد مجاني تماماً لخدمة الوطن العربي.", "الموقع وحاسبة مقاسات بئر المصاعد مجاني تماماً لخدمة فنيي ومندوبي ومهندسي الوطن العربي.");
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + meta + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:650px;'>"
                      "<div class='card'><h2>❤️ المساهمة في دعم واستمرارية المنصة</h2>"
                      "<div class='sub-title'>الموقع وحاسبة مقاسات بئر المصاعد مجاني تماماً لخدمة فنيي ومندوبي ومهندسي الوطن العربي، مساهمتك تساعد في تطوير الخوادم وزيادة جودة الشروحات الميكانيكية.</div>"
                      "<a class='btn-action' href='/contact' style='display:block;'>💳 استعراض وسائل وطرق المساهمة المتاحة</a>"
                      "</div></div>"
                      "<div class='footer'>منصة ضربة شاكوش الفنية © 2026 - إنشاء محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    const char* port_env = getenv("PORT");
    int port = port_env ? safe_stoi(port_env, 8080) : 8080;
    cout << "🚀 Professional Hammer-Platform active on port: " << port << endl;
    svr.listen("0.0.0.0", port);
    return 0;
}
