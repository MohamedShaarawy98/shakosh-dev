
/*                              <   وَأَن لَّيْسَ لِلإِنسَانِ إِلاَّ مَا سَعَى * وَأَنَّ سَعْيَهُ سَوْفَ يُرَى * ثُمَّ يُجْزَاهُ الْجَزَاء الأَوْفَى  >


                                       ============================================================
                                       =                  منصة ضربة شاكوش                        =
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

// ============================================================
//  نظام المحتوى التعليمي: مسارات (Tracks) + مقالات/فيديوهات (Lessons)
//  لإضافة محتوى جديد عدّل فقط على الدوال get_tracks() و get_lessons()
//  أدناه — كل الصفحات والروابط بتتولّد منهم تلقائياً.
// ============================================================
struct Lesson {
    string slug;          // يُستخدم في الرابط: /lesson/<slug> (إنجليزي وبدون مسافات)
    string track_slug;    // المسار اللي ينتمي له هذا المحتوى (لازم يطابق slug في get_tracks)
    string type;          // "article" أو "video"
    string title;
    string summary;       // وصف قصير يظهر في كروت العرض
    string content_html;  // نص المقال الكامل (HTML) — يُستخدم فقط لو type == "article"
    string video_embed_url; // رابط embed الخاص باليوتيوب — يُستخدم فقط لو type == "video"
    int order;             // ترتيب الحلقة داخل مسارها (1، 2، 3...)
};

struct Track {
    string slug;        // يُستخدم في الرابط: /track/<slug>
    string emoji;
    string title;
    string description;

    
};

static vector<Track> get_tracks() {
    return {
        { "basics", "🧱", "مسار الأساسات", "المفاهيم الأولى لتصفية أبعاد بئر المصعد ومكوناته الرئيسية." },
        { "doors",  "😪", "مسار أبواب المصاعد", "أنواع الأبواب وأكواد الفتح المختلفة وإزاي تختار النوع المناسب." },

        { "darbat" , "🔨" , "كورس كهرباء المصاعد "  , "الكورس متخصص في تعليم كبل شئ تخص كهرباء المصاعد"},

    }; 

}

static vector<Lesson> get_lessons() {
    return {
        { "intro-shaft-dimensions", "basics", "video",
          "مقدمة: فهم أبعاد بئر المصعد",
          "الفرق بين البئر الحر والـ Pit والـ Overhead وأهميتهم في التصفية.",
          "<p>بئر المصعد بيتكون من 3 قياسات أساسية لازم تكون دقيقة قبل أي تصفية: "
          "العرض والعمق الحُرّين للبئر، عمق حفرة الـ Pit أسفل المحطة الأخيرة، وارتفاع الـ Overhead فوق آخر محطة.</p>"
          "<p>أي خطأ بسيط في أي قياس من الثلاثة بيأثر مباشرة على نوع الباب المتاح ومقاس الكابينة الصافي، "
          "وده اللي بتحسبه الحاسبة أوتوماتيك من غير الحاجة لجدول ورقي.</p>",
          "https://www.youtube.com/embed/ZluG-pfc2HY",1},

        { "door-types-explained", "doors", "video",
          "شرح أنواع أبواب المصاعد Auto / Semi",
          "فيديو يوضح الفرق بين CO و SI وإزاي تختار نوع الباب المناسب لمساحة بئرك.",
          "",
          "https://www.youtube.com/embed/ZluG-pfc2HY", 1},

          {"darbat-shakosh-one" ,"darbat" , "video", 
            "مقدمة كورس رقم 2 كهرباء المصعد",
            "اهمية ترتيب خطوات الكهرباء للامان والشغل النضيف",
          "<p> اولا يتم  التاكد من كهرباء المبني سواء 220 || 380 لعمل الكنترول علي هذا الساس <p>"
          "<p> ثانيا تركيب الكنترول وتوصيل الماكينه وقفل دوائر السيفتي {الشوكة  - الكالون - الاستوح} ثم التاكد من حركة المصعد <p>",
          "https://www.youtube.com/embed/ZluG-pfc2HY", 2},

           {"darbat-shakosh-tow" ,"darbat" , "article", 
            "مقدمة كورس رقم 1 كهرباء المصعد",
            "اهمية ترتيب خطوات الكهرباء للامان والشغل النضيف",
          "<p> اولا يتم  التاكد من كهرباء المبني سواء 220 || 380 لعمل الكنترول علي هذا الساس <p>"
          "<p> ثانيا تركيب الكنترول وتوصيل الماكينه وقفل دوائر السيفتي {الشوكة  - الكالون - الاستوح} ثم التاكد من حركة المصعد <p>",
          "https://www.youtube.com/embed/ZluG-pfc2HY", 1},
          
    };
}

static vector<Lesson> get_lessons_by_track(const string& track_slug) {
    vector<Lesson> all = get_lessons();
    vector<Lesson> filtered;
    for (auto& l : all) if (l.track_slug == track_slug) filtered.push_back(l);
    sort(filtered.begin(), filtered.end(), [](const Lesson& a, const Lesson& b) { return a.order < b.order; });
    return filtered;
}

// ============================================================
//  الستايل الاحترافي — هوية بصرية مستوحاة من المخططات الهندسية
//  (شبكة Blueprint خفيفة + إطارات قياس بزوايا + أرقام Mono)
// ============================================================
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
           "a{outline-offset:3px;}"
           ":focus-visible{outline:2px solid var(--accent); outline-offset:2px; border-radius:4px;}"

           // ===== الهيدر =====
           ".navbar{background-color:var(--surface); border-bottom:1px solid var(--border); padding:14px 28px; display:flex; justify-content:space-between; align-items:center; position:relative; z-index:50; box-shadow:0 4px 6px -1px rgba(0,0,0,0.15);}"
           ".nav-right{display:flex; align-items:center; gap:20px; flex-wrap:wrap;}"
           ".navbar-brand{display:flex; align-items:center; gap:10px; color:#ffffff; font-size:1.25rem; font-weight:800; text-decoration:none; padding-inline-end:22px; border-inline-end:1px solid var(--border);}"
           ".brand-mark{width:32px; height:32px; flex-shrink:0; border-radius:8px; background:linear-gradient(135deg, var(--accent), #0369a1); display:flex; align-items:center; justify-content:center;}"
           ".brand-mark svg{width:17px; height:17px; fill:#06121c;}"
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
           ".dropdown-heading{color:var(--accent); font-size:0.78rem; font-weight:700; letter-spacing:0.02em; margin-bottom:2px;}"
           ".dropdown-panel a, .mobile-panel a{color:#e2e8f0; font-size:0.95rem; font-weight:600; text-decoration:none; transition:color 0.15s;}"
           ".dropdown-panel a:hover{color:var(--accent);}"
           ".desktop-only{display:flex;}"
           ".mobile-only{display:none;}"
           "@media (max-width:860px){.desktop-only{display:none;} .mobile-only{display:flex;} .navbar-brand span:last-child{font-size:1.05rem;}}"

           // ===== الأيقونات والقائمة المنبثقة الجانبية (موبايل) =====
           ".nav-left{display:flex; align-items:center; gap:18px;}"
           ".nav-icon{color:#94a3b8; cursor:pointer; display:flex; align-items:center; justify-content:center; transition:0.2s; text-decoration:none; list-style:none;}"
           ".nav-icon::-webkit-details-marker{display:none;}"
           ".nav-icon:hover{color:var(--accent);}"
           ".nav-icon svg{width:22px; height:22px; fill:currentColor;}"
           ".mobile-menu{position:relative;}"
           ".mobile-panel{position:absolute; inset-inline-end:0; top:calc(100% + 14px); background:var(--surface-2); border:1px solid var(--border); border-radius:12px; padding:18px 20px; display:flex; flex-direction:column; gap:4px; min-width:230px; box-shadow:0 20px 25px -5px rgba(0,0,0,0.45); z-index:60; animation:dropdownIn 0.18s ease;}"
           ".mobile-panel a{padding:9px 6px; border-radius:6px;}"
           ".mobile-panel a:hover{background:rgba(56,189,248,0.1); color:var(--accent);}"
           ".mobile-panel .dropdown-heading{margin-top:10px; padding:0 6px;}"
           ".mobile-divider{height:1px; background:var(--border); margin:8px 2px;}"

           // ===== الحاوي والبطاقات =====
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
           "button, .btn-action{background:linear-gradient(135deg, #0284c7, #0369a1); color:#ffffff; border:none; padding:16px; border-radius:8px; width:100%; font-size:1.1rem; font-weight:700; cursor:pointer; transition:0.3s; text-decoration:none; display:inline-block; text-align:center;}"
           "button:hover, .btn-action:hover{background:linear-gradient(135deg, #0369a1, #075985); transform:translateY(-1px);}"

           // ===== الجداول =====
           ".table-container{position:relative; width:100%; overflow-x:auto; background:var(--bg); border-radius:8px; border:1px solid var(--border); margin-top:20px;}"
           ".tbl{width:100%; border-collapse:collapse; text-align:right;}"
           ".tbl th{background:var(--surface); padding:15px; color:var(--accent); font-weight:600; border-bottom:1px solid var(--border); font-size:1rem; text-align:right; width:45%;}"
           ".tbl td{padding:15px; border-bottom:1px solid var(--border); color:var(--text); font-size:1rem; font-weight:600; text-align:right; font-family:var(--font-mono);}"
           ".actions{display:flex; justify-content:space-between; margin-top:35px; gap:20px;}"
           ".btn-print{background:linear-gradient(135deg, #16a34a, #15803d); color:white; border:none; padding:15px 25px; border-radius:8px; font-weight:700; cursor:pointer; flex:1; transition:0.3s; text-align:center; font-family:var(--font-display);}"
           ".btn-print:hover{background:linear-gradient(135deg, #15803d, #166534);}"
           ".btn-secondary{background:linear-gradient(135deg, #4f46e5, #4338ca); color:white; padding:15px 25px; border-radius:8px; font-weight:700; text-align:center; flex:1; transition:0.3s; display:inline-block; text-decoration:none; font-family:var(--font-display);}"
           ".btn-secondary:hover{background:linear-gradient(135deg, #4338ca, #3730a3);}"
           ".grid-nav{display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:25px; width:100%;}"
           ".nav-card{position:relative; background:var(--surface); border:1px solid var(--border); padding:30px; border-radius:12px; text-decoration:none; color:var(--text); transition:0.3s; display:flex; flex-direction:column; text-align:right;}"
           ".nav-card:hover{border-color:var(--accent); transform:translateY(-3px); box-shadow:0 10px 20px rgba(0,0,0,0.2);}"
           ".nav-card h3{color:var(--accent); font-size:1.3rem; margin:0 0 12px 0;}"
           ".nav-card p{color:var(--text-muted); font-size:0.95rem; line-height:1.6; margin:0;}"

           // ===== محتوى المسارات والمقالات/الفيديوهات =====
           ".section-intro{margin-bottom:30px; text-align:right;}"
           ".section-intro h1{color:#ffffff; font-size:1.7rem; font-weight:800; margin:0 0 8px 0;}"
           ".section-intro p{color:var(--text-muted); font-size:1rem; line-height:1.7; margin:0;}"
           ".lesson-tag{display:inline-flex; align-items:center; gap:5px; font-size:0.78rem; font-weight:700; padding:4px 10px; border-radius:20px; margin-bottom:12px; width:fit-content;}"
           ".tag-article{background:rgba(56,189,248,0.14); color:var(--accent);}"
           ".tag-video{background:rgba(245,165,36,0.16); color:var(--accent-2);}"
           ".video-embed{position:relative; width:100%; aspect-ratio:16/9; border-radius:10px; overflow:hidden; background:#000; margin:20px 0; border:1px solid var(--border);}"
           ".video-embed iframe{position:absolute; inset:0; width:100%; height:100%; border:0;}"
           ".lesson-body{color:#e2e8f0; font-size:1.02rem; line-height:1.9;}"
           ".lesson-body p{margin:0 0 16px 0;}"
           ".lesson-body h3{color:#ffffff; font-size:1.2rem; margin:24px 0 12px 0;}"
           ".track-list{display:flex; flex-direction:column; gap:14px; margin-top:10px;}"
           ".track-item{display:flex; align-items:flex-start; gap:16px; background:var(--bg); border:1px solid var(--border); border-radius:10px; padding:18px 20px; text-decoration:none; transition:0.2s;}"
           ".track-item:hover{border-color:var(--accent); transform:translateX(-3px);}"
           ".track-order{flex-shrink:0; width:34px; height:34px; border-radius:8px; background:var(--surface-2); color:var(--accent); font-family:var(--font-mono); font-weight:700; display:flex; align-items:center; justify-content:center; font-size:0.95rem;}"
           ".track-item-title{color:#f3f4f6; font-weight:700; font-size:1.02rem; margin-bottom:4px;}"
           ".track-item-summary{color:var(--text-muted); font-size:0.88rem; line-height:1.5;}"

           // ===== التذييل =====
           ".footer{margin-top:auto; padding:25px 0; font-size:15px; color:var(--text-muted); text-align:center; border-top:1px solid var(--border); background-color:var(--surface); font-weight:600;}"
           "@media print{.btn-print, .btn-secondary, h2, h3, .navbar, .footer {display:none;} .card{box-shadow:none; padding:0; border:none; background:none; color:#000;} .card::before, .card::after{display:none;} .tbl th{background:#eee; color:#000;} .tbl td{color:#000; font-family:inherit;}}"
           "</style>";
}

// ============================================================
//  بناء الهيدر — روابط مجمّعة داخل قائمة منبثقة واحدة (مزيد ▾)
//  بدلاً من سرد كل الروابط في صف واحد
// ============================================================
static string get_navbar_html() {
    const string logo_url = "https://raw.githubusercontent.com/MohamedShaarawi98/shakosh-dev/main/channels4_profile.jpg"; 
    const string chevron_svg = "<svg class='chevron' viewBox='0 0 24 24'><path d='M7 10l5 5 5-5z'/></svg>";

    return "<nav class='navbar'>"
           "  <div class='nav-right'>"
           "    <a href='/' class='navbar-brand'><span class='brand-mark'><img src='" + logo_url + "' style='width:100%; height:100%; border-radius:6px; object-fit:cover;'></span><span>ضربة شاكوش</span></a>"
           "    <div class='nav-center desktop-only'>"
           "      <a href='/' class='nav-link'>الرئيسية</a>"
           "      <a href='/paths' class='nav-link'>مسارات</a>"
           "      <a href='/paths' class='nav-link'>كورسات</a>"
           "      <a href='#' class='nav-link'>مشاريع</a>"
           "      <a href='#' class='nav-link'>كتب</a>"
           "      <a href='/blog' class='nav-link'>مقالات</a>"
           "      <a href='/support' class='nav-link'>أسئلة</a>"
           "      <details class='nav-dropdown'>"
           "        <summary>المزيد " + chevron_svg + "</summary>"
           "        <div class='dropdown-panel'>"
           "          <div class='dropdown-col'>"
           "            <a href='/calculator'>أدوات (الحاسبة)</a>"
           "            <a href='/contact'>التواصل</a>"
           "            <a href='/support'>الدعم</a>"
           "            <a href='/donate'>التبرع للموقع</a>"
           "          </div>"
           "        </div>"
           "      </details>"
           "    </div>"
           "  </div>"
           "  <div class='nav-left'>"
           "    <a class='nav-icon' title='بحث'><svg viewBox='0 0 24 24'><path d='M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z'/></svg></a>"
           "    <a class='nav-icon' title='الحساب الشخصي'><svg viewBox='0 0 24 24'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z'/></svg></a>"
           "    <details class='nav-dropdown mobile-menu mobile-only'>"
           "      <summary class='nav-icon' title='القائمة'><svg viewBox='0 0 24 24'><path d='M3 6h18v2H3zm0 5h18v2H3zm0 5h18v2H3z'/></svg></summary>"
           "      <div class='mobile-panel'>"
           "        <a href='/'>الرئيسية</a>"
           "        <a href='/paths'>مسارات</a>"
           "        <a href='/paths'>كورسات</a>"
           "        <a href='#'>مشاريع</a>"
           "        <a href='#'>كتب</a>"
           "        <a href='/blog'>مقالات</a>"
           "        <a href='/support'>أسئلة</a>"
           "        <div class='mobile-divider'></div>"
           "        <a href='/calculator'>أدوات (الحاسبة)</a>"
           "        <a href='/contact'>التواصل</a>"
           "        <a href='/support'>الدعم</a>"
           "        <a href='/donate'>التبرع للموقع</a>"
           "      </div>"
           "    </details>"
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
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
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
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
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
            string err = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                         "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                         + get_modern_blue_css() + "</head><body>"
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
        os << "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
           "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
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

    // 4️⃣ صفحة المقالات والفيديوهات (تُبنى تلقائياً من get_lessons())
    svr.Get("/blog", [](const httplib::Request&, httplib::Response& res) {
        auto lessons = get_lessons();
        ostringstream cards;
        for (auto& l : lessons) {
            string tag_class = (l.type == "video") ? "tag-video" : "tag-article";
            string tag_label = (l.type == "video") ? "🎥 فيديو" : "📖 مقال";
            cards << "<a href='/lesson/" << l.slug << "' class='nav-card'>"
                  << "<span class='lesson-tag " << tag_class << "'>" << tag_label << "</span>"
                  << "<h3>" << html_escape(l.title) << "</h3>"
                  << "<p>" << html_escape(l.summary) << "</p>"
                  << "</a>";
        }
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container'>"
                      "<div class='section-intro'><h1>📚 سلسلة تعلّم المصاعد</h1>"
                      "<p>مقالات وفيديوهات تشرح تصفية وتركيب المصاعد خطوة بخطوة.</p></div>"
                      "<div class='grid-nav'>" + cards.str() + "</div>"
                      "</div>"
                      "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 4.1️⃣ عرض مقال أو فيديو واحد بالتفصيل: /lesson/<slug>
    svr.Get(R"(/lesson/([a-zA-Z0-9\-]+))", [](const httplib::Request& req, httplib::Response& res) {
        string slug = req.matches[1].str();
        auto lessons = get_lessons();
        auto it = find_if(lessons.begin(), lessons.end(), [&](const Lesson& l) { return l.slug == slug; });

        if (it == lessons.end()) {
            res.status = 404;
            string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                          "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                          + get_modern_blue_css() + "</head><body>"
                          + get_navbar_html() +
                          "<div class='container' style='display:flex; align-items:center; justify-content:center; min-height:50vh;'>"
                          "<div class='card' style='text-align:center; max-width:450px;'>"
                          "<h2>⚠️ المحتوى غير موجود</h2>"
                          "<p style='color:#94a3b8; margin-bottom:24px;'>الرابط ده غير متاح أو تم حذفه.</p>"
                          "<a class='btn-secondary' href='/blog'>⬅️ كل المقالات والفيديوهات</a>"
                          "</div></div>"
                          "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                          "</body></html>";
            res.set_content(html, "text/html; charset=utf-8");
            return;
        }

        string tag_class = (it->type == "video") ? "tag-video" : "tag-article";
        string tag_label = (it->type == "video") ? "🎥 فيديو" : "📖 مقال";

        ostringstream body;
        if (it->type == "video" && !it->video_embed_url.empty()) {
            body << "<div class='video-embed'><iframe src='" << it->video_embed_url
                 << "' allow='accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture' "
                    "allowfullscreen loading='lazy'></iframe></div>";
        }
        if (!it->content_html.empty()) {
            body << "<div class='lesson-body'>" << it->content_html << "</div>";
        }

        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:750px;'>"
                      "<div class='card'>"
                      "<span class='lesson-tag " + tag_class + "'>" + tag_label + "</span>"
                      "<h2>" + html_escape(it->title) + "</h2>"
                      "<div class='sub-title'>" + html_escape(it->summary) + "</div>"
                      + body.str() +
                      "<div class='actions'><a class='btn-secondary' href='/blog'>⬅️ كل المقالات والفيديوهات</a></div>"
                      "</div></div>"
                      "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 4.2️⃣ صفحة المسارات: تُبنى تلقائياً من get_tracks()
    svr.Get("/paths", [](const httplib::Request&, httplib::Response& res) {
        auto tracks = get_tracks();
        ostringstream cards;
        for (auto& t : tracks) {
            cards << "<a href='/track/" << t.slug << "' class='nav-card'>"
                  << "<h3>" << t.emoji << " " << html_escape(t.title) << "</h3>"
                  << "<p>" << html_escape(t.description) << "</p>"
                  << "</a>";
        }
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container'>"
                      "<div class='section-intro'><h1>🧭 مسارات التعلّم</h1>"
                      "<p>كل مسار يجمع مجموعة مقالات وفيديوهات مرتبة بالترتيب الصحيح من الأساسي للمتقدم.</p></div>"
                      "<div class='grid-nav'>" + cards.str() + "</div>"
                      "</div>"
                      "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 4.3️⃣ عرض مسار واحد بكل محتواه مرتب: /track/<slug>
    svr.Get(R"(/track/([a-zA-Z0-9\-]+))", [](const httplib::Request& req, httplib::Response& res) {
        string slug = req.matches[1].str();
        auto tracks = get_tracks();
        auto trackIt = find_if(tracks.begin(), tracks.end(), [&](const Track& t) { return t.slug == slug; });

        if (trackIt == tracks.end()) {
            res.status = 404;
            string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                          "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                          + get_modern_blue_css() + "</head><body>"
                          + get_navbar_html() +
                          "<div class='container' style='display:flex; align-items:center; justify-content:center; min-height:50vh;'>"
                          "<div class='card' style='text-align:center; max-width:450px;'>"
                          "<h2>⚠️ المسار غير موجود</h2>"
                          "<p style='color:#94a3b8; margin-bottom:24px;'>الرابط ده غير متاح أو تم حذفه.</p>"
                          "<a class='btn-secondary' href='/paths'>⬅️ كل المسارات</a>"
                          "</div></div>"
                          "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                          "</body></html>";
            res.set_content(html, "text/html; charset=utf-8");
            return;
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
            items << "<p style='color:#8b96ab;'>لسه مفيش محتوى مضاف لهذا المسار.</p>";
        }

        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:700px;'>"
                      "<div class='card'>"
                      "<h2>" + trackIt->emoji + " " + html_escape(trackIt->title) + "</h2>"
                      "<div class='sub-title'>" + html_escape(trackIt->description) + "</div>"
                      "<div class='track-list'>" + items.str() + "</div>"
                      "</div></div>"
                      "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 5️⃣ صفحة التواصل
    svr.Get("/contact", [](const httplib::Request&, httplib::Response& res) {
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:650px;'>"
                      "<div class='card'><h2>📩 تواصل معنا</h2>"
                      "<div class='sub-title'>عندك سؤال فني، اقتراح، أو لاحظت مشكلة في الحاسبة؟ تواصل معنا وهنرد عليك في أقرب وقت.</div>"
                      "<a class='btn-action' href='http://facebook.com' style='margin-bottom:14px; display:block;'>📧 راسلنا على البريد الإلكتروني</a>"
                      "<p style='color:#8b96ab; font-size:0.9rem; text-align:center;'>* استبدل هذا البريد ببريدك الفعلي قبل النشر.</p>"
                      "</div></div>"
                      "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 6️⃣ صفحة الدعم والمساعدة
    svr.Get("/support", [](const httplib::Request&, httplib::Response& res) {
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:650px;'>"
                      "<div class='card'><h2>🛟 الدعم والمساعدة</h2>"
                      "<div class='sub-title'>محتاج مساعدة في استخدام حاسبة المقاسات أو فهم نتيجة التقرير؟</div>"
                      "<p style='color:#e2e8f0; line-height:1.8; margin-bottom:24px;'>راجع قسم الأسئلة الشائعة أولاً، ولو المشكلة لسه قائمة تواصل معنا مباشرة وهنرجع لك بالتفاصيل.</p>"
                      "<div class='actions'>"
                      "<a class='btn-print' href='http://facebook.com'>❓ الأسئلة الشائعة</a>"
                      "<a class='btn-secondary' href='http://facebook.com'>📩 تواصل معنا</a>"
                      "</div></div></div>"
                      "<div class='footer'>إنشاء : محمد الشعراوي</div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 7️⃣ صفحة التبرع للموقع
    svr.Get("/donate", [](const httplib::Request&, httplib::Response& res) {
        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap' rel='stylesheet'>"
                      + get_modern_blue_css() + "</head><body>"
                      + get_navbar_html() +
                      "<div class='container' style='max-width:650px;'>"
                      "<div class='card'><h2>❤️ ادعم استمرار الموقع</h2>"
                      "<div class='sub-title'>الموقع مجاني بالكامل لكل المهندسين والفنيين، ودعمك بيساعدنا نطوّر الحاسبة ونزيد المحتوى التعليمي.</div>"
                      "<a class='btn-action' href='/contact' style='display:block;'>💳 طرق دعم الموقع</a>"
                      "<p style='color:#8b96ab; font-size:0.9rem; text-align:center; margin-top:14px;'>* أضف هنا رابط وسيلة الدفع الفعلية (فودافون كاش، إنستاباي، إلخ) بدلاً من رابط التواصل.</p>"
                      "</div></div>"
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
