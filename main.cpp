#include "httplib.h"
#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <algorithm>
#include <map>
#include <chrono>
#include <mutex>

using namespace std;

// هيكل بيانات لتتبع طلبات كل مستخدم (IP)
struct RateLimitInfo {
    int count = 0;
    chrono::steady_clock::time_point reset_time;
};

static map<string, RateLimitInfo> ip_tracker;
static mutex rate_limit_mtx;
const int MAX_REQUESTS_PER_MINUTE = 15;

// ============================================================
//  دوال الحماية والتحويل الآمنة
// ============================================================
static int safe_stoi(const string& s, int default_val = 0) {
    try { if (s.empty()) return default_val; return stoi(s); } catch (...) { return default_val; }
}
static float safe_stof(const string& s, float default_val = 0.0f) {
    try { if (s.empty()) return default_val; return stof(s); } catch (...) { return default_val; }
}
static int clamp_int(int v, int lo, int hi) { return max(lo, min(hi, v)); }
static float clamp_float(float v, float lo, float hi) { return max(lo, min(hi, v)); }

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

static void set_security_headers(httplib::Response& res) {
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-XSS-Protection", "1; mode=block");
    res.set_header("Content-Security-Policy", "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com;");
    res.set_header("Server", "Hammer-Engine/1.0"); 
}

// دالة جلب الـ IP الصحيحة للشبكة خلف البروكسي أو كلوفلير
static string get_client_ip(const httplib::Request& req) {
    if (req.has_header("CF-Connecting-IP")) return req.get_header_value("CF-Connecting-IP");
    if (req.has_header("X-Forwarded-For")) {
        string xff = req.get_header_value("X-Forwarded-For");
        size_t comma = xff.find(',');
        if (comma != string::npos) return xff.substr(0, comma);
        return xff;
    }
    return req.remote_addr;
}

static bool is_rate_limited(const string& ip) {
    lock_guard<mutex> lock(rate_limit_mtx);
    auto now = chrono::steady_clock::now();
    
    if (ip_tracker.size() > 500) {
        for (auto it = ip_tracker.begin(); it != ip_tracker.end(); ) {
            if (now >= it->second.reset_time) it = ip_tracker.erase(it); else ++it;
        }
    }

    if (ip_tracker.find(ip) == ip_tracker.end() || now >= ip_tracker[ip].reset_time) {
        ip_tracker[ip].count = 1;
        ip_tracker[ip].reset_time = now + chrono::minutes(1);
        return false;
    }
    
    ip_tracker[ip].count++;
    return ip_tracker[ip].count > MAX_REQUESTS_PER_MINUTE;
}

static void send_rate_limit_error(httplib::Response& res) {
    ostringstream os;
    os << "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
       << "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
       << "<style>"
       << "body{background-color:#121212; font-family:'Cairo', sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; direction:rtl;}"
       << ".limit-card{background:#1e1e1e; border:2px solid #ecc94b; padding:40px; border-radius:15px; text-align:center; max-width:500px; width:90%; box-shadow:0 10px 25px rgba(236,201,75,0.15);}"
       << ".limit-card h2{color:#ecc94b; font-size:22px; margin-top:0;}"
       << ".limit-card p{color:#ccc; font-size:15px; line-height:1.6; margin-bottom:25px;}"
       << "</style></head><body>"
       << "<div class='limit-card'>"
       << "<h2>⚠️ تم تجاوز حد الطلبات المسموح به</h2>"
       << "<p>لقد قمت بإرسال عدد كبير من الطلبات في وقت قصير لحماية خوادم المنصة يرجى الانتظار دقيقة واحدة ثم إعادة المحاولة بشكل طبيعي.</p>"
       << "</div></body></html>";
    res.status = 429; 
    res.set_content(os.str(), "text/html; charset=utf-8");
}

// دالة محرك الرد الذكي الفنية للموقع
static string get_ai_response(const string& query) {
    string msg = query;
    transform(msg.begin(), msg.end(), msg.begin(), ::tolower);
    
    if (msg.find("عطل") != string::npos || msg.find("كود") != string::npos || msg.find("خطأ") != string::npos) {
        return "🤖 المستشار الهندسي: أهلاً بك يا هندسة. عند فحص أعطال كروت التحكم الإلكترونية، يرجى فحص سلامة تغذية الفازات الثلاثة والـ Inverter أولاً. إذا كان العطل يرتبط بدوائر الأمان، تأكد من شوكة الأبواب ونقاط الكوالين (Riddle Switches).";
    }
    if (msg.find("مقاس") != string::npos || msg.find("حفرة") != string::npos || msg.find("مساحة") != string::npos) {
        return "🤖 المستشار الهندسي: المقاسات البنائية الحرجة للبئر تتطلب دقة هندسية عالية. تذكر دائماً أن عمق الحفرة (Pit) القياسي بالمنصة تم ضبطه على 100 سم والـ Overhead على 400 سم. في حال وجود بئر ضيق، يُفضل استخدام التوزيع الجانبي لسكك الثقل واستغلال عمق البئر للأبواب التلسكوبية.";
    }
    return "🤖 المستشار الهندسي: مرحباً بك يا هندسة في بوابة المساعد الذكي لموقع ضربة شاكوش! أنا مستشارك الفني المتخصص في تقديم الاستشارات الهندسية والميكانيكية للمصاعد وكروت التحكم. كيف يمكنني مساعدتك في موقعك اليوم؟";
}

// ============================================================
//  كلاس المصعد (المطور لسكك منفصلة وسعر 0)
// ============================================================
class Elevator {
private:
    const float P_BRACKET    = 0.0f; 
    const float P_BOLT       = 0.0f; 
    const float P_ROPE       = 0.0f; 
    const float P_FISH       = 0.0f; 
    const float P_CABIN_RAIL = 0.0f; 
    const float P_CWT_RAIL   = 0.0f; 

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
    
    float calc_cabin_rails(float h) { return (h * 2.0f) / 5.0f; }
    float calc_cwt_rails(float h)   { return (h * 2.0f) / 5.0f; }

    float get_p_bracket()    { return P_BRACKET; }
    float get_p_bolt()       { return P_BOLT; } 
    float get_p_rope()       { return P_ROPE; }
    float get_p_fish()       { return P_FISH; }
    float get_p_cabin_rail() { return P_CABIN_RAIL; }
    float get_p_cwt_rail()   { return P_CWT_RAIL; }
};

int main() {
    httplib::Server svr;
    Elevator elevator;

    // 1️⃣ واجهة البوابة الرئيسية بالتصميم القديم المخصص
    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);
        string client_ip = get_client_ip(req);
        if (is_rate_limited(client_ip)) { send_rate_limit_error(res); return; }

        stringstream html;
        html << "<!DOCTYPE html><html lang='ar' dir='rtl'><head><meta charset='UTF-8'>"
             << "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
             << "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
             << "<style>"
             << "body{background-color:#121212; font-family:'Cairo', sans-serif; color:#fff; direction:rtl; padding:20px; display:flex; flex-direction:column; align-items:center; min-height:100vh; margin:0;}"
             << "header{text-align:center; margin:30px 0 20px 0;}"
             << "header h1{color:#ffcc00; font-size:2.5rem; margin-bottom:5px;}"
             << "header p{color:#aaa; font-size:1rem; margin-top:5px;}"
             << ".alert-box{background: rgba(229, 62, 62, 0.1); border: 2px dashed #e53e3e; padding: 20px; border-radius: 12px; max-width: 900px; text-align: center; margin-bottom: 25px; box-shadow: 0 4px 15px rgba(229,62,62,0.15); width:100%; box-sizing:border-box;}"
             << ".alert-box h4{color:#fc8181; margin:0 0 8px 0; font-size:1.1rem; font-weight:700; display:flex; align-items:center; justify-content:center; gap:8px;}"
             << ".alert-box p{color:#fecdd3; margin:0; font-size:0.95rem; line-height:1.6; font-weight:600;}"
             << ".grid-nav{display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:25px; width:100%; max-width:900px; margin-top:10px; margin-bottom:25px;}"
             << ".nav-card{background:#1e1e1e; border:1px solid #333; padding:30px; border-radius:15px; text-align:center; text-decoration:none; color:#fff; transition:0.3s; display:flex; flex-direction:column; align-items:center; justify-content:center; box-sizing:border-box;}"
             << ".nav-card:hover{border-color:#ffcc00; transform:translateY(-5px); box-shadow:0 10px 20px rgba(255,204,0,0.15);}"
             << ".nav-card h3{color:#ffcc00; font-size:1.4rem; margin-bottom:12px;}"
             << ".nav-card p{color:#aaa; font-size:0.9rem; line-height:1.5; margin:0;}"
             << ".disabled{opacity:0.5; cursor:not-allowed;}"
             << ".disabled:hover{transform:none; border-color:#333; box-shadow:none;}"
             << ".ai-service-card{background:#1e1e1e; border:2px solid #ffcc00; padding:30px; border-radius:15px; max-width:900px; width:100%; box-sizing:border-box; margin-top:10px; box-shadow:0 4px 15px rgba(255,204,0,0.05);}"
             << ".ai-service-card h2{color:#ffcc00; font-size:1.4rem; margin-top:0; margin-bottom:15px; text-align:center;}"
             << ".chat-area{height:220px; overflow-y:auto; background:#151515; border:1px solid #333; padding:15px; border-radius:10px; margin-bottom:15px; display:flex; flex-direction:column; gap:12px; box-sizing:border-box; text-align:right;}"
             << ".msg{padding:10px 14px; border-radius:10px; font-size:13.5px; line-height:1.5; max-width:85%; word-wrap:break-word; font-weight:600;}"
             << ".msg.user{background:#ffcc00; color:#121212; align-self:flex-start;}"
             << ".msg.ai{background:#2a2a2a; color:#fff; align-self:flex-end; border-right:3px solid #ffcc00;}"
             << ".ai-input-group{display:flex; gap:10px;}"
             << ".ai-input-group input{flex:1; padding:12px; border:1px solid #333; background:#151515; color:#fff; border-radius:8px; font-family:'Cairo', sans-serif; font-weight:600; text-align:center;}"
             << ".ai-input-group button{width:auto; padding:0 25px; background:#ffcc00; color:#121212; border:none; border-radius:8px; font-weight:700; font-family:'Cairo', sans-serif; cursor:pointer; font-size:14px; transition:0.2s;}"
             << ".ai-input-group button:hover{background:#ccaa00;}"
             << ".footer{margin-top:auto; padding:40px 0 20px 0; font-size:13px; color:#555; text-align:center; font-weight:600;}"
             << "</style></head><body>"
             << "<header><h1>ضربة شاكوش 🛠️</h1><p>المنصة الهندسية لتقنيات المصاعد والتحكم البرمجي</p></header>"
             << "<div class='alert-box'><h4>⚠️ تنبيه هام جداً للمستخدمين</h4>"
             << "<p>المنصة حالياً تحت التجربة والتطوير المستمر. يمكنك استخدام الحاسبة ومراجعة النتائج، ولكن يرجى عدم الاعتماد التام والنهائي على المقاسات الناتجة في المواقع الحقيقية دون مراجعتها يدوياً من قِبلك فنيّاً وهندسيّاً.</p></div>"
             << "<div class='grid-nav'>"
             << "<a href='/calculator' class='nav-card'><h3>🛗  حاسبة مقاسات البضاعة</h3><p>تصفية أبعاد بئر المصعد وحساب الكابينة والمواد هندسياً بأعلى دقة.</p></a>"
             << "<a href='/blog' class='nav-card'><h3>📚 مقالات وشروحات عملي</h3><p> مخططات طرق صيانة الكروت الإلكترونية، وبرمجة الروبوتات ب C.</p></a>"
             << "<div class='nav-card disabled'><h3>🦾  تحكم الروبوتات </h3><p>(قريباً) واجهة حساب معاملات الحركة ومحاور الـ CNC بالـ C++.</p></div>"
             << "</div>"
             
             << "<div class='ai-service-card'><h2>🤖 خدمة الفني - المستشار الهندسي الذكي (AI)</h2>"
             << "<div class='chat-area' id='chatBox'>"
             << "<div class='msg ai'>مرحباً بك يا هندسة في الخدمة الفنية الذكية لموقع ضربة شاكوش! اسألني عن أي كود خطأ في الكروت، أو استشارة سريعة بخصوص أبعاد ومقاسات بئر المصاعد في الموقع الآن.</div>"
             << "</div>"
             << "<div class='ai-input-group'>"
             << "<input type='text' id='userInput' placeholder='اكتب استفسارك الفني هنا... (مثال: عطل في كرت الصيانة)'>"
             << "<button onclick='sendAiMessage()'>إرسال الاستشارة</button></div></div>"
             
             << "<div class='footer'>انشاء وتطوير: محمد الشعراوي</div>"
             
             << "<script>"
             << "function sendAiMessage(){"
             << "  var input=document.getElementById('userInput'); var msgText=input.value.trim();"
             << "  if(!msgText) return;"
             << "  var box=document.getElementById('chatBox');"
             << "  box.innerHTML += '<div class=\"msg user\">'+msgText+'</div>';"
             << "  input.value=''; box.scrollTop=box.scrollHeight;"
             << "  var xhr=new XMLHttpRequest(); xhr.open('POST', '/ai-chat', true);"
             << "  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');"
             << "  xhr.onreadystatechange=function(){"
             << "    if(xhr.readyState==4 && xhr.status==200){"
             << "      box.innerHTML += '<div class=\"msg ai\">'+xhr.responseText+'</div>';"
             << "      box.scrollTop=box.scrollHeight;"
             << "    }else if(xhr.readyState==4 && xhr.status==429){"
             << "      box.innerHTML += '<div class=\"msg ai\" style=\"border-right-color:#e53e3e;\">'+xhr.responseText+'</div>';"
             << "      box.scrollTop=box.scrollHeight;"
             << "    }"
             << "  };"
             << "  xhr.send('message='+encodeURIComponent(msgText));"
             << "}"
             << "</script></body></html>";

        res.set_content(html.str(), "text/html; charset=utf-8");
    });

    // 2️⃣ واجهة إدخال بيانات الحاسبة
    svr.Get("/calculator", [](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);
        string client_ip = get_client_ip(req);
        if (is_rate_limited(client_ip)) { send_rate_limit_error(res); return; }

        string html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                      "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
                      "<style>"
                      "body{background-color:#f4f7fc; font-family:'Cairo', sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:20px; box-sizing:border-box; flex-direction:column; color:#2d3748;}"
                      ".card{background: #ffffff; padding:40px; border-radius:20px; box-shadow: 0 10px 30px rgba(160, 174, 192, 0.2); width:95%; max-width:550px; direction:rtl; text-align:right; box-sizing:border-box; border: 1px solid rgba(226, 232, 240, 0.8);}"
                      "h2{color:#1a365d; text-align:center; margin-top:0; margin-bottom:10px; font-weight:700; font-size:24px;}"
                      ".sub-title{text-align:center; color:#718096; margin-bottom:30px; font-size:14px; font-weight:400;}"
                      ".f-group{margin-bottom:20px;}"
                      "label{font-weight:600; color:#4a5568; display:block; margin-bottom:8px; font-size:14px;}"
                      "input,select{width:100%; padding:14px; border:1px solid #cbd5e0; border-radius:12px; box-sizing:border-box; text-align:center; font-size:16px; font-family:'Cairo', sans-serif; background-color:#f8fafc; color:#2d3748; transition: all 0.3s ease; font-weight:600;}"
                      "input:focus, select:focus{outline:none; border-color:#3182ce; background-color:#fff; box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.15);}"
                      "button{background: linear-gradient(135deg, #2b6cb0, #1a365d); color:white; border:none; padding:16px; border-radius:12px; width:100%; font-size:16px; font-weight:700; font-family:'Cairo', sans-serif; cursor:pointer; margin-top:15px; box-shadow:0 4px 12px rgba(26, 54, 93, 0.2); transition: all 0.3s ease;}"
                      "button:hover{background: linear-gradient(135deg, #1a365d, #2b6cb0); transform: translateY(-1px); box-shadow:0 6px 20px rgba(26, 54, 93, 0.3);}"
                      ".btn-home{display:block; text-align:center; margin-top:20px; color:#3182ce; text-decoration:none; font-weight:700; font-size:14px;}"
                      "</style></head><body>"
                      "<div class='card'><h2>🛗 حاسبة المقاسات والبضاعة الذكية</h2>"
                      "<div class='sub-title'>النظام الهندسي المطور لتصفية وحساب بضاعة المصاعد فوراً</div>"
                      "<form action='/calculate' method='post'>"
                      "<div class='f-group'><label>📦 نوع نظام الهندسة:</label><select name='m_type'><option value='MR'>غرفة محرك أعلى البئر (MR)</option><option value='MRL'>بدون غرفة محرك (MRL)</option></select></div>"
                      "<div class='f-group'><label>📏 عرض البئر الحُر (CM):</label><input type='number' name='width' required min='80' max='250' placeholder='أدخل عرض البئر بالسم'></div>"
                      "<div class='f-group'><label>📐 عمق البئر الحُر (CM):</label><input type='number' name='depth' required min='80' max='250' placeholder='أدخل عمق البئر بالسم'></div>"
                      "<div class='f-group'><label>🏢 عدد أدوار المبنى (الوقفات):</label><input type='number' name='floors' required min='1' max='60' placeholder='أدخل إجمالي الأدوار'></div>"
                      "<div class='f-group'><label>🕳️ عمق الحفرة Pit (CM):</label><input type='number' name='depth_pit' required min='10' max='500' value='100'></div>"
                      "<div class='f-group'><label>🏠 الارتفاع العلوي Overhead (CM):</label><input type='number' name='overhead' required min='100' max='800' value='400'></div>"
                      "<button type='submit'>🚀 تحليل الأبعاد وتصفية المقايسة</button></form>"
                      "<a href='/' class='btn-home'>⬅️ العودة للبوابة الرئيسية</a></div>"
                      "</body></html>";
        res.set_content(html, "text/html; charset=utf-8");
    });

    // 3️⃣ مسار استشارات الذكاء الاصطناعي (تمت صيانته وحقنه بالدوال بنجاح)
    svr.Post("/ai-chat", [](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);
        string client_ip = get_client_ip(req);
        if (is_rate_limited(client_ip)) {
            res.status = 429;
            res.set_content("🚨 عذراً يا هندسة، لقد تجاوزت حد الأسئلة في الدقيقة. انتظر دقيقة واحدة لحماية خوادم المنصة.", "text/plain; charset=utf-8");
            return;
        }
        string user_msg = req.get_param_value("message");
        string ai_reply = get_ai_response(user_msg);
        res.set_content(ai_reply, "text/plain; charset=utf-8");
    });

    // 4️⃣ تقارير المقايسة
    svr.Post("/calculate", [&elevator](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);
        string client_ip = get_client_ip(req);
        if (is_rate_limited(client_ip)) { send_rate_limit_error(res); return; }
        
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
                     << "<style>"
                     << "body{background-color:#121212; font-family:'Cairo', sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; direction:rtl;}"
                     << ".error-card{background:#1e1e1e; border:2px solid #dd6b20; padding:40px; border-radius:15px; text-align:center; max-width:500px; width:90%; box-shadow:0 10px 25px rgba(221,107,32,0.2);}"
                     << ".error-card h2{color:#dd6b20; font-size:22px; margin-top:0;}"
                     << ".error-card p{color:#ccc; font-size:15px; line-height:1.6; margin-bottom:25px;}"
                     << ".btn-retry{display:inline-block; background:#dd6b20; color:white; padding:12px 30px; text-decoration:none; border-radius:10px; font-weight:700; transition:0.3s;}"
                     << ".btn-retry:hover{background:#c05621; transform:translateY(-2px);}"
                     << "</style></head><body>"
                     << "<div class='error-card'>"
                     << "<h2>⚠️ عذراً، أبعاد البئر غير مطابقة للمواصفات</h2>"
                     << "<p>أبعاد بئر المصعد المدخلة أقل من الحد الأدنى الفني المسموح به للحساب الآلي بالمنصة.<br><b>الحد الأدنى المطلوب:</b> عرض لا يقل عن 110 سم، وعمق لا يقل عن 100 سم.</p>"
                     << "<a href='/' class='btn-retry'>🔄 العودة وتعديل المقاسات</a>"
                     << "</div></body></html>";
            res.set_content(error_os.str(), "text/html; charset=utf-8"); return;
        }

        string pit_display_text, overhead_display_text;
        if (original_pit < 60 || original_pit > 200) {
            pit_display_text = "<span style='color: #e53e3e; background: #fff5f5; padding: 4px 8px; border-radius: 6px; border: 1px solid #fed7d7; font-size: 13px;'>⚠️ مقاس غير قياسي (" + to_string(original_pit) + " CM) - يرجى المراجعة</span>";
        } else { pit_display_text = to_string(original_pit) + " CM"; }

        if (original_overhead < 350 || original_overhead > 600) {
            overhead_display_text = "<span style='color: #e53e3e; background: #fff5f5; padding: 4px 8px; border-radius: 6px; border: 1px solid #fed7d7; font-size: 13px;'>⚠️ مقاس غير قياسي (" + to_string(original_overhead) + " CM) - يرجى المراجعة</span>";
        } else { overhead_display_text = to_string(original_overhead) + " CM"; }

        w = clamp_int(w, 80, 250); d = clamp_int(d, 80, 250); f = clamp_float(f, 1.0f, 60.0f);
        float pit_clamped = clamp_float((float)original_pit, 10.0f, 500.0f);
        float overhead_clamped = clamp_float((float)original_overhead, 100.0f, 800.0f);

        float pit_m = pit_clamped / 100.0f; float overhead_m = overhead_clamped / 100.0f;
        string door = elevator.get_door_type(w); int cabin_dbg = elevator.get_cabin_dbg(w); int cwt_dbg = elevator.get_cwt_dbg(w);
        int cab_w = elevator.get_cabin_width(w); int cab_d = elevator.get_cabin_depth(d);
        float h = elevator.get_shaft_height(f, pit_m, overhead_m, m_type);

        int brackets = elevator.calc_brackets(h); int bolts = elevator.calc_bolts(brackets); float ropes = elevator.calc_ropes(h);
        int fishplates = ((int)f) * 4; 
        
        float cabin_rails = elevator.calc_cabin_rails(h);
        float cwt_rails   = elevator.calc_cwt_rails(h);

        float c_brackets = brackets * elevator.get_p_bracket(); float c_bolts = bolts * elevator.get_p_bolt(); 
        float c_ropes = ropes * elevator.get_p_rope(); float c_fishplates = fishplates * elevator.get_p_fish(); 
        float c_cabin_rail = cabin_rails * elevator.get_p_cabin_rail();
        float c_cwt_rail   = cwt_rails * elevator.get_p_cwt_rail();
        
        float total = c_brackets + c_bolts + c_ropes + c_fishplates + c_cabin_rail + c_cwt_rail;

        string cwt_display_text;
        if (cwt_dbg == 0) {
            cwt_display_text = "<span style='color: #e53e3e; background: #fff5f5; padding: 4px 8px; border-radius: 6px; border: 1px solid #fed7d7; font-size: 13px;'>⚠️ مقاس غير قياسي - يرجى المراجعة يدوياً</span>";
        } else { cwt_display_text = to_string(cwt_dbg) + " CM"; }

        ostringstream os;
        os << "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
           << "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
           << "<style>"
           << "body{background-color:#1a5d3e; font-family:'Cairo', sans-serif; padding:30px 10px; direction:rtl; text-align:right; color:#2d3748;}"
           << ".box{max-width:650px; margin:auto; background:#ffffff; padding:35px; border-radius:20px; box-shadow:0 10px 30px rgba(160,174,192,0.15); border: 1px solid #e2e8f0;}"
           << "h2{color:#1a365d; text-align:center; margin-top:0; font-weight:700; font-size:22px; border-bottom:2px solid #e2e8f0; padding-bottom:15px;}"
           << "h3{color:#2b6cb0; font-size:15px; font-weight:700; margin-top:25px; margin-bottom:12px; display:flex; align-items:center;}"
           << ".table-container{width:100%; overflow-x:auto; background:#fff; border-radius:12px; border:1px solid #edf2f7; margin-top:8px;}"
           << ".tbl{width:100%; border-collapse:collapse; text-align:right;}"
           << ".tbl th{background:#f7fafc; padding:12px 15px; color:#4a5568; font-weight:600; border-bottom:1px solid #edf2f7; font-size:14px; width:45%;}"
           << ".tbl td{padding:12px 15px; border-bottom:1px solid #edf2f7; color:#1a202c; font-size:14px; font-weight:600;}"
           << ".btbl{width:100%; border-collapse:collapse; text-align:center;}"
           << ".btbl th{background:#2d3748; color:white; padding:12px; font-weight:600; font-size:13px;}"
           << ".btbl td{padding:12px; border-bottom:1px solid #edf2f7; color:#2d3748; font-size:14px; font-weight:600;}"
           << ".btbl tr:nth-child(even){background-color: #f8fafc;}"
           << ".inv{background:linear-gradient(135deg, #f0fff4, #c6f6d5); padding:18px; border-radius:12px; border:1px dashed #38a169; margin-top:25px; text-align:center; font-size:18px; font-weight:700; color:#22543d; box-shadow: 0 4px 6px rgba(56,161,105,0.05);}"
           << ".actions{display:flex; justify-content:space-between; margin-top:30px; gap:15px;}"
           << ".btn-print{background:#2f855a; color:white; padding:12px 25px; border:none; border-radius:10px; font-weight:700; font-family:'Cairo', sans-serif; cursor:pointer; font-size:14px; flex:1; box-shadow:0 4px 10px rgba(47,133,90,0.2); transition:all 0.3s;}"
           << ".btn-print:hover{background:#22543d; transform:translateY(-1px);}"
           << ".btn-back{background:#3182ce; color:white; padding:12px 25px; text-decoration:none; border-radius:10px; font-weight:700; font-size:14px; text-align:center; flex:1; box-shadow:0 4px 10px rgba(49,130,206,0.2); transition:all 0.3s;}"
           << ".btn-back:hover{background:#2b6cb0; transform:translateY(-1px);}"
           << "@media print{.btn-print, .btn-back, h2, h3 {display:none;} .box{box-shadow:none; padding:0; border:none;}}"
           << "</style></head><body><div class='box'><h2>📋 تقرير تصفية الأبعاد الفنية والمقايسة</h2>"
           << "<h3>📐 أولاً: البيانات الهندسية الناتجة</h3>"
           << "<div class='table-container'><table class='tbl'>"
           << "<tr><th>نوع الباب الافتراضي للموقع:</th><td style='color:#3182ce;'>" << door << "</td></tr>"
           << "<tr><th>مقاس DBG الكابينة:</th><td>" << cabin_dbg << " CM</td></tr>"
           << "<tr><th>مقاس DBG الثقل (CWT):</th><td>" << cwt_display_text << "</td></tr>"
           << "<tr><th>صافي عرض الكابينة الداخلي:</th><td>" << cab_w << " CM</td></tr>"
           << "<tr><th>صافي عمق الكابينة الداخلي:</th><td>" << cab_d << " CM</td></tr>"
           << "<tr><th>مقاس عمق الحفرة المدخل:</th><td>" << pit_display_text << "</td></tr>"
           << "<tr><th>مقاس الارتفاع العلوي المدخل:</th><td>" << overhead_display_text << "</td></tr>"
           << "<tr><th>إجمالي مشوار البئر المحسوب:</th><td style='color:#dd6b20;'>" << h << " متر</td></tr>"
           << "</table></div>"
           << "<h3>📦 ثانياً: كمية البضاعة المحسوبة للمشوار</h3>"
           << "<div class='table-container'><table class='btbl'><thead><tr><th>اسم الصنف ومواصفاته الفنية</th><th>الكمية المطلوبة</th><th>التكلفة التقديرية</th></tr></thead><tbody>"
           << "<tr><td>كوابيل السكك الحديدية</td><td>" << brackets << " قطعة 🛑</td><td>" << c_brackets << " SAR</td></tr>"
           << "<tr><td>مسامير وجوايط التثبيت للآبار</td><td>" << bolts << " مسمار 🔩</td><td>" << c_bolts << " SAR</td></tr>"
           << "<tr><td>حبال واير الفولاذ القياسية</td><td>" << ropes << " متر 🧵</td><td>" << c_ropes << " SAR</td></tr>"
           << "<tr><td>لقم ربط السكك (التقفيل)</td><td>" << fishplates << " لقمة 🗜️</td><td>" << c_fishplates << " SAR</td></tr>"
           << "<tr><td>قضبان سكك الكابينة (المقاس الرئيسي)</td><td>" << cabin_rails << " قضيب (5م) 🛤️</td><td>" << c_cabin_rail << " SAR</td></tr>"
           << "<tr><td>قضبان سكك الثقل CWT (المقاس الفرعي)</td><td>" << cwt_rails << " قضيب (5م) 🛤️</td><td>" << c_cwt_rail << " SAR</td></tr>"
           << "</tbody></table></div>"
           << "<div class='inv'>💰 إجمالي القيمة المالية التقديرية: " << total << " SAR</div>"
           << "<div class='actions'>"
           << "<button class='btn-print' onclick='window.print()'>🖨️ طباعة التقرير الفني / حفظ PDF</button>"
           << "<a class='btn-back' href='/'>🔄 حساب مقايسة جديدة</a>"
           << "</div></div></body></html>";
        res.set_content(os.str(), "text/html; charset=utf-8");
    });

    // 5️⃣ مسار المقالات والمدونة
    svr.Get("/blog", [](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);
        string blog_html = "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                           "<link href='https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap' rel='stylesheet'>"
                           "<style>"
                           "body{background-color:#121212; font-family:'Cairo', sans-serif; color:#fff; direction:rtl; padding:40px 20px;}"
                           ".container{max-width:800px; margin:auto;}"
                           "h1{color:#ffcc00; border-bottom:2px solid #ffcc00; padding-bottom:10px;}"
                           ".card{background:#1e1e1e; padding:20px; border-radius:10px; margin-top:20px; border:1px solid #333;}"
                           "h2{color:#ffcc00; font-size:20px;}"
                           "p{color:#aaa; line-height:1.6;}"
                           ".btn-back{display:inline-block; margin-top:20px; background:#3182ce; color:white; padding:10px 20px; text-decoration:none; border-radius:50px; font-weight:700;}"
                           "</style></head><body><div class='container'>"
                           "<h1>📚 بوابة ضربة شاكوش للمقالات والشروحات الهندسية</h1>"
                           "<div class='card'><h2>قريباً: شرح مخططات DWG والتثبيت الميكانيكي للمصاعد</h2><p>هنا سيتم رفع الشروحات الفنية المفصلة لطرق تركيب وتوزيع السكك، والمقاسات القياسية لكوابين المصاعد بمختلف أنواعها...</p></div>"
                           "<div class='card'><h2>قريباً: التحكم البرمجي بالـ C++ وكروت صيانة الروبوتات</h2><p>شرح عملي عميق لكيفية بناء الدوال الحسابية وتحويل الأوامر المدخلة إلى إشارات ميكانيكية دقيقة للـ CNC ومحركات التوجيه الذكية...</p></div>"
                           "<a class='btn-back' href='/'>🧮 العودة للبوابة الرئيسية</a>"
                           "</div></body></html>";
        res.set_content(blog_html, "text/html; charset=utf-8");
    });

    const char* port_env = getenv("PORT");
    int port = port_env ? safe_stoi(port_env, 8080) : 8080;
    std::cout << "🚀 سيرفر ضربة شاكوش القديم يعمل محلياً الآن على: http://localhost:" << port << std::endl;
    svr.listen("0.0.0.0", port);
    return 0;
}
