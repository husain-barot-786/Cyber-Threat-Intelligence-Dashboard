import os
import re
import json
import csv
from datetime import datetime
from io import StringIO, BytesIO
from flask import Flask, render_template, request, redirect, url_for, send_file
from pymongo import MongoClient
import requests
import plotly
import plotly.graph_objs as go

# ----------- CONFIGURATION -------------
MONGO_URI = "mongodb://localhost:27017/"
VIRUSTOTAL_API_KEY = "6ddfa02022b51c2db234eb2beebec79a3a7be2ccf24b546d63f325d51453cf8d"
ABUSEIPDB_API_KEY = "67356a581f9465f69e23ffe81d50dac3a3742cc655663c183fb947c922da617624c00cafb8432ec4"

app = Flask(__name__)

client = MongoClient(MONGO_URI)
db = client['cti_dashboard']
threats_collection = db['threats']

# ---------- Helper Functions -----------

def is_ip(s):
    try:
        pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        if not pattern.match(s):
            return False
        parts = s.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    except Exception:
        return False

def looks_like_ip(s):
    pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    return bool(pattern.match(s))

def is_domain(s):
    if is_ip(s):
        return False
    return "." in s and not s.startswith("http")

def is_reserved_ip(ip):
    private_patterns = [
        re.compile(r"^10\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
        re.compile(r"^127\."),
        re.compile(r"^0\."),
        re.compile(r"^169\.254\."),
        re.compile(r"^255\.")
    ]
    return any(p.match(ip) for p in private_patterns)

def is_testnet_ip(ip):
    testnet_ranges = [
        re.compile(r"^192\.0\.2\."),
        re.compile(r"^198\.51\.100\."),
        re.compile(r"^203\.0\.113\.")
    ]
    return any(p.match(ip) for p in testnet_ranges)

def safe_json(obj):
    """Ensures that only JSON serializable Python objects are returned to the template."""
    try:
        json.dumps(obj)
        return obj
    except Exception:
        return {}

# ---------- Routes -----------

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = ""
    ioc = ""
    vt_last_results = {}
    vt_raw_json = {}
    ab_data = {}

    if request.method == 'POST':
        ioc = request.form.get('ioc', '').strip()

        # Input validation
        if not ioc:
            error = "Please provide a valid IP or domain."
        elif not (is_ip(ioc) or is_domain(ioc) or looks_like_ip(ioc)):
            error = "Input must be a valid IPv4 address or a valid domain."
        else:
            # --- VirusTotal Lookup ---
            vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            vt_url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
            vt_data = {}
            try:
                if not VIRUSTOTAL_API_KEY:
                    vt_data = {"error": "VirusTotal API key is missing or invalid."}
                else:
                    vt_resp = requests.get(vt_url, headers=vt_headers, timeout=10)
                    vt_json = vt_resp.json()
                    if vt_resp.status_code == 401:
                        vt_data = {"error": "VirusTotal API key is missing or invalid."}
                    elif vt_resp.status_code == 429:
                        vt_data = {"error": "VirusTotal API rate limit exceeded. Please try again later."}
                    elif vt_resp.status_code == 404:
                        vt_data = {"error": "No data found for this IP/domain in VirusTotal."}
                    elif vt_resp.status_code != 200:
                        vt_data = {"error": f"VirusTotal API returned an error (status code: {vt_resp.status_code})."}
                    elif "error" in vt_json:
                        vt_data = {"error": vt_json.get("error", {}).get("message", "Unexpected response from VirusTotal.")}
                    elif "data" in vt_json and (vt_json["data"] is None or vt_json["data"] == []):
                        vt_data = {"error": "No data found for this IP/domain in VirusTotal."}
                    else:
                        vt_data = vt_json
            except requests.exceptions.RequestException:
                vt_data = {"error": "Network error while contacting VirusTotal."}
            except Exception as e:
                vt_data = {"error": f"Unexpected error from VirusTotal: {str(e)}"}

            vt_raw_json = safe_json(vt_data)
            if vt_data and not vt_data.get("error"):
                vt_data_obj = vt_data.get("data")
                vt_attr = None
                if isinstance(vt_data_obj, list) and len(vt_data_obj) > 0:
                    vt_attr = vt_data_obj[0].get("attributes", {})
                elif isinstance(vt_data_obj, dict):
                    vt_attr = vt_data_obj.get("attributes", {})
                if isinstance(vt_attr, dict) and "last_analysis_results" in vt_attr:
                    vt_last_results = vt_attr["last_analysis_results"]

            # --- AbuseIPDB Lookup ---
            if looks_like_ip(ioc) and not is_ip(ioc):
                ab_data = {"error": "The IP address entered is not valid."}
            elif is_ip(ioc) and is_reserved_ip(ioc):
                ab_data = {"error": "The IP address provided is not a public routable address."}
            elif is_ip(ioc) and is_testnet_ip(ioc):
                ab_data = {"error": "No data found for this IP in AbuseIPDB."}
            elif is_ip(ioc):
                ab_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
                ab_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}&maxAgeInDays=90&verbose"
                try:
                    if not ABUSEIPDB_API_KEY:
                        ab_data = {"error": "AbuseIPDB API key is missing or invalid."}
                    else:
                        ab_resp = requests.get(ab_url, headers=ab_headers, timeout=10)
                        ab_json = ab_resp.json()
                        if ab_resp.status_code == 401:
                            ab_data = {"error": "AbuseIPDB API key is missing or invalid."}
                        elif ab_resp.status_code == 429:
                            ab_data = {"error": "AbuseIPDB API rate limit exceeded. Please try again later."}
                        elif ab_resp.status_code == 422:
                            if ab_json.get("errors"):
                                err_msgs = "; ".join(e.get("detail", str(e)) for e in ab_json["errors"])
                                if "not a public routable address" in err_msgs.lower():
                                    ab_data = {"error": "The IP address provided is not a public routable address."}
                                elif "must be a valid ipv4 address" in err_msgs.lower() or "invalid ip" in err_msgs.lower():
                                    ab_data = {"error": "The IP address entered is not valid."}
                                else:
                                    ab_data = {"error": err_msgs}
                            else:
                                ab_data = {"error": f"AbuseIPDB API returned an error (status code: {ab_resp.status_code})."}
                        elif ab_resp.status_code == 404:
                            ab_data = {"error": "No data found for this IP in AbuseIPDB."}
                        elif ab_resp.status_code != 200:
                            ab_data = {"error": f"AbuseIPDB API returned an error (status code: {ab_resp.status_code})."}
                        elif ab_json.get("errors"):
                            err_msgs = "; ".join(e.get("detail", str(e)) for e in ab_json["errors"])
                            ab_data = {"error": err_msgs}
                        elif "data" in ab_json and ab_json["data"]:
                            usage_type = ab_json["data"].get("usageType", "").lower()
                            abuse_score = ab_json["data"].get("abuseConfidenceScore", 0)
                            total_reports = ab_json["data"].get("totalReports", 0)
                            is_public = ab_json["data"].get("isPublic", True)
                            if not is_public or usage_type == "reserved":
                                ab_data = {"error": "The IP address provided is not a public routable address."}
                            elif abuse_score == 0 and total_reports == 0:
                                ab_data = {"error": "No data found for this IP in AbuseIPDB."}
                            else:
                                ab_data = ab_json
                        else:
                            ab_data = {"error": "Unexpected response from AbuseIPDB."}
                except requests.exceptions.RequestException:
                    ab_data = {"error": "Network error while contacting AbuseIPDB."}
                except Exception as e:
                    ab_data = {"error": f"Unexpected error from AbuseIPDB: {str(e)}"}
                ab_data = safe_json(ab_data)
            elif is_domain(ioc):
                ab_data = {"error": "AbuseIPDB only supports IP address lookups."}
            else:
                ab_data = {"error": "Input must be a valid IPv4 address or a valid domain."}
                ab_data = safe_json(ab_data)

            # Save lookup to DB
            try:
                # Remove excess fields to avoid Mongo errors on serialization
                db_vt = vt_raw_json if isinstance(vt_raw_json, dict) else {}
                db_ab = ab_data if isinstance(ab_data, dict) else {}
                threats_collection.insert_one({
                    "ioc": ioc,
                    "timestamp": datetime.utcnow(),
                    "vt_data": db_vt,
                    "ab_data": db_ab,
                    "tag": ""
                })
            except Exception:
                pass # Fail silently on DB issues (for robustness)

            result = {
                "ioc": ioc,
                "vt_last_results": vt_last_results if vt_last_results else {},
                "vt_raw_json": vt_raw_json if vt_raw_json else {},
                "ab": ab_data if ab_data else {}
            }

    return render_template(
        "index.html",
        result=result if result is not None else {},
        error=error,
        ioc=ioc,
        active_page="home"
    )

@app.route('/recent-lookups')
def recent_lookups():
    recent_lookups = list(threats_collection.find().sort("timestamp", -1))
    return render_template(
        "recent-lookups.html",
        threats=recent_lookups,
        active_page="recent_lookups"
    )

@app.route('/metrics')
def metrics():
    pipeline = [
        {"$group": {"_id": "$ioc", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    data = list(threats_collection.aggregate(pipeline))
    labels = [d['_id'] for d in data]
    values = [d['count'] for d in data]

    bar = go.Bar(x=labels, y=values)
    fig = go.Figure([bar])
    fig.update_layout(title='Threat Lookup Frequency', xaxis_title='IOC', yaxis_title='Lookup Count')
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('metrics.html', graphJSON=graphJSON, active_page="metrics")

@app.route('/tag', methods=['POST'])
def tag():
    ioc = request.form.get('ioc', '')
    tag = request.form.get('tag', '')
    redirect_page = request.form.get('redirect_page', 'index')
    threats_collection.update_many({'ioc': ioc}, {'$set': {'tag': tag}})
    if redirect_page == "recent_lookups":
        return redirect(url_for('recent_lookups'))
    else:
        return redirect(url_for('index'))

@app.route('/export')
def export():
    data = list(threats_collection.find())
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['IOC', 'Timestamp', 'Tag', 'VirusTotal', 'AbuseIPDB'])
    for row in data:
        cw.writerow([
            row.get('ioc', ''),
            row.get('timestamp', ''),
            row.get('tag', ''),
            json.dumps(row.get('vt_data', {})),
            json.dumps(row.get('ab_data', {}))
        ])
    output = BytesIO(si.getvalue().encode('utf-8'))
    si.close()
    output.seek(0)
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='cti_export.csv'
    )
if __name__ == '__main__':
    app.run(debug=True)