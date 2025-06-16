# Cyber Threat Intelligence Dashboard

A Flask-based web application for real-time threat intelligence lookups, visualization of threat metrics, and rapid reporting. Designed to empower security teams and IT professionals with actionable insights and intuitive tools for monitoring, analysing, and responding to cyber threats.

---

##  Features

- Real-Time Threat Lookup: Instantly check IP addresses and domains against multiple open-source CTI APIs.
- Visualize Trends: Dynamic, interactive charts show threat activity and lookup trends over time (using Plotly).
- Recent Lookups: Maintain and search recent threat lookups for easy reference and analysis.
- Tagging & Export: Tag lookups for future reference and export results for reporting or sharing.
- Comprehensive Error Handling: Clear, user-friendly feedback for invalid input and API errors.
- Modern UI: Clean, responsive interface built with HTML, CSS, and Jinja2 templating.

---

## Tools & Technologies

- Flask – Python web framework (backend)
- PyMongo – Python-MongoDB integration (lookup storage)
- Plotly – Visualization library for interactive graphs
- Requests – HTTP requests to external CTI APIs
- dnspython – Domain/IP parsing and validation
- MongoDB – Database for recent lookups and tags
- HTML/CSS – Frontend design (with Jinja2 templates)

---

## Project Structure

```
.
├── assets/
│   └── demo.wmv
├── static/
│   └── style.css
├── templates/
│   ├── dashboard.html
│   ├── index.html
│   ├── layout.html
│   ├── metrics.html
│   └── recent-lookups.html
├── .gitignore
├── Report.pdf
├── app.py
├── errors-check.txt
├── requirements.txt
└── README.md
```

---

## Getting Started

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/cyber-threat-intelligence-dashboard.git
   cd cyber-threat-intelligence-dashboard
   ```

2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

3. Start the application
   ```bash
   python app.py
   ```
   Visit [http://localhost:5000](http://localhost:5000) in your browser.

---

## Report

See [`Report.pdf`](Report.pdf) for a comprehensive overview of project goals, methods, tools, and results.

---

## Testing & Error Handling

All critical error scenarios have been tested and documented in [`errors-check.txt`](errors-check.txt).  
This includes invalid input, API failures, and edge cases for maximum reliability.

---

## Future Enhancements

- Integration with additional CTI APIs and threat feeds
- User authentication and role-based access control
- Advanced analytics and predictive threat modelling
- Cloud deployment for global accessibility

---

For questions or contributions, please open an issue or pull request!
