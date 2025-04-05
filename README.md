# Automating-Security-Audits-and-Server-hardening-On-Linux-Server

Download & Make Executable : wget https://github.com/your-repo/security-audit/audit.sh
chmod +x audit.sh

Run the Audit  : sh /audit.sh
View the Report : cat /var/log/security_audit.log

Future Enhancements
Email alerts: Add mail -s "Security Audit Report" admin@example.com < /var/log/security_audit.log

Automatic scheduling: Add to cron for regular audits
