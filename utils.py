import random
import string
import ipaddress
import time
from datetime import datetime, timedelta
from app import db
from models import Vulnerability, Task


def generate_random_string(length=10):
    """Generate a random string of fixed length."""
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for i in range(length))


def get_ip_range(ip_address):
    """Convert IP address to a range for scanning."""
    try:
        # Check if it's a CIDR notation
        if '/' in ip_address:
            network = ipaddress.IPv4Network(ip_address, strict=False)
            return [str(ip) for ip in network.hosts()]
        else:
            # Single IP
            return [ip_address]
    except ValueError:
        return []


def simulate_scan_progress(task_id, duration=30):
    """
    Simulate a scanning process by updating the task progress over time.
    
    Parameters:
    - task_id: The ID of the task to update
    - duration: The total duration of the scan in seconds
    """
    task = Task.query.get(task_id)
    if not task:
        return
    
    # Set task as running
    task.status = 'running'
    db.session.commit()
    
    # Calculate progress step
    step = 100 / duration
    
    # Update progress every second
    for i in range(duration):
        task.progress = min(int(i * step), 99)
        db.session.commit()
        time.sleep(1)
    
    # Generate sample vulnerabilities based on task type
    generate_sample_vulnerabilities(task)
    
    # Complete the task
    task.progress = 100
    task.status = 'completed'
    task.end_time = datetime.utcnow()
    db.session.commit()


def generate_sample_vulnerabilities(task):
    """
    Generate sample vulnerabilities for a task based on its type.
    This is a simulation function and would be replaced with real scanning results.
    """
    # Common vulnerabilities for all scan types
    common_vulns = [
        {
            'name': 'Outdated Software',
            'description': '检测到系统使用过时的软件版本，可能存在已知安全漏洞。',
            'severity': 'high'
        },
        {
            'name': 'Weak Credentials',
            'description': '发现弱密码或默认凭据，攻击者可能通过暴力破解获取访问权限。',
            'severity': 'high'
        },
        {
            'name': 'Insecure Configuration',
            'description': '检测到不安全的系统配置，可能导致未授权访问或信息泄露。',
            'severity': 'medium'
        }
    ]
    
    # Specific vulnerabilities based on task type
    type_specific_vulns = {
        'IP': [
            {
                'name': 'Open Ports',
                'description': '发现多个未使用但开放的端口，增加了攻击面。',
                'severity': 'medium',
                'port': 22
            },
            {
                'name': 'Vulnerable Service',
                'description': '检测到易受攻击的服务正在运行。',
                'severity': 'critical',
                'port': 80
            }
        ],
        'Web': [
            {
                'name': 'SQL Injection',
                'description': '发现可能导致SQL注入的表单输入字段。',
                'severity': 'critical',
                'path': '/login'
            },
            {
                'name': 'Cross-Site Scripting (XSS)',
                'description': '网站存在XSS漏洞，可能导致攻击者注入恶意脚本。',
                'severity': 'high',
                'path': '/search'
            },
            {
                'name': 'CSRF Vulnerability',
                'description': '网站存在跨站请求伪造漏洞，可能导致未授权操作。',
                'severity': 'medium',
                'path': '/account'
            }
        ],
        'Network': [
            {
                'name': 'Misconfigured Firewall',
                'description': '防火墙配置不当，可能允许未授权访问。',
                'severity': 'high'
            },
            {
                'name': 'Unencrypted Communication',
                'description': '检测到网络上的明文通信，可能导致信息泄露。',
                'severity': 'medium'
            },
            {
                'name': 'ARP Spoofing',
                'description': '网络可能容易受到ARP欺骗攻击。',
                'severity': 'high'
            }
        ]
    }
    
    # Select vulnerabilities based on task type
    selected_vulns = common_vulns.copy()
    if task.task_type in type_specific_vulns:
        selected_vulns.extend(type_specific_vulns[task.task_type])
    
    # Randomly decide how many vulnerabilities to include (between 2 and 5)
    num_vulns = random.randint(2, min(5, len(selected_vulns)))
    selected_vulns = random.sample(selected_vulns, num_vulns)
    
    # Add vulnerabilities to database
    for vuln_data in selected_vulns:
        vuln = Vulnerability(
            name=vuln_data['name'],
            description=vuln_data.get('description', ''),
            severity=vuln_data['severity'],
            target=task.target,
            port=vuln_data.get('port'),
            path=vuln_data.get('path'),
            details="详细信息将根据进一步的漏洞验证提供。",
            task_id=task.id
        )
        db.session.add(vuln)
    
    db.session.commit()


def get_vulnerability_count_by_severity():
    """Get the count of vulnerabilities grouped by severity."""
    severity_counts = {
        'critical': Vulnerability.query.filter_by(severity='critical').count(),
        'high': Vulnerability.query.filter_by(severity='high').count(),
        'medium': Vulnerability.query.filter_by(severity='medium').count(),
        'low': Vulnerability.query.filter_by(severity='low').count(),
        'info': Vulnerability.query.filter_by(severity='info').count()
    }
    return severity_counts


def get_vulnerability_trend(days=30):
    """Get vulnerability trend data for the specified number of days."""
    today = datetime.utcnow().date()
    trend_data = []
    
    # Loop through the past N days
    for i in range(days, 0, -1):
        date = today - timedelta(days=i-1)
        start = datetime.combine(date, datetime.min.time())
        end = datetime.combine(date, datetime.max.time())
        
        # Count vulnerabilities discovered on this date
        count = Vulnerability.query.filter(
            Vulnerability.discovery_time >= start,
            Vulnerability.discovery_time <= end
        ).count()
        
        trend_data.append({
            'date': date.strftime('%Y-%m-%d'),
            'count': count
        })
    
    return trend_data


def get_task_statistics():
    """Get statistics about tasks."""
    stats = {
        'total': Task.query.count(),
        'pending': Task.query.filter_by(status='pending').count(),
        'running': Task.query.filter_by(status='running').count(),
        'completed': Task.query.filter_by(status='completed').count(),
        'failed': Task.query.filter_by(status='failed').count()
    }
    return stats
