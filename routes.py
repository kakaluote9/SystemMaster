import threading
from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from models import User, Task, Vulnerability, VulnerabilityVerification, DataValidation, MaintenanceAudit
from forms import (
    LoginForm, IPScanForm, AdvancedOptionsForm, WebScanForm, 
    NetworkScanForm, DataValidationForm
)
from utils import (
    simulate_scan_progress, get_vulnerability_count_by_severity,
    get_vulnerability_trend, get_task_statistics
)
from zkp import DataValidator


# User Authentication Routes
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('请输入正确的用户名和密码！', 'danger')
    
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功退出登录', 'success')
    return redirect(url_for('login'))


# Main Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Get statistics for dashboard
    vuln_by_severity = get_vulnerability_count_by_severity()
    vuln_trend = get_vulnerability_trend()
    task_stats = get_task_statistics()
    
    # Get recent tasks
    recent_tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.start_time.desc()).limit(5).all()
    
    return render_template(
        'dashboard.html',
        vuln_by_severity=vuln_by_severity,
        vuln_trend=vuln_trend,
        task_stats=task_stats,
        recent_tasks=recent_tasks
    )


# IP Scanning Routes
@app.route('/ip-scan', methods=['GET', 'POST'])
@login_required
def ip_scan():
    form = IPScanForm()
    if form.validate_on_submit():
        # Create new scanning task
        task = Task(
            name=form.scan_name.data,
            task_type='IP',
            target=form.ip_address.data,
            status='pending',
            user_id=current_user.id
        )
        db.session.add(task)
        db.session.commit()
        
        # Start scanning in background
        thread = threading.Thread(target=simulate_scan_progress, args=(task.id,))
        thread.daemon = True
        thread.start()
        
        flash(f'IP扫描任务已创建: {form.scan_name.data}', 'success')
        return redirect(url_for('task_list'))
    
    return render_template('ip_scan.html', form=form)


@app.route('/ip-scan/advanced-options', methods=['GET', 'POST'])
@login_required
def ip_scan_advanced_options():
    form = AdvancedOptionsForm()
    if form.validate_on_submit():
        flash('高级选项设置已保存', 'success')
        return redirect(url_for('ip_scan'))
    
    return render_template('advanced_options.html', form=form)


# Web Scanning Routes
@app.route('/web-scan', methods=['GET', 'POST'])
@login_required
def web_scan():
    form = WebScanForm()
    if form.validate_on_submit():
        # Create new scanning task
        task = Task(
            name=form.scan_name.data,
            task_type='Web',
            target=form.url.data,
            status='pending',
            user_id=current_user.id
        )
        db.session.add(task)
        db.session.commit()
        
        # Start scanning in background
        thread = threading.Thread(target=simulate_scan_progress, args=(task.id,))
        thread.daemon = True
        thread.start()
        
        flash(f'Web扫描任务已创建: {form.scan_name.data}', 'success')
        return redirect(url_for('task_list'))
    
    return render_template('web_scan.html', form=form)


# Network Scanning Routes
@app.route('/network-scan', methods=['GET', 'POST'])
@login_required
def network_scan():
    form = NetworkScanForm()
    if form.validate_on_submit():
        # Create new scanning task
        task = Task(
            name=form.scan_name.data,
            task_type='Network',
            target=form.target.data,
            status='pending',
            user_id=current_user.id
        )
        db.session.add(task)
        db.session.commit()
        
        # Start scanning in background
        thread = threading.Thread(target=simulate_scan_progress, args=(task.id,))
        thread.daemon = True
        thread.start()
        
        flash(f'网络扫描任务已创建: {form.scan_name.data}', 'success')
        return redirect(url_for('task_list'))
    
    return render_template('network_scan.html', form=form)


# Task Management Routes
@app.route('/tasks')
@login_required
def task_list():
    tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.start_time.desc()).all()
    return render_template('task_list.html', tasks=tasks)


@app.route('/tasks/<int:task_id>')
@login_required
def task_details(task_id):
    task = Task.query.get_or_404(task_id)
    # Ensure the user can only view their own tasks
    if task.user_id != current_user.id:
        flash('您无权查看此任务', 'danger')
        return redirect(url_for('task_list'))
    
    vulnerabilities = Vulnerability.query.filter_by(task_id=task.id).all()
    return render_template('vulnerability_details.html', task=task, vulnerabilities=vulnerabilities)


@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    # Ensure the user can only delete their own tasks
    if task.user_id != current_user.id:
        flash('您无权删除此任务', 'danger')
        return redirect(url_for('task_list'))
    
    # Delete associated vulnerabilities first
    Vulnerability.query.filter_by(task_id=task.id).delete()
    db.session.delete(task)
    db.session.commit()
    
    flash('任务已删除', 'success')
    return redirect(url_for('task_list'))


@app.route('/tasks/<int:task_id>/stop', methods=['POST'])
@login_required
def stop_task(task_id):
    task = Task.query.get_or_404(task_id)
    # Ensure the user can only stop their own tasks
    if task.user_id != current_user.id:
        flash('您无权停止此任务', 'danger')
        return redirect(url_for('task_list'))
    
    # Only allow stopping tasks that are pending or running
    if task.status in ['pending', 'running']:
        task.status = 'stopped'
        db.session.commit()
        flash('任务已停止', 'success')
    else:
        flash('无法停止已完成或已失败的任务', 'warning')
    
    return redirect(url_for('task_list'))


# Vulnerability Management Routes
@app.route('/vulnerability/<int:vuln_id>')
@login_required
def vulnerability_details(vuln_id):
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    task = Task.query.get_or_404(vulnerability.task_id)
    
    # Ensure the user can only view their own vulnerabilities
    if task.user_id != current_user.id:
        flash('您无权查看此漏洞', 'danger')
        return redirect(url_for('task_list'))
    
    verifications = VulnerabilityVerification.query.filter_by(vulnerability_id=vulnerability.id).all()
    return render_template('vulnerability_details.html', vulnerability=vulnerability, task=task, verifications=verifications)


@app.route('/vulnerability/<int:vuln_id>/verify', methods=['POST'])
@login_required
def verify_vulnerability(vuln_id):
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    task = Task.query.get_or_404(vulnerability.task_id)
    
    # Ensure the user can only verify their own vulnerabilities
    if task.user_id != current_user.id:
        flash('您无权验证此漏洞', 'danger')
        return redirect(url_for('task_list'))
    
    # Simulate vulnerability verification
    # In a real system, this would run actual verification tools
    verification = VulnerabilityVerification(
        verification_tool="ZKP验证工具",
        tool_description="使用零知识证明验证漏洞的存在性而不暴露系统细节",
        result=True,  # Simulated result
        details="漏洞验证已完成，确认该漏洞存在。建议采取相应的修复措施。",
        vulnerability_id=vulnerability.id
    )
    db.session.add(verification)
    db.session.commit()
    
    flash('漏洞验证已完成', 'success')
    return redirect(url_for('vulnerability_details', vuln_id=vuln_id))


@app.route('/vulnerability/comparison')
@login_required
def vulnerability_comparison():
    # Get vulnerability trend data for comparison
    trend_data = get_vulnerability_trend(days=30)
    
    # Get vulnerability counts by severity for current period
    current_severity_counts = get_vulnerability_count_by_severity()
    
    # Simulate historical data (in a real app, this would come from the database)
    historical_severity_counts = {
        'critical': max(0, current_severity_counts['critical'] - 2),
        'high': max(0, current_severity_counts['high'] - 5),
        'medium': max(0, current_severity_counts['medium'] - 3),
        'low': max(0, current_severity_counts['low'] - 1),
        'info': max(0, current_severity_counts['info'] - 4)
    }
    
    return render_template(
        'vulnerability_comparison.html',
        trend_data=trend_data,
        current_counts=current_severity_counts,
        historical_counts=historical_severity_counts
    )


@app.route('/vulnerability/analysis')
@login_required
def vulnerability_analysis():
    # Get vulnerability statistics for analysis
    severity_counts = get_vulnerability_count_by_severity()
    trend_data = get_vulnerability_trend(days=30)
    
    # Get tasks with the most vulnerabilities
    tasks_with_most_vulns = db.session.query(
        Task, db.func.count(Vulnerability.id).label('vuln_count')
    ).join(Vulnerability).group_by(Task.id).order_by(db.desc('vuln_count')).limit(5).all()
    
    # Get most common vulnerability types
    common_vulns = db.session.query(
        Vulnerability.name, db.func.count(Vulnerability.id).label('count')
    ).group_by(Vulnerability.name).order_by(db.desc('count')).limit(10).all()
    
    return render_template(
        'vulnerability_analysis.html',
        severity_counts=severity_counts,
        trend_data=trend_data,
        tasks_with_most_vulns=tasks_with_most_vulns,
        common_vulns=common_vulns
    )


# Data Validation Routes
@app.route('/data-validation', methods=['GET', 'POST'])
@login_required
def data_validation():
    form = DataValidationForm()
    validation_result = None
    
    if form.validate_on_submit():
        # Perform data validation using zero-knowledge proofs
        data = form.data.data
        validation_type = form.validation_type.data
        
        # Call the appropriate validation method based on type
        if validation_type == 'integrity':
            is_valid, proof = DataValidator.validate_data_integrity(data)
        elif validation_type == 'authenticity':
            is_valid, proof = DataValidator.validate_data_authenticity(data)
        elif validation_type == 'origin':
            is_valid, proof = DataValidator.validate_data_origin(data)
        
        # Save the validation result
        validation = DataValidation(
            data_hash=proof['commitment'],
            validation_type=validation_type,
            is_valid=is_valid,
            proof=str(proof),
            user_id=current_user.id
        )
        db.session.add(validation)
        db.session.commit()
        
        validation_result = {
            'is_valid': is_valid,
            'message': '数据验证通过' if is_valid else '数据验证失败',
            'proof': proof
        }
        
        flash(f'数据验证完成: {"成功" if is_valid else "失败"}', 'success' if is_valid else 'danger')
    
    # Get recent validations
    recent_validations = DataValidation.query.filter_by(user_id=current_user.id).order_by(
        DataValidation.validation_time.desc()
    ).limit(5).all()
    
    return render_template(
        'data_validation.html',
        form=form,
        validation_result=validation_result,
        recent_validations=recent_validations
    )


# Maintenance Audit Routes
@app.route('/maintenance-audit')
@login_required
def maintenance_audit():
    # Get maintenance audit records
    audits = MaintenanceAudit.query.filter_by(user_id=current_user.id).order_by(
        MaintenanceAudit.audit_time.desc()
    ).all()
    
    return render_template('maintenance_audit.html', audits=audits)


@app.route('/maintenance-audit/new', methods=['POST'])
@login_required
def new_maintenance_audit():
    target = request.form.get('target')
    audit_type = request.form.get('audit_type')
    
    if not target or not audit_type:
        flash('请提供有效的审计目标和类型', 'danger')
        return redirect(url_for('maintenance_audit'))
    
    # Create a new maintenance audit record
    audit = MaintenanceAudit(
        audit_type=audit_type,
        target=target,
        findings="系统自动审计完成。发现部分配置可能需要优化，详细信息请查看建议。",
        recommendations="建议加强密码策略、更新软件版本并定期进行安全扫描。",
        user_id=current_user.id
    )
    db.session.add(audit)
    db.session.commit()
    
    flash('维护审计已完成', 'success')
    return redirect(url_for('maintenance_audit'))


# API Endpoints for AJAX requests
@app.route('/api/task/<int:task_id>/progress')
@login_required
def task_progress(task_id):
    task = Task.query.get_or_404(task_id)
    # Ensure the user can only check their own tasks
    if task.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'progress': task.progress,
        'status': task.status
    })


# Initialize database with a default user
def create_default_user():
    # Check if the default user already exists
    if not User.query.filter_by(username='admin').first():
        user = User(username='admin')
        user.set_password('password')
        db.session.add(user)
        db.session.commit()

# Use with_app_context instead of before_first_request
with app.app_context():
    create_default_user()
