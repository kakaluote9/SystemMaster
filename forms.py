from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, IPAddress, URL, Optional, NumberRange


class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=3, max=64)])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6, max=128)])
    submit = SubmitField('登录')


class IPScanForm(FlaskForm):
    ip_address = StringField('IP地址', validators=[DataRequired(), IPAddress()])
    scan_name = StringField('扫描任务名称', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('开始扫描')


class AdvancedOptionsForm(FlaskForm):
    scan_template = SelectField('扫描模板', choices=[
        ('default', '默认'),
        ('fast', '快速扫描'),
        ('thorough', '全面扫描'),
        ('custom', '自定义')
    ], default='default')
    
    protocol = SelectField('报表协议', choices=[
        ('http', 'HTTP'),
        ('https', 'HTTPS'),
        ('ftp', 'FTP'),
        ('ssh', 'SSH')
    ], default='http')
    
    authentication = SelectField('认证方式', choices=[
        ('none', '无'),
        ('basic', '基本认证'),
        ('digest', '摘要认证'),
        ('form', '表单认证')
    ], default='none')
    
    port_range = StringField('端口范围', validators=[Optional()])
    timeout = IntegerField('超时时间(秒)', validators=[Optional(), NumberRange(min=1, max=3600)])
    max_depth = IntegerField('最大深度', validators=[Optional(), NumberRange(min=1, max=10)])
    submit = SubmitField('保存设置')


class WebScanForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired(), URL()])
    scan_name = StringField('扫描任务名称', validators=[DataRequired(), Length(max=100)])
    service_type = SelectField('服务类型', choices=[
        ('http', 'HTTP'),
        ('https', 'HTTPS'),
        ('webapp', 'Web应用'),
        ('api', 'API服务')
    ], default='http')
    submit = SubmitField('开始扫描')


class NetworkScanForm(FlaskForm):
    target = StringField('扫描目标', validators=[DataRequired(), Length(max=255)])
    scan_name = StringField('扫描任务名称', validators=[DataRequired(), Length(max=100)])
    scan_depth = SelectField('扫描深度', choices=[
        ('low', '低'),
        ('medium', '中'),
        ('high', '高')
    ], default='medium')
    submit = SubmitField('开始扫描')


class DataValidationForm(FlaskForm):
    data = TextAreaField('数据', validators=[DataRequired()])
    validation_type = SelectField('验证类型', choices=[
        ('integrity', '完整性验证'),
        ('authenticity', '真实性验证'),
        ('origin', '来源验证')
    ], default='integrity')
    submit = SubmitField('验证数据')
