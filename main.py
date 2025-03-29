from flask import render_template
from app import app
import routes  # noqa: F401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)


    @app.route("/")  # 关键！必须定义根路径
    def home():
        return render_template("login.html")  # 或返回你的首页模板


