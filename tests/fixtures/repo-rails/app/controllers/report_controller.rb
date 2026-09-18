# ガードが無い側（「ガード検出なし」と出るべき）
class ReportController < ApplicationController
  def create
    UserMailer.report(params[:email]).deliver_now
    render json: { ok: true }
  end
  def raw
    # 危険な関数（3 節）
    User.connection.execute("select * from users where id = #{params[:id]}")
  end
end
