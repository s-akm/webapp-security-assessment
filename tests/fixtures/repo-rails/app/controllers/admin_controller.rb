# ガードがある側（before_action で検出されるべき）
class AdminController < ApplicationController
  before_action :require_admin
  def index
    @users = User.select(:id, :email)
  end
end
