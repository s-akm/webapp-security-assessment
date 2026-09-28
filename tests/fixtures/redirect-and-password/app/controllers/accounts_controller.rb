# 架空の題材: Rails の戻り先を変数に受けてから転送する
class AccountsController < ApplicationController
  def create
    user = User.authenticate(params[:email], params[:password])
    dest = params[:return_to].presence || root_path
    if user
      session[:user_id] = user.id
      redirect_to dest
    else
      render :new
    end
  end
end
