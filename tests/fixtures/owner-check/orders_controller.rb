class OrdersController < ApplicationController
  before_action :authenticate_user!

  def show
    @order = current_user.orders.find(params[:id])
  end

  def profile
    log_access(current_user)
    @profile = Profile.find_by(user_id: params[:user_id])
  end

  def cancel
    order = Order.find(params[:id])
    head :forbidden and return unless order.user_id == current_user.id
    order.cancel!
  end
end
