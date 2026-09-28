class NotesController < ApplicationController
  def index
    render json: Note.order(:id).limit(params[:per_page])
  end
end
