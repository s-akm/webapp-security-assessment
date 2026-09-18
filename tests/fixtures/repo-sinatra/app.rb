require 'sinatra'

get '/api/admin' do
  halt 401 unless authenticate!
  { ok: true }.to_json
end

post '/api/report' do
  UserMailer.report(params[:email]).deliver_now
  { ok: true }.to_json
end
