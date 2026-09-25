import { WebSocketServer } from 'ws';
const wss = new WebSocketServer({ noServer: true });
wss.on('connection', (socket) => {
  socket.on('join', (data) => socket.join(data.room));
});
