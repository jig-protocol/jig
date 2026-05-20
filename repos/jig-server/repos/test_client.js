const WebSocket = require('ws');

async function test() {
  const ws = new WebSocket('ws://localhost:8080/ws');

  ws.on('open', () => {
    ws.send(JSON.stringify({
      id: 1,
      method: 'auth.anonymous',
      params: { nickname: 'test' }
    }));

    ws.send(JSON.stringify({
      id: 2,
      method: 'subscribe.channel',
      params: { channel: '#general' }
    }));

    ws.send(JSON.stringify({
      id: 3,
      method: 'message.send',
      params: { channel: '#general', content: 'Hello WebSocket!' }
    }));
  });

  ws.on('message', (data) => {
    console.log('Received:', JSON.parse(data));
  });
}

test();
