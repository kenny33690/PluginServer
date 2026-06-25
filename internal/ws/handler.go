package ws

import (
	"net/http"

	"github.com/gorilla/websocket"
)

type LoggerFunc func(format string, args ...any)

var logf LoggerFunc = func(format string, args ...any) {}


func SetLogger(fn LoggerFunc) {
	if fn == nil {
		return
	}
	logf = fn
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func Handler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logf("upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	logf("client connected: %s", r.RemoteAddr)

	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			logf("client disconnected: %s: %v", r.RemoteAddr, err)
			return
		}

		logf("received from %s: %s", r.RemoteAddr, message)

		if err := conn.WriteMessage(messageType, message); err != nil {
			logf("write failed: %s: %v", r.RemoteAddr, err)
			return
		}
	}
}
