import http.server
import socketserver

def main(): 
    serverPort = 8000
    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(('', serverPort), Handler) as httpd:
        print("serving at port", serverPort)
        httpd.serve_forever()

if __name__ == "__main__":
	main()       
 